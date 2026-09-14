/*
 * Copyright (c) 2026 Default Gateway GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * l2tvpp-encap-fastpath: the encap-direction counterpart of the decap
 * fastpath. A plain IPv4 packet arriving on the uplink toward a subscriber
 * normally traverses ethernet-input -> ip4-input -> ip4-lookup -> ip4-midchain
 * (the session's L2TP/UDP/IP/PPP rewrite) -> the tunnel egress. On the
 * single-flow bench the uplink worker saturated on that path while the decap
 * side (which has a fast path) stayed clean.
 *
 * This is a device-input feature on the uplink: the driver hands the frame
 * here before ethernet-input. We read the inner IPv4 destination, look it up
 * in l2tvpp_main.encap_adj_by_ip4 (subscriber /32 -> the session's midchain
 * adj_index, populated by l2tvpp_route_add_del), and if it hits we strip L2,
 * set ip.adj_index[VLIB_TX] to that adjacency and go straight to ip4-midchain
 * - skipping ethernet-input, ip4-input and ip4-lookup. ip4-midchain does the
 * TTL decrement, checksum, rewrite prepend and fixup exactly as on the normal
 * path, so forwarding semantics are unchanged; only the lookup is shortcut.
 *
 * Anything we cannot resolve to a cached subscriber adjacency (ARP, non-IP,
 * IP options, fragments to be safe, a destination that is not a subscriber)
 * is passed to ethernet-input untouched. IPv4 only; enable per interface with
 * `l2tvpp encap-fastpath <uplink> [disable]`.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/adj/adj.h>
#include <vppinfra/bihash_8_8.h>
#include <l2tvpp/l2tvpp.h>

typedef struct
{
  uword *enabled;		/* bitmap of uplink sw_if_index with the feature on */
} l2tvpp_encap_fastpath_main_t;

l2tvpp_encap_fastpath_main_t l2tvpp_encap_fastpath_main;

typedef enum
{
  L2TVPP_ENCAP_FP_NEXT_ETHERNET_INPUT,
  L2TVPP_ENCAP_FP_NEXT_IP4_MIDCHAIN,
  L2TVPP_ENCAP_FP_N_NEXT,
} l2tvpp_encap_fp_next_t;

typedef struct
{
  u32 dst;
  u32 adj_index;
  u8 hit;
} l2tvpp_encap_fp_trace_t;

static u8 *
format_l2tvpp_encap_fp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tvpp_encap_fp_trace_t *t = va_arg (*args, l2tvpp_encap_fp_trace_t *);
  if (t->hit)
    return format (s, "l2tvpp-encap-fastpath: %U -> adj %d (ip4-midchain)",
		   format_ip4_address, &t->dst, t->adj_index);
  return format (s, "l2tvpp-encap-fastpath: %U miss -> ethernet-input",
		 format_ip4_address, &t->dst);
}

/* read the inner IPv4 dst of an ethernet frame at p; 0 = not plain IPv4 we
 * want to shortcut (VLAN, options, fragment, too short -> normal path).
 * On success sets *dst and *l2_len (bytes of L2 to strip). */
static_always_inline int
l2tvpp_encap_peek_dst (u8 * p, u8 * end, u32 * dst, u16 * l2_len)
{
  ethernet_header_t *eth = (ethernet_header_t *) p;
  ip4_header_t *ip;
  u16 type;
  u16 l2 = sizeof (*eth);

  if (PREDICT_FALSE (p + sizeof (*eth) > end))
    return 0;
  type = eth->type;
  if (PREDICT_FALSE (type == clib_host_to_net_u16 (ETHERNET_TYPE_VLAN)))
    return 0;			/* tagged uplink: leave to ethernet-input */
  if (type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    return 0;
  ip = (ip4_header_t *) (p + l2);
  if (PREDICT_FALSE ((u8 *) ip + sizeof (*ip) > end))
    return 0;
  /* only plain, unfragmented v4 with no options: ip4-midchain assumes a
   * 20-byte header for the TTL/checksum fast path, and fragments/options
   * are rare enough to hand to the general path */
  if (PREDICT_FALSE (ip->ip_version_and_header_length != 0x45))
    return 0;
  if (PREDICT_FALSE (ip4_get_fragment_offset (ip)
		     || ip4_get_fragment_more (ip)))
    return 0;
  *dst = ip->dst_address.as_u32;
  *l2_len = l2;
  return 1;
}

VLIB_NODE_FN (l2tvpp_encap_fastpath_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  u32 n = frame->n_vectors, *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 i;

  vlib_get_buffers (vm, from, bufs, n);

  for (i = 0; i < n; i++)
    {
      u8 *p = vlib_buffer_get_current (b[i]);
      u8 *end = p + b[i]->current_length;
      clib_bihash_kv_8_8_t kv;
      u32 dst = 0;
      u16 l2_len = 0;
      u8 hit = 0;

      if (PREDICT_TRUE (i + 4 < n))
	{
	  vlib_prefetch_buffer_header (b[i + 4], LOAD);
	  clib_prefetch_load (vlib_buffer_get_current (b[i + 2]));
	}

      if (PREDICT_TRUE (lm->encap_adj_init
			&& l2tvpp_encap_peek_dst (p, end, &dst, &l2_len)))
	{
	  kv.key = dst;
	  if (PREDICT_TRUE (!clib_bihash_search_8_8
			    (&lm->encap_adj_by_ip4, &kv, &kv)))
	    {
	      /* deliver to ip4-midchain exactly as ip4-lookup would: L2
	       * stripped, adjacency in ip.adj_index[VLIB_TX] */
	      vlib_buffer_advance (b[i], l2_len);
	      vnet_buffer (b[i])->ip.adj_index[VLIB_TX] = (u32) kv.value;
	      next[i] = L2TVPP_ENCAP_FP_NEXT_IP4_MIDCHAIN;
	      hit = 1;
	    }
	}
      if (!hit)
	next[i] = L2TVPP_ENCAP_FP_NEXT_ETHERNET_INPUT;

      if (PREDICT_FALSE (b[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2tvpp_encap_fp_trace_t *t =
	    vlib_add_trace (vm, node, b[i], sizeof (*t));
	  t->dst = dst;
	  t->adj_index = hit ? (u32) kv.value : ~0;
	  t->hit = hit;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n);
  return n;
}

VLIB_REGISTER_NODE (l2tvpp_encap_fastpath_node) = {
  .name = "l2tvpp-encap-fastpath",
  .vector_size = sizeof (u32),
  .format_trace = format_l2tvpp_encap_fp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = L2TVPP_ENCAP_FP_N_NEXT,
  .next_nodes = {
    [L2TVPP_ENCAP_FP_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [L2TVPP_ENCAP_FP_NEXT_IP4_MIDCHAIN] = "ip4-midchain",
  },
};

VNET_FEATURE_INIT (l2tvpp_encap_fastpath_feature, static) = {
  .arc_name = "device-input",
  .node_name = "l2tvpp-encap-fastpath",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

#ifndef CLIB_MARCH_VARIANT
int
l2tvpp_encap_fastpath_enable_disable (vlib_main_t * vm, u32 sw_if_index,
				      u8 enable)
{
  l2tvpp_encap_fastpath_main_t *em = &l2tvpp_encap_fastpath_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  enable = enable ? 1 : 0;
  if (clib_bitmap_get (em->enabled, sw_if_index) == enable)
    return 0;
  em->enabled = clib_bitmap_set (em->enabled, sw_if_index, enable);
  vnet_feature_enable_disable ("device-input", "l2tvpp-encap-fastpath",
			       sw_if_index, enable, 0, 0);
  return 0;
}

static clib_error_t *
l2tvpp_encap_fastpath_cli (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line, *line = &_line;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line))
    return clib_error_return (0, "interface required");
  while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line, "disable") || unformat (line, "del"))
	enable = 0;
      else if (unformat (line, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	{
	  unformat_free (line);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line);
	}
    }
  unformat_free (line);
  if (sw_if_index == ~0)
    return clib_error_return (0, "interface required");

  rv = l2tvpp_encap_fastpath_enable_disable (vm, sw_if_index, enable);
  if (rv == VNET_API_ERROR_INVALID_SW_IF_INDEX)
    return clib_error_return (0, "not a hardware interface");
  if (rv)
    return clib_error_return (0, "error %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_encap_fastpath_command, static) = {
  .path = "l2tvpp encap-fastpath",
  .short_help = "l2tvpp encap-fastpath <interface> [disable]",
  .function = l2tvpp_encap_fastpath_cli,
};

static clib_error_t *
l2tvpp_show_encap_fastpath_cli (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  l2tvpp_encap_fastpath_main_t *em = &l2tvpp_encap_fastpath_main;
  l2tvpp_main_t *lm = &l2tvpp_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  int any = 0;

  clib_bitmap_foreach (sw_if_index, em->enabled)
  {
    any = 1;
    vlib_cli_output (vm, "%U", format_vnet_sw_if_index_name, vnm, sw_if_index);
  }
  if (!any)
    vlib_cli_output (vm, "l2tvpp encap-fastpath: no interfaces");
  vlib_cli_output (vm, "cached subscriber adjacencies: %u",
		   lm->encap_adj_count);
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_show_encap_fastpath_command, static) = {
  .path = "show l2tvpp encap-fastpath",
  .short_help = "show l2tvpp encap-fastpath",
  .function = l2tvpp_show_encap_fastpath_cli,
};
#endif /* CLIB_MARCH_VARIANT */
