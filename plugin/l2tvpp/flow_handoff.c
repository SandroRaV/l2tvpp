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
 * l2tvpp-flow-handoff: spread a single LAC's tunnel across workers by the
 * INNER flow, right after the driver.
 *
 * Why: l2tvpp-handoff (handoff.c) spreads by L2TP session, which is the
 * right unit for a busy LNS with thousands of sessions, but a test load
 * (Viavi, one tunnel, one session) or one heavy subscriber stays on a
 * single worker; and it runs after ip4-input/ip4-lookup/ip4-receive/
 * udp-local, so the RX worker has already spent most of the per-packet
 * budget before it hands off. This node is a "device-input" feature: the
 * driver (dpdk-input) delivers the frame here instead of ethernet-input,
 * we parse just far enough to hash a flow key and enqueue the buffer to
 * ethernet-input on the chosen worker, exactly like VPP's own
 * worker-handoff (vnet/handoff.c) but L2TP-aware:
 *
 *   L2TPv2 data (udp/1701, T=0): key = inner IPv4/IPv6 src, dst, proto and
 *     TCP/UDP ports (first fragment only), so one tunnel/session spreads
 *     over all workers while every 5-tuple flow stays in order.
 *   everything else IPv4/IPv6: key = outer src, dst, proto, ports - the
 *     same spread NIC RSS would give the plain side.
 *   non-IP, control (T=1), truncated: stay on the RX worker.
 *
 * Per-session ordering is NOT preserved (only per inner flow); PPP has no
 * ordering requirement for IP and l2tvpp-input ignores Ns/Nr anyway.
 *
 * Enable per interface with `l2tvpp flow-handoff <if> [workers <list>]
 * [fastpath]` (worker numbers as in `show threads` minus one, like `set
 * interface handoff`). Enabling it turns the session handoff off (`l2tvpp
 * handoff off`): udp/1701 then goes straight to l2tvpp-input on the worker
 * the buffer landed on, so a packet is never handed off twice.
 *
 * Modes, all per interface:
 *   workers <list>  spread by flow hash over those workers; a list of ONE
 *                   worker is an in-order pipeline (rx worker polls and
 *                   classifies, the other worker does everything else),
 *                   the only spread that keeps a single flow in order.
 *   no workers      stay on the rx worker (only useful with fastpath).
 *   fastpath        L2TPv2 data to one of our tunnel endpoints skips
 *                   ethernet-input, ip4-input, ip4-lookup, ip4-receive and
 *                   udp-local: the outer header is validated here (v4,
 *                   no options, not fragmented, header checksum, length,
 *                   dst = local tunnel IP, udp/1701, v2, T=0) and the
 *                   buffer is delivered to l2tvpp-input at the L2TP
 *                   header, locally or on the chosen worker through the
 *                   plugin's l2tvpp-input frame queue. Anything else takes
 *                   the ethernet-input path as before.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/crc32.h>
#include <l2tvpp/l2tvpp.h>

typedef struct
{
  u16 *workers;			/* thread indices, vec; empty = stay local */
  u32 rr;			/* round-robin cursor for spray mode */
  u8 enabled;
  u8 fastpath;
  u8 spray;			/* fan one flow across workers, ignore hash
				 * (reorders within a flow) */
} l2tvpp_flow_handoff_if_t;

typedef struct
{
  l2tvpp_flow_handoff_if_t *if_data;	/* by sw_if_index */
  u32 frame_queue_index;	/* -> ethernet-input, ~0 until first enable */
} l2tvpp_flow_handoff_main_t;

l2tvpp_flow_handoff_main_t l2tvpp_flow_handoff_main = {
  .frame_queue_index = ~0,
};

typedef enum
{
  L2TVPP_FLOW_HANDOFF_NEXT_DROP,
  L2TVPP_FLOW_HANDOFF_NEXT_ETHERNET_INPUT,
  L2TVPP_FLOW_HANDOFF_NEXT_L2TVPP_INPUT,
  L2TVPP_FLOW_HANDOFF_N_NEXT,
} l2tvpp_flow_handoff_next_t;

/* classification result */
#define L2TVPP_FLOW_KIND_LOCAL 0	/* not hashable: ethernet-input, this thread */
#define L2TVPP_FLOW_KIND_OUTER 1	/* outer 5-tuple hash, ethernet-input */
#define L2TVPP_FLOW_KIND_INNER 2	/* inner 5-tuple hash, ethernet-input */
#define L2TVPP_FLOW_KIND_FAST  3	/* inner 5-tuple hash, l2tvpp-input */

typedef struct
{
  u32 sw_if_index;
  u32 hash;
  u16 thread_index;
  u8 kind;
} l2tvpp_flow_handoff_trace_t;

static u8 *
format_l2tvpp_flow_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tvpp_flow_handoff_trace_t *t =
    va_arg (*args, l2tvpp_flow_handoff_trace_t *);
  static char *kinds[] =
    { "local", "outer 5-tuple", "inner 5-tuple", "inner 5-tuple fastpath" };
  return format (s, "l2tvpp-flow-handoff: sw_if_index %d %s hash 0x%08x "
		 "-> thread %d", t->sw_if_index, kinds[t->kind], t->hash,
		 t->thread_index);
}

#define foreach_l2tvpp_flow_handoff_error _ (CONGESTION, "congestion drop")

typedef enum
{
#define _(sym, str) L2TVPP_FLOW_HANDOFF_ERROR_##sym,
  foreach_l2tvpp_flow_handoff_error
#undef _
    L2TVPP_FLOW_HANDOFF_N_ERROR,
} l2tvpp_flow_handoff_error_t;

static char *l2tvpp_flow_handoff_error_strings[] = {
#define _(sym, str) str,
  foreach_l2tvpp_flow_handoff_error
#undef _
};

/* flow key fed to crc32c; ports are 0 for non-TCP/UDP and fragments */
typedef struct
{
  ip6_address_t src;
  ip6_address_t dst;
  u32 ports;
  u8 proto;
  u8 pad[3];
} l2tvpp_flow_key_t;

/* Hash an IPv4 or IPv6 header at p (ethertype-agnostic: we look at the
 * version nibble). Returns 1 and the hash, or 0 if truncated/unknown. */
static_always_inline int
l2tvpp_hash_ip (u8 * p, u8 * end, u32 * hash)
{
  l2tvpp_flow_key_t k;
  u8 *l4;
  u8 proto, ver;

  if (PREDICT_FALSE (p + 1 > end))
    return 0;
  ver = p[0] >> 4;
  clib_memset (&k, 0, sizeof (k));
  if (PREDICT_TRUE (ver == 4))
    {
      ip4_header_t *ip = (ip4_header_t *) p;
      if (PREDICT_FALSE (p + sizeof (*ip) > end))
	return 0;
      k.src.as_u32[0] = ip->src_address.as_u32;
      k.dst.as_u32[0] = ip->dst_address.as_u32;
      proto = ip->protocol;
      l4 = p + ip4_header_bytes (ip);
      /* only the first (or an unfragmented) fragment carries ports */
      if (PREDICT_FALSE (ip4_get_fragment_offset (ip)))
	l4 = end;
    }
  else if (ver == 6)
    {
      ip6_header_t *ip = (ip6_header_t *) p;
      if (PREDICT_FALSE (p + sizeof (*ip) > end))
	return 0;
      k.src = ip->src_address;
      k.dst = ip->dst_address;
      proto = ip->protocol;	/* next header; ext headers -> no ports */
      l4 = p + sizeof (*ip);
    }
  else
    return 0;

  k.proto = proto;
  if ((proto == IP_PROTOCOL_UDP || proto == IP_PROTOCOL_TCP)
      && l4 + 4 <= end)
    k.ports = *(u32 *) l4;
  *hash = clib_crc32c ((u8 *) & k, sizeof (k));
  return 1;
}

static_always_inline int
l2tvpp_is_local_ip4 (l2tvpp_main_t * lm, u32 addr)
{
  u32 *a;
  vec_foreach (a, lm->local_ip4s) if (*a == addr) return 1;
  return 0;
}

/* From the ethernet header: outer IP; if it is L2TPv2 data to udp/1701,
 * walk into the PPP payload and hash the inner IP instead. With fastpath,
 * L2TP data whose outer header passes every check we would otherwise do
 * in ip4-input/ip4-lookup/ip4-receive is flagged KIND_FAST and
 * *l2tp_offset is set to the L2TP header. The hash is only computed when
 * want_hash is set (more than one target worker). */
static_always_inline u8
l2tvpp_flow_classify (l2tvpp_main_t * lm, vlib_buffer_t * b, int fastpath,
		      int want_hash, u32 * hash, u16 * l2tp_offset)
{
  u8 *start = vlib_buffer_get_current (b);
  u8 *p = start;
  u8 *end = p + b->current_length;
  ethernet_header_t *eth = (ethernet_header_t *) p;
  u16 type;
  int tagged = 0;

  if (PREDICT_FALSE (p + sizeof (*eth) > end))
    return L2TVPP_FLOW_KIND_LOCAL;
  type = eth->type;
  p += sizeof (*eth);
  if (type == clib_host_to_net_u16 (ETHERNET_TYPE_VLAN))
    {
      if (PREDICT_FALSE (p + 4 > end))
	return L2TVPP_FLOW_KIND_LOCAL;
      type = *(u16 *) (p + 2);
      p += 4;
      tagged = 1;
    }
  if (type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    {
      if (type == clib_host_to_net_u16 (ETHERNET_TYPE_IP6))
	return (!want_hash || l2tvpp_hash_ip (p, end, hash))
	  ? L2TVPP_FLOW_KIND_OUTER : L2TVPP_FLOW_KIND_LOCAL;
      return L2TVPP_FLOW_KIND_LOCAL;
    }

  /* outer IPv4: is it plain L2TPv2 data to us? */
  {
    ip4_header_t *ip = (ip4_header_t *) p;
    udp_header_t *udp;
    u8 *l2tp, *cur;
    u16 flags;
    int fast;

    if (PREDICT_FALSE (p + sizeof (*ip) > end))
      return L2TVPP_FLOW_KIND_LOCAL;
    if (ip->protocol != IP_PROTOCOL_UDP || ip4_get_fragment_offset (ip)
	|| ip4_get_fragment_more (ip))
      goto outer;
    udp = (udp_header_t *) (p + ip4_header_bytes (ip));
    if (PREDICT_FALSE ((u8 *) udp + sizeof (*udp) > end))
      goto outer;
    if (udp->dst_port != clib_host_to_net_u16 (L2TVPP_UDP_PORT))
      goto outer;
    l2tp = (u8 *) (udp + 1);
    if (PREDICT_FALSE (l2tp + 6 > end))
      goto outer;
    flags = clib_net_to_host_u16 (*(u16 *) l2tp);
    if ((flags & L2TVPP_HDR_VER) != 2 || (flags & L2TVPP_HDR_T))
      return L2TVPP_FLOW_KIND_LOCAL;	/* control or not v2: keep it local */

    /* fastpath: everything ip4-input + ip4-lookup + ip4-receive would have
     * checked before udp-local handed the packet to l2tvpp-input */
    fast = fastpath && !tagged
      && ip->ip_version_and_header_length == 0x45
      && clib_net_to_host_u16 (ip->length) <= (end - p)
      && clib_net_to_host_u16 (ip->length) >= sizeof (*ip) + sizeof (*udp) + 6
      && ip4_header_checksum_is_valid (ip)
      && l2tvpp_is_local_ip4 (lm, ip->dst_address.as_u32);
    if (fast)
      {
	*l2tp_offset = l2tp - start;
	/* what ethernet-input/ip4-input would have recorded; l2tvpp-input
	 * rewinds punts to l3_hdr_offset, ip4-punt-redirect and friends
	 * read the same fields */
	vnet_buffer (b)->l2_hdr_offset = b->current_data;
	vnet_buffer (b)->l3_hdr_offset = b->current_data + (p - start);
	vnet_buffer (b)->l4_hdr_offset = b->current_data + ((u8 *) udp - start);
	b->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID
	  | VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      }

    if (!want_hash)
      return fast ? L2TVPP_FLOW_KIND_FAST : L2TVPP_FLOW_KIND_INNER;

    /* same walk as l2tvpp-input: flags, [len], tid, sid, [Ns Nr], [off] */
    cur = l2tp + 2;
    if (flags & L2TVPP_HDR_L)
      cur += 2;
    cur += 4;
    if (flags & L2TVPP_HDR_S)
      cur += 4;
    if (flags & L2TVPP_HDR_O)
      {
	if (PREDICT_FALSE (cur + 2 > end))
	  goto outer;
	cur += 2 + clib_net_to_host_u16 (*(u16 *) cur);
      }
    if (PREDICT_FALSE (cur + 4 > end))
      goto outer;
    /* PPP: optional FF 03, then 1- or 2-byte protocol (PFC if odd) */
    if (cur[0] == 0xff && cur[1] == 0x03)
      cur += 2;
    if (cur[0] & 1)
      {
	if (cur[0] != (PPP_PROTO_IP4 & 0xff)
	    && cur[0] != (PPP_PROTO_IP6 & 0xff))
	  goto outer;
	cur += 1;
      }
    else
      {
	u16 pp = clib_net_to_host_u16 (*(u16 *) cur);
	if (pp != PPP_PROTO_IP4 && pp != PPP_PROTO_IP6)
	  goto outer;
	cur += 2;
      }
    if (l2tvpp_hash_ip (cur, end, hash))
      return fast ? L2TVPP_FLOW_KIND_FAST : L2TVPP_FLOW_KIND_INNER;
    if (fast)
      {
	/* inner not hashable (non-IP PPP payload): still ours, one worker */
	*hash = 0;
	return L2TVPP_FLOW_KIND_FAST;
      }
  outer:
    if (!want_hash)
      return L2TVPP_FLOW_KIND_OUTER;
    return l2tvpp_hash_ip (p, end, hash) ? L2TVPP_FLOW_KIND_OUTER
      : L2TVPP_FLOW_KIND_LOCAL;
  }
}

VLIB_NODE_FN (l2tvpp_flow_handoff_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  l2tvpp_flow_handoff_main_t *fm = &l2tvpp_flow_handoff_main;
  l2tvpp_main_t *lm = &l2tvpp_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 n = frame->n_vectors, *from = vlib_frame_vector_args (frame);
  u32 this_thread = vm->thread_index;
  /* three output sets: local (by next index), remote via ethernet-input
   * frame queue, remote via l2tvpp-input frame queue */
  u32 local_bi[VLIB_FRAME_SIZE], eth_bi[VLIB_FRAME_SIZE],
    l2tp_bi[VLIB_FRAME_SIZE];
  u16 local_next[VLIB_FRAME_SIZE], eth_ti[VLIB_FRAME_SIZE],
    l2tp_ti[VLIB_FRAME_SIZE];
  u32 n_local = 0, n_eth = 0, n_l2tp = 0, n_enq, i;

  vlib_get_buffers (vm, from, bufs, n);

  for (i = 0; i < n; i++)
    {
      l2tvpp_flow_handoff_if_t *ifd;
      u32 hash = 0, sw_if_index, nw;
      u16 thread, l2tp_offset = 0;
      u8 kind;

      if (PREDICT_TRUE (i + 4 < n))
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[i + 4], LOAD);
	  /* the walk reaches ~80 bytes in: two cache lines */
	  p = vlib_buffer_get_current (b[i + 2]);
	  clib_prefetch_load (p);
	  clib_prefetch_load (p + CLIB_CACHE_LINE_BYTES);
	}

      sw_if_index = vnet_buffer (b[i])->sw_if_index[VLIB_RX];
      ifd = vec_elt_at_index (fm->if_data, sw_if_index);
      nw = vec_len (ifd->workers);
      /* spray needs no hash (round-robin), so classify cheaply; otherwise
       * compute the flow hash only when there is more than one target */
      kind = l2tvpp_flow_classify (lm, b[i], ifd->fastpath,
				   !ifd->spray && nw > 1, &hash, &l2tp_offset);
      if (kind == L2TVPP_FLOW_KIND_LOCAL || nw == 0)
	thread = this_thread;
      else if (ifd->spray)
	thread = ifd->workers[ifd->rr++ % nw];	/* benign race on rr */
      else if (nw == 1)
	thread = ifd->workers[0];
      else
	thread = ifd->workers[is_pow2 (nw) ? (hash & (nw - 1)) : hash % nw];

      if (kind == L2TVPP_FLOW_KIND_FAST)
	{
	  /* deliver at the L2TP header, as udp-local would */
	  vlib_buffer_advance (b[i], l2tp_offset);
	  vnet_buffer (b[i])->sw_if_index[VLIB_TX] = ~0;
	  if (thread == this_thread)
	    {
	      local_bi[n_local] = from[i];
	      local_next[n_local++] = L2TVPP_FLOW_HANDOFF_NEXT_L2TVPP_INPUT;
	    }
	  else
	    {
	      l2tp_bi[n_l2tp] = from[i];
	      l2tp_ti[n_l2tp++] = thread;
	    }
	}
      else if (thread == this_thread)
	{
	  local_bi[n_local] = from[i];
	  local_next[n_local++] = L2TVPP_FLOW_HANDOFF_NEXT_ETHERNET_INPUT;
	}
      else
	{
	  eth_bi[n_eth] = from[i];
	  eth_ti[n_eth++] = thread;
	}

      if (PREDICT_FALSE (b[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2tvpp_flow_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[i], sizeof (*t));
	  t->sw_if_index = sw_if_index;
	  t->hash = hash;
	  t->thread_index = thread;
	  t->kind = kind;
	}
    }

  if (n_local)
    vlib_buffer_enqueue_to_next (vm, node, local_bi, local_next, n_local);
  if (n_eth)
    {
      n_enq = vlib_buffer_enqueue_to_thread (vm, node, fm->frame_queue_index,
					     eth_bi, eth_ti, n_eth, 1);
      if (PREDICT_FALSE (n_enq < n_eth))
	vlib_node_increment_counter (vm, node->node_index,
				     L2TVPP_FLOW_HANDOFF_ERROR_CONGESTION,
				     n_eth - n_enq);
    }
  if (n_l2tp)
    {
      n_enq = vlib_buffer_enqueue_to_thread (vm, node,
					     lm->handoff_frame_queue_index,
					     l2tp_bi, l2tp_ti, n_l2tp, 1);
      if (PREDICT_FALSE (n_enq < n_l2tp))
	vlib_node_increment_counter (vm, node->node_index,
				     L2TVPP_FLOW_HANDOFF_ERROR_CONGESTION,
				     n_l2tp - n_enq);
    }
  return n;
}

VLIB_REGISTER_NODE (l2tvpp_flow_handoff_node) = {
  .name = "l2tvpp-flow-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_l2tvpp_flow_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = L2TVPP_FLOW_HANDOFF_N_ERROR,
  .error_strings = l2tvpp_flow_handoff_error_strings,
  .n_next_nodes = L2TVPP_FLOW_HANDOFF_N_NEXT,
  .next_nodes = {
    [L2TVPP_FLOW_HANDOFF_NEXT_DROP] = "error-drop",
    [L2TVPP_FLOW_HANDOFF_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [L2TVPP_FLOW_HANDOFF_NEXT_L2TVPP_INPUT] = "l2tvpp-input",
  },
};

VNET_FEATURE_INIT (l2tvpp_flow_handoff_feature, static) = {
  .arc_name = "device-input",
  .node_name = "l2tvpp-flow-handoff",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

#ifndef CLIB_MARCH_VARIANT
int
l2tvpp_flow_handoff_enable_disable (vlib_main_t * vm, u32 sw_if_index,
				    uword * workers_bitmap, u8 fastpath,
				    u8 spray, u8 enable)
{
  l2tvpp_flow_handoff_main_t *fm = &l2tvpp_flow_handoff_main;
  vnet_main_t *vnm = vnet_get_main ();
  l2tvpp_flow_handoff_if_t *ifd;
  vnet_sw_interface_t *sw;
  u32 n_workers = vlib_num_workers ();
  int i;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  if (enable && workers_bitmap
      && clib_bitmap_last_set (workers_bitmap) >= n_workers)
    return VNET_API_ERROR_INVALID_WORKER;

  if (fm->frame_queue_index == ~0)
    {
      vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
      fm->frame_queue_index = vlib_frame_queue_main_init (n->index, 0);
    }

  vec_validate (fm->if_data, sw_if_index);
  ifd = vec_elt_at_index (fm->if_data, sw_if_index);
  if (ifd->enabled == enable && !enable)
    return 0;

  vlib_worker_thread_barrier_sync (vm);
  vec_free (ifd->workers);
  if (enable && workers_bitmap)
    {
      clib_bitmap_foreach (i, workers_bitmap)
	vec_add1 (ifd->workers, (u16) (1 + i));	/* workers are threads 1..n */
    }
  ifd->fastpath = enable ? fastpath : 0;
  ifd->spray = enable ? spray : 0;
  ifd->rr = 0;
  if (ifd->enabled != enable)
    vnet_feature_enable_disable ("device-input", "l2tvpp-flow-handoff",
				 sw_if_index, enable, 0, 0);
  ifd->enabled = enable;
  vlib_worker_thread_barrier_release (vm);

  /* never hand a packet off twice: the session handoff would move it
   * again (all sessions of a test load land on one worker anyway) */
  if (enable)
    l2tvpp_set_handoff (&l2tvpp_main, 0);
  return 0;
}

static clib_error_t *
l2tvpp_flow_handoff_cli (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line, *line = &_line;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  uword *bitmap = 0;
  u8 enable = 1, fastpath = 0, spray = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line))
    return clib_error_return (0, "missing arguments");
  while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line, "disable") || unformat (line, "del"))
	enable = 0;
      else if (unformat (line, "workers %U", unformat_bitmap_list, &bitmap))
	;
      else if (unformat (line, "fastpath"))
	fastpath = 1;
      else if (unformat (line, "spray"))
	spray = 1;
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
  if (enable && bitmap == 0 && !fastpath)
    return clib_error_return (0, "workers <list> and/or fastpath required");
  if (spray && clib_bitmap_count_set_bits (bitmap) < 2)
    {
      clib_bitmap_free (bitmap);
      return clib_error_return (0, "spray needs workers <list> with >= 2 "
				"workers");
    }

  rv = l2tvpp_flow_handoff_enable_disable (vm, sw_if_index, bitmap, fastpath,
					   spray, enable);
  clib_bitmap_free (bitmap);
  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "not a hardware interface");
    case VNET_API_ERROR_INVALID_WORKER:
      return clib_error_return (0, "invalid worker(s), have %d",
				vlib_num_workers ());
    default:
      return clib_error_return (0, "error %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_flow_handoff_command, static) = {
  .path = "l2tvpp flow-handoff",
  .short_help = "l2tvpp flow-handoff <interface> [workers <list>] [fastpath]"
		" [spray] | l2tvpp flow-handoff <interface> disable",
  .function = l2tvpp_flow_handoff_cli,
};

static clib_error_t *
l2tvpp_inner_checksum_cli (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  unformat_input_t _line, *line = &_line;

  if (unformat_user (input, unformat_line_input, line))
    {
      while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line, "on"))
	    lm->inner_ip4_no_checksum = 0;
	  else if (unformat (line, "off"))
	    lm->inner_ip4_no_checksum = 1;
	  else
	    {
	      unformat_free (line);
	      return clib_error_return (0, "unknown input");
	    }
	}
      unformat_free (line);
    }
  vlib_cli_output (vm, "l2tvpp inner IPv4 header checksum verification %s",
		   lm->inner_ip4_no_checksum ? "off" : "on");
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_inner_checksum_command, static) = {
  .path = "l2tvpp inner-checksum",
  .short_help = "l2tvpp inner-checksum [on|off]",
  .function = l2tvpp_inner_checksum_cli,
};

static clib_error_t *
l2tvpp_show_flow_handoff_cli (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  l2tvpp_flow_handoff_main_t *fm = &l2tvpp_flow_handoff_main;
  l2tvpp_main_t *lm = &l2tvpp_main;
  vnet_main_t *vnm = vnet_get_main ();
  l2tvpp_flow_handoff_if_t *ifd;
  u32 sw_if_index;
  int any = 0;

  vec_foreach_index (sw_if_index, fm->if_data)
  {
    ifd = vec_elt_at_index (fm->if_data, sw_if_index);
    if (!ifd->enabled)
      continue;
    any = 1;
    {
      u8 *ts = 0;
      u16 *w;
      vec_foreach (w, ifd->workers) ts = format (ts, "%s%d", ts ? "," : "", *w);
      if (ts)
	vec_add1 (ts, 0);
      vlib_cli_output (vm, "%U -> threads %s%s%s",
		       format_vnet_sw_if_index_name, vnm, sw_if_index,
		       ts ? (char *) ts : "local",
		       ifd->fastpath ? " fastpath" : "",
		       ifd->spray ? " spray(reorders)" : "");
      vec_free (ts);
    }
  }
  if (!any)
    vlib_cli_output (vm, "l2tvpp flow-handoff: no interfaces");
  vlib_cli_output (vm, "inner IPv4 checksum verification %s, local tunnel "
		   "endpoints %d", lm->inner_ip4_no_checksum ? "off" : "on",
		   vec_len (lm->local_ip4s));
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_show_flow_handoff_command, static) = {
  .path = "show l2tvpp flow-handoff",
  .short_help = "show l2tvpp flow-handoff",
  .function = l2tvpp_show_flow_handoff_cli,
};
#endif /* CLIB_MARCH_VARIANT */
