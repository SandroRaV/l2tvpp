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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <l2tvpp/l2tvpp.h>

l2tvpp_main_t l2tvpp_main;

/* --------------------------------------------------------------------
 * formatting
 */
static u8 *
format_l2tvpp_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "l2tvpp%d", dev_instance);
}

u8 *
format_l2tvpp_tunnel (u8 * s, va_list * args)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  l2tvpp_tunnel_t *t = va_arg (*args, l2tvpp_tunnel_t *);
  return format (s, "[%d] %U:%d -> %U:%d tid %d/%d sessions %d",
		 t - lm->tunnels,
		 format_ip46_address, &t->local_ip, IP46_TYPE_ANY,
		 t->local_port,
		 format_ip46_address, &t->peer_ip, IP46_TYPE_ANY,
		 t->peer_port, t->local_tid, t->peer_tid, t->n_sessions);
}

u8 *
format_l2tvpp_session (u8 * s, va_list * args)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  l2tvpp_session_t *sess = va_arg (*args, l2tvpp_session_t *);
  return format (s, "[%d] %U tunnel %d sid %d/%d acfc %d pfc %d",
		 sess - lm->sessions,
		 format_vnet_sw_if_index_name, lm->vnet_main, sess->sw_if_index,
		 sess->tunnel_index, sess->local_sid, sess->peer_sid,
		 sess->acfc, sess->pfc);
}

/* --------------------------------------------------------------------
 * encap: midchain adjacency per session interface and link type.
 * The rewrite is IP4 + UDP + L2TP + PPP; ip4-rewrite prepends it, the
 * fixup patches lengths/checksum, then the adjacency stacks on the FIB
 * entry of the peer, i.e. the packet continues through ip4-lookup.
 */
static u8 *
l2tvpp_build_rewrite_i (l2tvpp_session_t * sess, vnet_link_t link_type)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  l2tvpp_tunnel_t *t = pool_elt_at_index (lm->tunnels, sess->tunnel_index);
  u8 *rw = 0;
  ip4_header_t *ip;
  udp_header_t *udp;
  l2tvpp_hdr_t *l2tp;
  l2tvpp_ppp_hdr_t *ppp;
  u16 proto;

  switch (link_type)
    {
    case VNET_LINK_IP4:
      proto = PPP_PROTO_IP4;
      break;
    case VNET_LINK_IP6:
      proto = PPP_PROTO_IP6;
      break;
    default:
      return 0;
    }

  /* M1: always emit FF 03 + 2-byte protocol, acfc/pfc are recorded but
   * not yet applied (see design.md step 4) */
  vec_validate (rw, sizeof (*ip) + sizeof (*udp) + sizeof (*l2tp)
		+ sizeof (*ppp) - 1);

  ip = (ip4_header_t *) rw;
  ip->ip_version_and_header_length = 0x45;
  ip->tos = 0;
  ip->length = 0;		/* fixup */
  ip->fragment_id = 0;
  ip->flags_and_fragment_offset = 0;	/* DF clear on purpose */
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->checksum = 0;		/* fixup */
  ip->src_address.as_u32 = t->local_ip.ip4.as_u32;
  ip->dst_address.as_u32 = t->peer_ip.ip4.as_u32;

  udp = (udp_header_t *) (ip + 1);
  udp->src_port = clib_host_to_net_u16 (t->local_port);
  udp->dst_port = clib_host_to_net_u16 (t->peer_port);
  udp->length = 0;		/* fixup */
  udp->checksum = 0;

  l2tp = (l2tvpp_hdr_t *) (udp + 1);
  l2tp->flags_ver = clib_host_to_net_u16 (2);
  l2tp->tunnel_id = clib_host_to_net_u16 (t->peer_tid);
  l2tp->session_id = clib_host_to_net_u16 (sess->peer_sid);

  ppp = (l2tvpp_ppp_hdr_t *) (l2tp + 1);
  ppp->address = 0xff;
  ppp->control = 0x03;
  ppp->protocol = clib_host_to_net_u16 (proto);

  return rw;
}

static u8 *
l2tvpp_build_rewrite (vnet_main_t * vnm, u32 sw_if_index,
		      vnet_link_t link_type, const void *dst_address)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  u32 si = lm->session_index_by_sw_if_index[sw_if_index];
  return l2tvpp_build_rewrite_i (pool_elt_at_index (lm->sessions, si),
				 link_type);
}

static void
l2tvpp_fixup (vlib_main_t * vm, const ip_adjacency_t * adj,
	      vlib_buffer_t * b, const void *data)
{
  ip4_header_t *ip = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *) (ip + 1);
  u16 len = vlib_buffer_length_in_chain (vm, b);

  /* the outer IP is ours, not the subscriber's: don't let ip4-rewrite
   * TTL-decrement it */
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  ip->length = clib_host_to_net_u16 (len);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (len - sizeof (*ip));
}

static void
l2tvpp_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  u32 si = (sw_if_index < vec_len (lm->session_index_by_sw_if_index)) ?
    lm->session_index_by_sw_if_index[sw_if_index] : ~0;
  l2tvpp_session_t *sess;
  l2tvpp_tunnel_t *t;
  ip_adjacency_t *adj = adj_get (ai);
  u8 *rw;

  if (si == ~0 || pool_is_free_index (lm->sessions, si))
    return;
  sess = pool_elt_at_index (lm->sessions, si);
  t = pool_elt_at_index (lm->tunnels, sess->tunnel_index);
  rw = l2tvpp_build_rewrite_i (sess, adj->ia_link);

  if (!rw)
    return;

  adj_nbr_midchain_update_rewrite (ai, l2tvpp_fixup, sess,
				   ADJ_FLAG_MIDCHAIN_IP_STACK, rw);

  fib_prefix_t pfx = {
    .fp_len = 32,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4 = t->peer_ip.ip4,
  };
  adj_midchain_delegate_stack (ai, t->encap_fib_index, &pfx);
}

/* No VNET_DEVICE_CLASS_TX_FN on purpose: like ipip/gre tunnel interfaces,
 * transit traffic leaves through the midchain adjacency's stacked next_dpo
 * (ip4-midchain -> adj-midchain-tx -> peer forwarding). Defining a device tx
 * function would instead route ip4-midchain into interface-N-output and drop
 * the encapsulated packet. */

/* Drop the midchain delegate (and its fib_entry_track sibling) from every
 * adjacency on the session interface before the interface is deleted, so no
 * stale delegate lingers on the peer's FIB entry and the adjacency is freed
 * cleanly for reuse. */
static adj_walk_rc_t
l2tvpp_adj_remove_delegate (adj_index_t ai, void *ctx)
{
  adj_midchain_delegate_remove (ai);
  return ADJ_WALK_RC_CONTINUE;
}

static clib_error_t *
l2tvpp_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

VNET_DEVICE_CLASS (l2tvpp_device_class) = {
  .name = "l2tvpp",
  .format_device_name = format_l2tvpp_name,
  .admin_up_down_function = l2tvpp_admin_up_down,
};

VNET_HW_INTERFACE_CLASS (l2tvpp_hw_class) = {
  .name = "l2tvpp",
  .build_rewrite = l2tvpp_build_rewrite,
  .update_adjacency = l2tvpp_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

/* --------------------------------------------------------------------
 * tunnels and sessions
 */
static l2tvpp_tunnel_t *
l2tvpp_tunnel_find (l2tvpp_main_t * lm, ip46_address_t * peer_ip,
		    u16 peer_port, u16 local_tid)
{
  l2tvpp_tunnel_t *t;
  pool_foreach (t, lm->tunnels)
    {
      if (t->local_tid == local_tid && t->peer_port == peer_port
	  && ip46_address_is_equal (&t->peer_ip, peer_ip))
	return t;
    }
  return 0;
}

int
l2tvpp_tunnel_add_del (l2tvpp_main_t * lm, ip46_address_t * local_ip,
		       ip46_address_t * peer_ip, u16 local_port,
		       u16 peer_port, u16 local_tid, u16 peer_tid,
		       u8 is_add, u32 * tunnel_indexp)
{
  l2tvpp_tunnel_t *t;

  if (!ip46_address_is_ip4 (local_ip) || !ip46_address_is_ip4 (peer_ip))
    return VNET_API_ERROR_UNIMPLEMENTED;	/* M1: IPv4 outer only */

  t = l2tvpp_tunnel_find (lm, peer_ip, peer_port, local_tid);

  if (is_add)
    {
      if (t)
	return VNET_API_ERROR_TUNNEL_EXIST;
      pool_get_zero (lm->tunnels, t);
      t->local_ip = *local_ip;
      t->peer_ip = *peer_ip;
      t->local_port = local_port;
      t->peer_port = peer_port;
      t->local_tid = local_tid;
      t->peer_tid = peer_tid;
      t->encap_fib_index = 0;
      if (tunnel_indexp)
	*tunnel_indexp = t - lm->tunnels;
      return 0;
    }

  if (!t)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (t->n_sessions)
    return VNET_API_ERROR_INSTANCE_IN_USE;
  pool_put (lm->tunnels, t);
  return 0;
}

int
l2tvpp_session_add_del (l2tvpp_main_t * lm, u32 tunnel_index,
			u16 local_sid, u16 peer_sid, u8 acfc, u8 pfc,
			u8 is_add, u32 * sw_if_indexp)
{
  vnet_main_t *vnm = lm->vnet_main;
  l2tvpp_tunnel_t *t;
  l2tvpp_session_t *sess;
  l2tvpp_session_key_t key;
  clib_bihash_kv_16_8_t kv;

  if (pool_is_free_index (lm->tunnels, tunnel_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  t = pool_elt_at_index (lm->tunnels, tunnel_index);

  l2tvpp_make_key (&key, t->local_tid, local_sid);
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];

  if (is_add)
    {
      if (!clib_bihash_search_16_8 (&lm->session_by_key, &kv, &kv))
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      pool_get_zero (lm->sessions, sess);
      sess->tunnel_index = tunnel_index;
      sess->local_sid = local_sid;
      sess->peer_sid = peer_sid;
      sess->acfc = acfc;
      sess->pfc = pfc;

      sess->hw_if_index = vnet_register_interface (vnm,
						   l2tvpp_device_class.index,
						   sess - lm->sessions,
						   l2tvpp_hw_class.index,
						   sess - lm->sessions);
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, sess->hw_if_index);
      sess->sw_if_index = hi->sw_if_index;

      /* virtual interface: no carrier of its own, so declare link up now
       * or the midchain IP-stack falls back to the (dropping) tx node */
      vnet_hw_interface_set_flags (vnm, sess->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);

      /* route the L3 output of this interface into the midchain tx node, so
       * an encapped packet goes ip4-midchain -> tunnel-output -> stacked
       * peer forwarding, exactly like ipip/gre. Without this the midchain's
       * next node resolves to local0-output and the packet is dropped. */
      vnet_set_interface_l3_output_node (lm->vlib_main, sess->sw_if_index,
					 (u8 *) "tunnel-output");

      vec_validate_init_empty (lm->session_index_by_sw_if_index,
			       sess->sw_if_index, ~0);
      lm->session_index_by_sw_if_index[sess->sw_if_index] =
	sess - lm->sessions;

      kv.value = sess - lm->sessions;
      clib_bihash_add_del_16_8 (&lm->session_by_key, &kv, 1);

      vnet_sw_interface_set_flags (vnm, sess->sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      ip4_sw_interface_enable_disable (sess->sw_if_index, 1);
      ip6_sw_interface_enable_disable (sess->sw_if_index, 1);

      t->n_sessions++;
      if (sw_if_indexp)
	*sw_if_indexp = sess->sw_if_index;
      return 0;
    }

  if (clib_bihash_search_16_8 (&lm->session_by_key, &kv, &kv))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  sess = pool_elt_at_index (lm->sessions, kv.value);

  ip4_sw_interface_enable_disable (sess->sw_if_index, 0);
  ip6_sw_interface_enable_disable (sess->sw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, sess->sw_if_index, 0);
  clib_bihash_add_del_16_8 (&lm->session_by_key, &kv, 0);
  lm->session_index_by_sw_if_index[sess->sw_if_index] = ~0;
  adj_nbr_walk (sess->sw_if_index, FIB_PROTOCOL_IP4,
		l2tvpp_adj_remove_delegate, 0);
  adj_nbr_walk (sess->sw_if_index, FIB_PROTOCOL_IP6,
		l2tvpp_adj_remove_delegate, 0);
  vnet_reset_interface_l3_output_node (lm->vlib_main, sess->sw_if_index);
  vnet_delete_hw_interface (vnm, sess->hw_if_index);
  t->n_sessions--;
  pool_put (lm->sessions, sess);
  return 0;
}

/* --------------------------------------------------------------------
 * worker handoff (spread decap across cores by session; see handoff.c)
 */
int
l2tvpp_set_handoff (l2tvpp_main_t * lm, u8 enable)
{
  vlib_main_t *vm = lm->vlib_main;

  enable = enable ? 1 : 0;
  if (enable == lm->handoff_enabled)
    return 0;

  vlib_worker_thread_barrier_sync (vm);
  /* re-point udp/1701 at the handoff node (enable) or straight at the
   * processing node (disable); the barrier makes the swap safe under load */
  udp_register_dst_port (vm, L2TVPP_UDP_PORT,
			 enable ? l2tvpp_handoff_node.index
			 : l2tvpp_input_node.index, 1);
  lm->handoff_enabled = enable;
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

/* --------------------------------------------------------------------
 * init
 */
static clib_error_t *
l2tvpp_init (vlib_main_t * vm)
{
  l2tvpp_main_t *lm = &l2tvpp_main;

  lm->vlib_main = vm;
  lm->vnet_main = vnet_get_main ();
  clib_bihash_init_16_8 (&lm->session_by_key, "l2tvpp sessions",
			 64 * 1024, 32 << 20);

  /* frame queue feeding l2tvpp-input, used by the handoff node to move
   * buffers to the worker chosen for their session */
  lm->handoff_frame_queue_index =
    vlib_frame_queue_main_init (l2tvpp_input_node.index, 0);
  lm->handoff_enabled = 0;

  /* take over UDP 1701 from udp-local; non-data packets are handed back
   * to the punt path by l2tvpp-input */
  udp_register_dst_port (vm, L2TVPP_UDP_PORT, l2tvpp_input_node.index, 1);
  return 0;
}

VLIB_INIT_FUNCTION (l2tvpp_init) =
{
  .runs_after = VLIB_INITS ("udp_local_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "L2TPv2 LNS data plane (l2tvpp)",
};
