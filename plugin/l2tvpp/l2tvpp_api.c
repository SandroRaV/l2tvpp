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
#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <l2tvpp/l2tvpp.h>

#include <l2tvpp/l2tvpp.api_enum.h>
#include <l2tvpp/l2tvpp.api_types.h>

#define REPLY_MSG_ID_BASE lm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_l2tvpp_tunnel_add_del_t_handler (vl_api_l2tvpp_tunnel_add_del_t * mp)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vl_api_l2tvpp_tunnel_add_del_reply_t *rmp;
  ip46_address_t local_ip, peer_ip;
  u32 tunnel_index = ~0;
  int rv;

  ip_address_decode (&mp->local_ip, &local_ip);
  ip_address_decode (&mp->peer_ip, &peer_ip);
  rv = l2tvpp_tunnel_add_del (lm, &local_ip, &peer_ip,
			      clib_net_to_host_u16 (mp->local_port),
			      clib_net_to_host_u16 (mp->peer_port),
			      clib_net_to_host_u16 (mp->local_tid),
			      clib_net_to_host_u16 (mp->peer_tid),
			      mp->is_add, &tunnel_index);

  REPLY_MACRO2 (VL_API_L2TVPP_TUNNEL_ADD_DEL_REPLY,
		({ rmp->tunnel_index = clib_host_to_net_u32 (tunnel_index); }));
}

static void
vl_api_l2tvpp_session_add_del_t_handler (vl_api_l2tvpp_session_add_del_t * mp)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vl_api_l2tvpp_session_add_del_reply_t *rmp;
  u32 sw_if_index = ~0;
  int rv;

  rv = l2tvpp_session_add_del (lm, clib_net_to_host_u32 (mp->tunnel_index),
			       clib_net_to_host_u16 (mp->local_sid),
			       clib_net_to_host_u16 (mp->peer_sid),
			       mp->acfc, mp->pfc, mp->is_add, &sw_if_index);

  REPLY_MACRO2 (VL_API_L2TVPP_SESSION_ADD_DEL_REPLY,
		({ rmp->sw_if_index = clib_host_to_net_u32 (sw_if_index); }));
}

static void
send_tunnel_details (l2tvpp_main_t * lm, vl_api_registration_t * reg,
		     u32 context, l2tvpp_tunnel_t * t)
{
  vl_api_l2tvpp_tunnel_details_t *rmp;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_L2TVPP_TUNNEL_DETAILS + lm->msg_id_base);
  rmp->context = context;
  rmp->tunnel_index = clib_host_to_net_u32 (t - lm->tunnels);
  ip_address_encode (&t->local_ip, IP46_TYPE_ANY, &rmp->local_ip);
  ip_address_encode (&t->peer_ip, IP46_TYPE_ANY, &rmp->peer_ip);
  rmp->local_port = clib_host_to_net_u16 (t->local_port);
  rmp->peer_port = clib_host_to_net_u16 (t->peer_port);
  rmp->local_tid = clib_host_to_net_u16 (t->local_tid);
  rmp->peer_tid = clib_host_to_net_u16 (t->peer_tid);
  rmp->n_sessions = clib_host_to_net_u32 (t->n_sessions);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_l2tvpp_tunnel_dump_t_handler (vl_api_l2tvpp_tunnel_dump_t * mp)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vl_api_registration_t *reg;
  l2tvpp_tunnel_t *t;
  u32 ti = clib_net_to_host_u32 (mp->tunnel_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (ti == ~0)
    {
      pool_foreach (t, lm->tunnels)
	send_tunnel_details (lm, reg, mp->context, t);
    }
  else if (!pool_is_free_index (lm->tunnels, ti))
    send_tunnel_details (lm, reg, mp->context,
			 pool_elt_at_index (lm->tunnels, ti));
}

static void
send_session_details (l2tvpp_main_t * lm, vl_api_registration_t * reg,
		      u32 context, l2tvpp_session_t * s)
{
  vl_api_l2tvpp_session_details_t *rmp;
  vnet_interface_main_t *im = &lm->vnet_main->interface_main;
  vlib_counter_t rx, tx;

  vlib_get_combined_counter (im->combined_sw_if_counters +
			     VNET_INTERFACE_COUNTER_RX, s->sw_if_index, &rx);
  vlib_get_combined_counter (im->combined_sw_if_counters +
			     VNET_INTERFACE_COUNTER_TX, s->sw_if_index, &tx);

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_L2TVPP_SESSION_DETAILS + lm->msg_id_base);
  rmp->context = context;
  rmp->sw_if_index = clib_host_to_net_u32 (s->sw_if_index);
  rmp->tunnel_index = clib_host_to_net_u32 (s->tunnel_index);
  rmp->local_sid = clib_host_to_net_u16 (s->local_sid);
  rmp->peer_sid = clib_host_to_net_u16 (s->peer_sid);
  rmp->acfc = s->acfc;
  rmp->pfc = s->pfc;
  rmp->rx_packets = clib_host_to_net_u64 (rx.packets);
  rmp->rx_bytes = clib_host_to_net_u64 (rx.bytes);
  rmp->tx_packets = clib_host_to_net_u64 (tx.packets);
  rmp->tx_bytes = clib_host_to_net_u64 (tx.bytes);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_l2tvpp_session_dump_t_handler (vl_api_l2tvpp_session_dump_t * mp)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vl_api_registration_t *reg;
  l2tvpp_session_t *s;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (s, lm->sessions)
    {
      if (sw_if_index == ~0 || s->sw_if_index == sw_if_index)
	send_session_details (lm, reg, mp->context, s);
    }
}

static void
vl_api_l2tvpp_set_handoff_t_handler (vl_api_l2tvpp_set_handoff_t * mp)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vl_api_l2tvpp_set_handoff_reply_t *rmp;
  int rv = 0;

  /* M3: handoff node not implemented yet */
  if (mp->enable)
    rv = VNET_API_ERROR_UNIMPLEMENTED;
  else
    lm->handoff_enabled = 0;

  REPLY_MACRO (VL_API_L2TVPP_SET_HANDOFF_REPLY);
}

#include <l2tvpp/l2tvpp.api.c>

static clib_error_t *
l2tvpp_api_init (vlib_main_t * vm)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  lm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (l2tvpp_api_init);
