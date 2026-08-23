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
/* L2TPv2 LNS data plane plugin: object model */
#ifndef __included_l2tp2_h__
#define __included_l2tp2_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vppinfra/bihash_16_8.h>

#define L2TP2_UDP_PORT 1701

/* RFC 2661 header flag bits */
#define L2TP2_HDR_T   0x8000
#define L2TP2_HDR_L   0x4000
#define L2TP2_HDR_S   0x0800
#define L2TP2_HDR_O   0x0200
#define L2TP2_HDR_P   0x0100
#define L2TP2_HDR_VER 0x000F

/* PPP protocol numbers we forward; everything else is punted */
#define PPP_PROTO_IP4 0x0021
#define PPP_PROTO_IP6 0x0057

typedef struct
{
  ip46_address_t local_ip;
  ip46_address_t peer_ip;
  u16 local_port;
  u16 peer_port;
  u16 local_tid;		/* in packets from the LAC */
  u16 peer_tid;			/* in packets to the LAC */
  u32 n_sessions;
  /* cached adjacency toward peer_ip on the access side, refreshed on
   * FIB change via a fib_entry_track, like the pppoe plugin does */
  u32 adj_index;
  u32 fib_entry_index;
  u32 sibling_index;
} l2tp2_tunnel_t;

typedef struct
{
  u32 tunnel_index;
  u16 local_sid;		/* in packets from the LAC */
  u16 peer_sid;			/* in packets to the LAC */
  u8 acfc;
  u8 pfc;
  u32 sw_if_index;		/* the l2tp2_session interface */
  u32 hw_if_index;
  /* precomputed encap: ip4 + udp + l2tp + ppp header bytes */
  u8 *rewrite;
  u32 encap_fib_index;
} l2tp2_session_t;

/* decap lookup key: peer ip4, peer port, tunnel id, session id */
typedef union
{
  struct
  {
    u32 peer_ip4;
    u16 peer_port;
    u16 local_tid;
    u16 local_sid;
    u16 pad[3];
  };
  u64 as_u64[2];
} l2tp2_session_key_t;

typedef struct
{
  l2tp2_tunnel_t *tunnels;	/* pool */
  l2tp2_session_t *sessions;	/* pool */
  clib_bihash_16_8_t session_by_key;
  u32 *session_index_by_sw_if_index;
  u8 handoff_enabled;
  u32 handoff_frame_queue_index;
  u32 punt_next_index;		/* where non-owned L2TP packets go */
  u16 msg_id_base;
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2tp2_main_t;

extern l2tp2_main_t l2tp2_main;
extern vlib_node_registration_t l2tp2_input_node;
extern vlib_node_registration_t l2tp2_handoff_node;

int l2tp2_tunnel_add_del (l2tp2_main_t * lm, ip46_address_t * local_ip,
			  ip46_address_t * peer_ip, u16 local_port,
			  u16 peer_port, u16 local_tid, u16 peer_tid,
			  u8 is_add, u32 * tunnel_indexp);
int l2tp2_session_add_del (l2tp2_main_t * lm, u32 tunnel_index,
			   u16 local_sid, u16 peer_sid, u8 acfc, u8 pfc,
			   u8 is_add, u32 * sw_if_indexp);

#endif /* __included_l2tp2_h__ */
