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
#ifndef __included_l2tvpp_h__
#define __included_l2tvpp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_node.h>
#include <vppinfra/bihash_16_8.h>

#define L2TVPP_UDP_PORT 1701

/* RFC 2661 header flag bits */
#define L2TVPP_HDR_T   0x8000
#define L2TVPP_HDR_L   0x4000
#define L2TVPP_HDR_S   0x0800
#define L2TVPP_HDR_O   0x0200
#define L2TVPP_HDR_P   0x0100
#define L2TVPP_HDR_VER 0x000F

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
  u32 encap_fib_index;		/* FIB used to reach peer_ip (M1: table 0) */
} l2tvpp_tunnel_t;

typedef struct
{
  u32 tunnel_index;
  u16 local_sid;		/* in packets from the LAC */
  u16 peer_sid;			/* in packets to the LAC */
  u8 acfc;
  u8 pfc;
  u32 sw_if_index;		/* the l2tvpp session interface */
  u32 hw_if_index;
} l2tvpp_session_t;

/* L2TPv2 data header as we emit it: no L, no S, no O */
typedef CLIB_PACKED (struct {
  u16 flags_ver;
  u16 tunnel_id;
  u16 session_id;
}) l2tvpp_hdr_t;

/* PPP framing with address/control: FF 03 + 2-byte protocol */
typedef CLIB_PACKED (struct {
  u8 address;
  u8 control;
  u16 protocol;
}) l2tvpp_ppp_hdr_t;

/* decap lookup key: the LNS-assigned (local) tunnel id + session id, which
 * RFC 2661 already makes unique on this LNS, so the outer IP/port is not
 * needed (and reading it post udp-local is fragile). */
typedef union
{
  struct
  {
    u16 local_tid;
    u16 local_sid;
    u16 pad[6];
  };
  u64 as_u64[2];
} l2tvpp_session_key_t;

typedef struct
{
  l2tvpp_tunnel_t *tunnels;	/* pool */
  l2tvpp_session_t *sessions;	/* pool */
  clib_bihash_16_8_t session_by_key;
  u32 *session_index_by_sw_if_index;
  u8 handoff_enabled;
  u32 handoff_frame_queue_index;
  u16 msg_id_base;
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2tvpp_main_t;

extern l2tvpp_main_t l2tvpp_main;
extern vlib_node_registration_t l2tvpp_input_node;
extern vnet_hw_interface_class_t l2tvpp_hw_class;
extern vnet_device_class_t l2tvpp_device_class;

u8 *format_l2tvpp_tunnel (u8 * s, va_list * args);
u8 *format_l2tvpp_session (u8 * s, va_list * args);

static_always_inline void
l2tvpp_make_key (l2tvpp_session_key_t * k, u16 local_tid, u16 local_sid)
{
  k->as_u64[0] = 0;
  k->as_u64[1] = 0;
  k->local_tid = local_tid;
  k->local_sid = local_sid;
}

int l2tvpp_tunnel_add_del (l2tvpp_main_t * lm, ip46_address_t * local_ip,
			  ip46_address_t * peer_ip, u16 local_port,
			  u16 peer_port, u16 local_tid, u16 peer_tid,
			  u8 is_add, u32 * tunnel_indexp);
int l2tvpp_session_add_del (l2tvpp_main_t * lm, u32 tunnel_index,
			   u16 local_sid, u16 peer_sid, u8 acfc, u8 pfc,
			   u8 is_add, u32 * sw_if_indexp);

#endif /* __included_l2tvpp_h__ */
