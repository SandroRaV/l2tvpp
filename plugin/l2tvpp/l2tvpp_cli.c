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
#include <l2tvpp/l2tvpp.h>

static clib_error_t *
l2tvpp_tunnel_cli (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  unformat_input_t _line, *line = &_line;
  ip46_address_t local_ip = { 0 }, peer_ip = { 0 };
  u32 local_port = L2TVPP_UDP_PORT, peer_port = L2TVPP_UDP_PORT;
  u32 local_tid = ~0, peer_tid = ~0, tunnel_index = ~0;
  u8 is_add = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line))
    return 0;

  while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line, "del"))
	is_add = 0;
      else if (unformat (line, "local %U", unformat_ip4_address, &local_ip.ip4))
	;
      else if (unformat (line, "peer %U", unformat_ip4_address, &peer_ip.ip4))
	;
      else if (unformat (line, "local-port %d", &local_port))
	;
      else if (unformat (line, "peer-port %d", &peer_port))
	;
      else if (unformat (line, "local-tid %d", &local_tid))
	;
      else if (unformat (line, "peer-tid %d", &peer_tid))
	;
      else
	{
	  unformat_free (line);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line);
	}
    }
  unformat_free (line);

  if (local_tid == ~0 || (is_add && peer_tid == ~0))
    return clib_error_return (0, "local-tid and peer-tid required");

  rv = l2tvpp_tunnel_add_del (lm, &local_ip, &peer_ip, local_port,
			      peer_port, local_tid, peer_tid, is_add,
			      &tunnel_index);
  if (rv)
    return clib_error_return (0, "l2tvpp_tunnel_add_del returned %d", rv);
  if (is_add)
    vlib_cli_output (vm, "tunnel %d", tunnel_index);
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_tunnel_command, static) = {
  .path = "l2tvpp tunnel",
  .short_help = "l2tvpp tunnel [del] local <ip4> peer <ip4> [local-port <n>] "
		"[peer-port <n>] local-tid <n> peer-tid <n>",
  .function = l2tvpp_tunnel_cli,
};

static clib_error_t *
l2tvpp_session_cli (vlib_main_t * vm, unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  unformat_input_t _line, *line = &_line;
  u32 tunnel_index = ~0, local_sid = ~0, peer_sid = ~0, sw_if_index = ~0;
  u8 is_add = 1, acfc = 0, pfc = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line))
    return 0;

  while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line, "del"))
	is_add = 0;
      else if (unformat (line, "tunnel %d", &tunnel_index))
	;
      else if (unformat (line, "local-sid %d", &local_sid))
	;
      else if (unformat (line, "peer-sid %d", &peer_sid))
	;
      else if (unformat (line, "acfc"))
	acfc = 1;
      else if (unformat (line, "pfc"))
	pfc = 1;
      else
	{
	  unformat_free (line);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line);
	}
    }
  unformat_free (line);

  if (tunnel_index == ~0 || local_sid == ~0 || (is_add && peer_sid == ~0))
    return clib_error_return (0, "tunnel, local-sid and peer-sid required");

  rv = l2tvpp_session_add_del (lm, tunnel_index, local_sid, peer_sid, acfc,
			       pfc, is_add, &sw_if_index);
  if (rv)
    return clib_error_return (0, "l2tvpp_session_add_del returned %d", rv);
  if (is_add)
    vlib_cli_output (vm, "%U", format_vnet_sw_if_index_name, lm->vnet_main,
		     sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_session_command, static) = {
  .path = "l2tvpp session",
  .short_help = "l2tvpp session [del] tunnel <idx> local-sid <n> peer-sid <n> "
		"[acfc] [pfc]",
  .function = l2tvpp_session_cli,
};

static clib_error_t *
l2tvpp_route_cli (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  unformat_input_t _line, *line = &_line;
  fib_prefix_t pfx = { 0 };
  u32 sw_if_index = ~0, plen = ~0;
  u8 is_add = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line))
    return 0;

  while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line, "del"))
	is_add = 0;
      else if (unformat (line, "%U/%d", unformat_ip4_address,
			 &pfx.fp_addr.ip4, &plen))
	pfx.fp_proto = FIB_PROTOCOL_IP4;
      else if (unformat (line, "%U/%d", unformat_ip6_address,
			 &pfx.fp_addr.ip6, &plen))
	pfx.fp_proto = FIB_PROTOCOL_IP6;
      else if (unformat (line, "%U", unformat_vnet_sw_interface,
			 lm->vnet_main, &sw_if_index))
	;
      else
	{
	  unformat_free (line);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line);
	}
    }
  unformat_free (line);

  if (plen == ~0 || sw_if_index == ~0)
    return clib_error_return (0, "prefix and session interface required");
  pfx.fp_len = plen;

  rv = l2tvpp_route_add_del (lm, &pfx, sw_if_index, is_add);
  if (rv)
    return clib_error_return (0, "l2tvpp_route_add_del returned %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_route_command, static) = {
  .path = "l2tvpp route",
  .short_help = "l2tvpp route [del] <prefix> <session-interface>",
  .function = l2tvpp_route_cli,
};

static clib_error_t *
show_l2tvpp_tunnel_cli (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  l2tvpp_tunnel_t *t;

  if (pool_elts (lm->tunnels) == 0)
    vlib_cli_output (vm, "no l2tvpp tunnels");
  pool_foreach (t, lm->tunnels)
    vlib_cli_output (vm, "%U", format_l2tvpp_tunnel, t);
  return 0;
}

VLIB_CLI_COMMAND (show_l2tvpp_tunnel_command, static) = {
  .path = "show l2tvpp tunnel",
  .short_help = "show l2tvpp tunnel",
  .function = show_l2tvpp_tunnel_cli,
};

static clib_error_t *
show_l2tvpp_session_cli (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  l2tvpp_session_t *s;

  if (pool_elts (lm->sessions) == 0)
    vlib_cli_output (vm, "no l2tvpp sessions");
  pool_foreach (s, lm->sessions)
    vlib_cli_output (vm, "%U", format_l2tvpp_session, s);
  return 0;
}

VLIB_CLI_COMMAND (show_l2tvpp_session_command, static) = {
  .path = "show l2tvpp session",
  .short_help = "show l2tvpp session",
  .function = show_l2tvpp_session_cli,
};

static clib_error_t *
l2tvpp_handoff_cli (vlib_main_t * vm, unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  unformat_input_t _line, *line = &_line;
  u8 enable = 1;

  if (unformat_user (input, unformat_line_input, line))
    {
      while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line, "on") || unformat (line, "enable"))
	    enable = 1;
	  else if (unformat (line, "off") || unformat (line, "disable"))
	    enable = 0;
	  else
	    {
	      unformat_free (line);
	      return clib_error_return (0, "unknown input");
	    }
	}
      unformat_free (line);
    }
  l2tvpp_set_handoff (lm, enable);
  vlib_cli_output (vm, "l2tvpp worker handoff %s (%d workers)",
		   lm->handoff_enabled ? "on" : "off", vlib_num_workers ());
  return 0;
}

VLIB_CLI_COMMAND (l2tvpp_handoff_command, static) = {
  .path = "l2tvpp handoff",
  .short_help = "l2tvpp handoff [on|off]",
  .function = l2tvpp_handoff_cli,
};
