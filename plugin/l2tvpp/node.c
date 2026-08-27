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
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <l2tvpp/l2tvpp.h>

typedef enum
{
  L2TVPP_INPUT_NEXT_IP4_INPUT,
  L2TVPP_INPUT_NEXT_IP6_INPUT,
  L2TVPP_INPUT_NEXT_PUNT,
  L2TVPP_INPUT_NEXT_DROP,
  L2TVPP_INPUT_N_NEXT,
} l2tvpp_input_next_t;

#define foreach_l2tvpp_input_error                       \
  _ (DECAP, "decapsulated")                               \
  _ (DECAP_SEQ, "sequenced, decapsulated")                \
  _ (DECAP_OFF, "offset, decapsulated")                   \
  _ (PUNT_CONTROL, "control message, punted")             \
  _ (PUNT_NO_SESSION, "unknown session, punted")          \
  _ (PUNT_PPP_PROTO, "non-IP PPP protocol, punted")       \
  _ (PUNT_UNSUPPORTED, "not v2, punted")                  \
  _ (TOO_SHORT, "truncated, dropped")

typedef enum
{
#define _(sym, str) L2TVPP_INPUT_ERROR_##sym,
  foreach_l2tvpp_input_error
#undef _
    L2TVPP_INPUT_N_ERROR,
} l2tvpp_input_error_t;

static char *l2tvpp_input_error_strings[] = {
#define _(sym, str) str,
  foreach_l2tvpp_input_error
#undef _
};

typedef struct
{
  u32 session_index;
  u32 sw_if_index;
  u16 tunnel_id;
  u16 session_id;
  u16 ppp_proto;
  u8 next;
} l2tvpp_input_trace_t;

static u8 *
format_l2tvpp_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tvpp_input_trace_t *t = va_arg (*args, l2tvpp_input_trace_t *);
  return format (s, "l2tvpp: tid %d sid %d ppp 0x%04x session %d sw_if_index %d next %d",
		 t->tunnel_id, t->session_id, t->ppp_proto,
		 t->session_index, t->sw_if_index, t->next);
}

/* Hand the packet back as if we had never registered the port: rewind to
 * the IP header and let ip4-punt (and whatever punt redirect the control
 * plane configured, e.g. linux-cp) take it. */
static_always_inline void
l2tvpp_rewind_to_ip (vlib_buffer_t * b)
{
  i32 off = vnet_buffer (b)->l3_hdr_offset - b->current_data;
  vlib_buffer_advance (b, off);
}

VLIB_NODE_FN (l2tvpp_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vnet_interface_main_t *im = &lm->vnet_main->interface_main;
  u32 thread_index = vm->thread_index;
  u32 n_left = frame->n_vectors, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 counts[L2TVPP_INPUT_N_ERROR] = { 0 };

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u8 *cur;
      u16 flags, tid, sid, ppp_proto = 0;

      if (PREDICT_TRUE (n_left > 4))
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  clib_prefetch_load (vlib_buffer_get_current (b[2]));
	}
      u32 session_index = ~0, error = L2TVPP_INPUT_ERROR_DECAP;
      u32 next0;

      /* udp-local leaves current_data at the L2TP header */
      cur = vlib_buffer_get_current (b0);

      if (PREDICT_FALSE (b0->current_length < 6))
	{
	  error = L2TVPP_INPUT_ERROR_TOO_SHORT;
	  next0 = L2TVPP_INPUT_NEXT_DROP;
	  goto trace;
	}

      flags = clib_net_to_host_u16 (*(u16 *) cur);

      if (PREDICT_FALSE ((flags & L2TVPP_HDR_VER) != 2))
	{
	  error = L2TVPP_INPUT_ERROR_PUNT_UNSUPPORTED;
	  goto punt;
	}
      /* T must be tested before S/O: control messages always carry S, so
       * checking S first would mislabel them as "sequenced" */
      if (PREDICT_FALSE (flags & L2TVPP_HDR_T))
	{
	  error = L2TVPP_INPUT_ERROR_PUNT_CONTROL;
	  goto punt;
	}
      cur += 2;
      if (flags & L2TVPP_HDR_L)
	{
	  /* the L bit pushes tid/sid to bytes 6-7 - re-check the length
	   * so they are not read from past the buffer */
	  if (PREDICT_FALSE (b0->current_length < 8))
	    {
	      error = L2TVPP_INPUT_ERROR_TOO_SHORT;
	      next0 = L2TVPP_INPUT_NEXT_DROP;
	      goto trace;
	    }
	  cur += 2;
	}
      tid = clib_net_to_host_u16 (*(u16 *) cur);
      sid = clib_net_to_host_u16 (*(u16 *) (cur + 2));
      cur += 4;
      /* Cisco LACs (ASR1001-X, Viavi bench 2026-08-25/27) send data with
       * sequence numbers and/or the offset bit (typically offset size 0);
       * RFC 2661 lets the receiver ignore sequence numbers and the offset
       * pad carries nothing, so skip both and decap instead of punting -
       * punting sent every upstream packet through the kernel at ~1/4 the
       * rate. Encap stays plain (no S/O), which the same bench proved the
       * LAC accepts. */
      if (PREDICT_FALSE (flags & L2TVPP_HDR_S))
	{
	  cur += 4;
	  error = L2TVPP_INPUT_ERROR_DECAP_SEQ;
	}
      if (PREDICT_FALSE (flags & L2TVPP_HDR_O))
	{
	  cur += 2 + clib_net_to_host_u16 (*(u16 *) cur);
	  error = L2TVPP_INPUT_ERROR_DECAP_OFF;
	}
      /* S/O advances are attacker-controlled (offset size field): make
       * sure the PPP header we are about to read is still inside the
       * buffer */
      if (PREDICT_FALSE (cur + 4 >
			 (u8 *) vlib_buffer_get_current (b0) +
			 b0->current_length))
	{
	  error = L2TVPP_INPUT_ERROR_TOO_SHORT;
	  next0 = L2TVPP_INPUT_NEXT_DROP;
	  goto trace;
	}

      {
	l2tvpp_session_key_t key;
	clib_bihash_kv_16_8_t kv;

	/* with handoff on, every frame came through l2tvpp-handoff, which
	 * already did this lookup and left the result in the buffer; a
	 * pool slot can be reused by a delete between the two nodes, so
	 * the hint only counts if the entry still matches the header key
	 * ((tid, sid) is unique, so a match is authoritative) */
	if (lm->handoff_enabled)
	  {
	    u32 hint = vnet_buffer (b0)->l2t.session_index;
	    if (hint != ~0 && !pool_is_free_index (lm->sessions, hint))
	      {
		l2tvpp_session_t *s = pool_elt_at_index (lm->sessions, hint);
		if (s->local_tid == tid && s->local_sid == sid)
		  session_index = hint;
	      }
	  }
	if (session_index == ~0)
	  {
	    l2tvpp_make_key (&key, tid, sid);
	    kv.key[0] = key.as_u64[0];
	    kv.key[1] = key.as_u64[1];
	    if (PREDICT_FALSE (clib_bihash_search_inline_16_8
			       (&lm->session_by_key, &kv)))
	      {
		error = L2TVPP_INPUT_ERROR_PUNT_NO_SESSION;
		goto punt;
	      }
	    session_index = kv.value;
	  }
      }

      /* PPP: optional FF 03, then 1- or 2-byte protocol (PFC if the
       * first byte is odd) */
      if (cur[0] == 0xff && cur[1] == 0x03)
	cur += 2;
      if (cur[0] & 1)
	{
	  ppp_proto = cur[0];
	  cur += 1;
	}
      else
	{
	  ppp_proto = clib_net_to_host_u16 (*(u16 *) cur);
	  cur += 2;
	}

      if (ppp_proto == PPP_PROTO_IP4)
	next0 = L2TVPP_INPUT_NEXT_IP4_INPUT;
      else if (ppp_proto == PPP_PROTO_IP6)
	next0 = L2TVPP_INPUT_NEXT_IP6_INPUT;
      else
	{
	  error = L2TVPP_INPUT_ERROR_PUNT_PPP_PROTO;
	  goto punt;
	}

      {
	l2tvpp_session_t *sess =
	  pool_elt_at_index (lm->sessions, session_index);
	u32 adv = cur - (u8 *) vlib_buffer_get_current (b0);

	vlib_buffer_advance (b0, adv);
	vnet_buffer (b0)->sw_if_index[VLIB_RX] = sess->sw_if_index;
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;	/* default FIB */
	vlib_increment_combined_counter (im->combined_sw_if_counters +
					 VNET_INTERFACE_COUNTER_RX,
					 thread_index, sess->sw_if_index, 1,
					 vlib_buffer_length_in_chain (vm, b0));
      }
      goto trace;

    punt:
      l2tvpp_rewind_to_ip (b0);
      next0 = L2TVPP_INPUT_NEXT_PUNT;

    trace:
      /* only dropped packets reach error-drop, which counts b->error;
       * punted and decapsulated packets keep forwarding, so their
       * counters must be incremented here */
      if (next0 == L2TVPP_INPUT_NEXT_DROP)
	b0->error = node->errors[error];
      else
	counts[error]++;
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2tvpp_input_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->session_index = session_index;
	  tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  tr->tunnel_id = tid;
	  tr->session_id = sid;
	  tr->ppp_proto = ppp_proto;
	  tr->next = next0;
	}
      next[0] = next0;
      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  for (u32 i = 0; i < L2TVPP_INPUT_N_ERROR; i++)
    if (counts[i])
      vlib_node_increment_counter (vm, node->node_index, i, counts[i]);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (l2tvpp_input_node) = {
  .name = "l2tvpp-input",
  .vector_size = sizeof (u32),
  .format_trace = format_l2tvpp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = L2TVPP_INPUT_N_ERROR,
  .error_strings = l2tvpp_input_error_strings,
  .n_next_nodes = L2TVPP_INPUT_N_NEXT,
  .next_nodes = {
    [L2TVPP_INPUT_NEXT_IP4_INPUT] = "ip4-input",
    [L2TVPP_INPUT_NEXT_IP6_INPUT] = "ip6-input",
    [L2TVPP_INPUT_NEXT_PUNT] = "ip4-punt",
    [L2TVPP_INPUT_NEXT_DROP] = "error-drop",
  },
};
