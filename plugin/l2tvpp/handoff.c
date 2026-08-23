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
 * l2tvpp-handoff: spread decap across worker threads by L2TP session.
 *
 * All tunnels from one LAC share a single outer UDP 4-tuple, so NIC RSS puts
 * every session behind that LAC on one RX queue / worker (see design.md 3d).
 * When handoff is enabled, udp/1701 is delivered to this node instead of
 * l2tvpp-input; it parses just far enough to get the session index, picks a
 * worker by session_index % n_workers, and enqueues the buffer to
 * l2tvpp-input on that worker. l2tvpp-input's processing is unchanged and
 * runs wherever the buffer lands, so the encapsulated decap/forward cost is
 * spread over cores even for a single LAC.
 *
 * Packets we cannot resolve to a session (control, unknown session,
 * truncated, v3) are kept on the current thread; l2tvpp-input punts/drops
 * them there, exactly as without handoff.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <l2tvpp/l2tvpp.h>

typedef struct
{
  u32 session_index;
  u16 thread_index;
} l2tvpp_handoff_trace_t;

static u8 *
format_l2tvpp_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tvpp_handoff_trace_t *t = va_arg (*args, l2tvpp_handoff_trace_t *);
  return format (s, "l2tvpp-handoff: session %d -> thread %d",
		 t->session_index, t->thread_index);
}

#define foreach_l2tvpp_handoff_error _ (CONGESTION, "congestion drop")

typedef enum
{
#define _(sym, str) L2TVPP_HANDOFF_ERROR_##sym,
  foreach_l2tvpp_handoff_error
#undef _
    L2TVPP_HANDOFF_N_ERROR,
} l2tvpp_handoff_error_t;

static char *l2tvpp_handoff_error_strings[] = {
#define _(sym, str) str,
  foreach_l2tvpp_handoff_error
#undef _
};

/* Parse just the L2TPv2 header far enough to read tid/sid and look the
 * session up. Returns ~0 for anything that is not a data packet we own. */
static_always_inline u32
l2tvpp_peek_session (l2tvpp_main_t * lm, vlib_buffer_t * b)
{
  u8 *cur = vlib_buffer_get_current (b);
  u16 flags, tid, sid;
  l2tvpp_session_key_t key;
  clib_bihash_kv_16_8_t kv;

  if (PREDICT_FALSE (b->current_length < 6))
    return ~0;
  flags = clib_net_to_host_u16 (*(u16 *) cur);
  if ((flags & L2TVPP_HDR_VER) != 2)
    return ~0;
  if (flags & (L2TVPP_HDR_T | L2TVPP_HDR_S | L2TVPP_HDR_O))
    return ~0;			/* control / sequenced / offset: keep local */
  cur += 2;
  if (flags & L2TVPP_HDR_L)
    cur += 2;
  tid = clib_net_to_host_u16 (*(u16 *) cur);
  sid = clib_net_to_host_u16 (*(u16 *) (cur + 2));

  l2tvpp_make_key (&key, tid, sid);
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  if (clib_bihash_search_inline_16_8 (&lm->session_by_key, &kv))
    return ~0;
  return kv.value;
}

VLIB_NODE_FN (l2tvpp_handoff_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  l2tvpp_main_t *lm = &l2tvpp_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti = thread_indices;
  u32 n = frame->n_vectors, *from = vlib_frame_vector_args (frame);
  u32 n_workers = vlib_num_workers ();
  u32 this_thread = vm->thread_index;
  u32 n_enq, i;

  vlib_get_buffers (vm, from, bufs, n);

  for (i = 0; i < n; i++)
    {
      u32 si = l2tvpp_peek_session (lm, b[i]);
      /* worker threads are 1 .. n_workers; keep unresolved packets local */
      ti[i] = (si == ~0 || n_workers == 0) ? this_thread
	: (u16) (1 + (si % n_workers));

      if (PREDICT_FALSE (b[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2tvpp_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[i], sizeof (*t));
	  t->session_index = si;
	  t->thread_index = ti[i];
	}
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, lm->handoff_frame_queue_index,
					 from, thread_indices, n, 1);
  if (PREDICT_FALSE (n_enq < n))
    vlib_node_increment_counter (vm, node->node_index,
				 L2TVPP_HANDOFF_ERROR_CONGESTION, n - n_enq);
  return n;
}

VLIB_REGISTER_NODE (l2tvpp_handoff_node) = {
  .name = "l2tvpp-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_l2tvpp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = L2TVPP_HANDOFF_N_ERROR,
  .error_strings = l2tvpp_handoff_error_strings,
  .n_next_nodes = 0,		/* buffers leave via the handoff frame queue */
};
