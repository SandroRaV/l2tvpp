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
 * Handoff defaults to on when VPP runs with two or more workers (decided at
 * main-loop enter, see l2tvpp.c) and stays off below that, where there is
 * nothing to spread over; `l2tvpp handoff on|off` overrides either way.
 * When handoff is enabled, udp/1701 is delivered to this node instead of
 * l2tvpp-input; it parses just far enough to read tid/sid, picks a worker
 * by a hash of (tid, sid) (l2tvpp_handoff_worker) and enqueues the buffer
 * to l2tvpp-input on that worker. No session lookup happens here: this node
 * runs on the one RX worker every session of a LAC lands on, so it must stay
 * cheap, and the bihash probe moves to l2tvpp-input on the target worker,
 * where it runs in parallel. l2tvpp-input's processing is unchanged and
 * runs wherever the buffer lands, so the encapsulated decap/forward cost is
 * spread over cores even for a single LAC. Unknown sessions are handed off
 * too and punted by l2tvpp-input on the target worker.
 *
 * Packets that are not v2 data (control, truncated, v3) are kept on the
 * current thread; l2tvpp-input punts/drops them there, exactly as without
 * handoff. Data with the S or O bit (the ASR quirks) is handed off like
 * plain data: tid/sid sit before the Ns/Nr and offset fields, and ordering
 * is safe session-by-session because one session always maps to one worker.
 *
 * The frame queue to l2tvpp-input drops when full (counted here as
 * "congestion drop"); its depth is `l2tvpp { handoff-queue-nelts N }`.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <l2tvpp/l2tvpp.h>

typedef struct
{
  u16 tunnel_id;
  u16 session_id;
  u16 thread_index;
} l2tvpp_handoff_trace_t;

static u8 *
format_l2tvpp_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2tvpp_handoff_trace_t *t = va_arg (*args, l2tvpp_handoff_trace_t *);
  return format (s, "l2tvpp-handoff: tid %d sid %d -> thread %d",
		 t->tunnel_id, t->session_id, t->thread_index);
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
      u16 flags, tid = 0, sid = 0;
      u32 off;

      if (PREDICT_TRUE (i + 4 < n))
	{
	  vlib_prefetch_buffer_header (b[i + 4], LOAD);
	  clib_prefetch_load (vlib_buffer_get_current (b[i + 2]));
	}

      /* worker threads are 1 .. n_workers; keep non-data packets local */
      if (PREDICT_TRUE (n_workers > 0
			&& l2tvpp_parse_hdr (vlib_buffer_get_current (b[i]),
					     b[i]->current_length, &flags,
					     &tid, &sid, &off)
			== L2TVPP_HDR_DATA))
	ti[i] = l2tvpp_handoff_worker (tid, sid, n_workers);
      else
	ti[i] = this_thread;

      if (PREDICT_FALSE (b[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2tvpp_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[i], sizeof (*t));
	  t->tunnel_id = tid;
	  t->session_id = sid;
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
