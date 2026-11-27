// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <unistd.h>
#include "CUnit/Test.h"
#include "dds/ddsrt/threads.h"
#include "dds/ddsrt/time.h"
#include "ddsi__sockwaitset.h"
#include "ddsi__tran.h"

struct pipe_conn {
  struct ddsi_tran_conn conn;
  int fds[2];
};

static ddsrt_socket_t pipe_handle (struct ddsi_tran_base *base)
{
  return ((struct pipe_conn *) base)->fds[0];
}

CU_Test (ddsi_sockwaitset, registration_during_enumeration, .timeout = 10)
{
  struct pipe_conn pipes[16] = { 0 };
  struct ddsi_sock_waitset *ws = ddsi_sock_waitset_new ();
  CU_ASSERT_NEQ_FATAL (ws, NULL);
  for (size_t i = 0; i < 16; i++)
  {
    pipes[i].conn.m_base.m_handle_fn = pipe_handle;
    ddsrt_atomic_st32 (&pipes[i].conn.m_count, 1);
    CU_ASSERT_EQ_FATAL (pipe (pipes[i].fds), 0);
  }

  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pipes[0].conn), 1);
  CU_ASSERT_EQ_FATAL (write (pipes[0].fds[1], "x", 1), 1);
  struct ddsi_sock_waitset_ctx *ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  /* Grow the registration table while a readable event is pending. */
  for (size_t i = 1; i < 16; i++)
    CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pipes[i].conn), 1);
  struct ddsi_tran_conn *conn;
  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_next_event (ctx, &conn), 0);
  CU_ASSERT_EQ (conn, &pipes[0].conn);
  ddsi_conn_unref (conn);
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);

  /* Re-register the same readable descriptor. Its old registration's event
     belongs to the previous batch and must be discarded. */
  ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  ddsi_sock_waitset_remove (ws, &pipes[0].conn);
  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pipes[0].conn), 1);
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);

  ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  CU_ASSERT_GEQ_FATAL (ddsi_sock_waitset_next_event (ctx, &conn), 0);
  CU_ASSERT_EQ (conn, &pipes[0].conn);
  ddsi_conn_unref (conn);
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);

  ddsi_sock_waitset_free (ws);
  for (size_t i = 0; i < 16; i++)
  {
    CU_ASSERT_EQ (close (pipes[i].fds[0]), 0);
    CU_ASSERT_EQ (close (pipes[i].fds[1]), 0);
  }
}

static uint32_t write_delayed_marker (void *arg)
{
  const struct pipe_conn *pc = arg;
  dds_sleepfor (DDS_MSECS (50));
  return write (pc->fds[1], "x", 1) == 1 ? 0 : 1;
}

CU_Test (ddsi_sockwaitset, coalesced_triggers, .timeout = 10)
{
  struct pipe_conn pc = { 0 };
  struct ddsi_sock_waitset *ws = ddsi_sock_waitset_new ();
  CU_ASSERT_NEQ_FATAL (ws, NULL);
  pc.conn.m_base.m_handle_fn = pipe_handle;
  ddsrt_atomic_st32 (&pc.conn.m_count, 1);
  CU_ASSERT_EQ_FATAL (pipe (pc.fds), 0);
  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pc.conn), 1);

  /* Only one wake should be pending, however many callers trigger. */
  ddsi_sock_waitset_trigger (ws);
  ddsi_sock_waitset_trigger (ws);
  struct ddsi_sock_waitset_ctx *ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  struct ddsi_tran_conn *conn;
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);

  /* The next wait should return for the marker, not a leftover wake. */
  ddsrt_thread_t writer;
  ddsrt_threadattr_t attr;
  ddsrt_threadattr_init (&attr);
  CU_ASSERT_EQ_FATAL (ddsrt_thread_create (&writer, "waitset-marker", &attr, write_delayed_marker, &pc), 0);
  ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  const int idx = ddsi_sock_waitset_next_event (ctx, &conn);
  CU_ASSERT_EQ (idx, 0);
  if (idx >= 0)
  {
    CU_ASSERT_EQ (conn, &pc.conn);
    ddsi_conn_unref (conn);
  }
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);
  uint32_t ret;
  CU_ASSERT_EQ_FATAL (ddsrt_thread_join (writer, &ret), 0);
  CU_ASSERT_EQ_FATAL (ret, 0);
  char byte;
  CU_ASSERT_EQ_FATAL (read (pc.fds[0], &byte, 1), 1);

  ddsi_sock_waitset_trigger (ws);
  ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);
  ddsi_sock_waitset_free (ws);
  CU_ASSERT_EQ (close (pc.fds[0]), 0);
  CU_ASSERT_EQ (close (pc.fds[1]), 0);
}

CU_Test (ddsi_sockwaitset, removed_connection_alive_during_dispatch, .timeout = 5)
{
  struct pipe_conn pc = { 0 };
  pc.conn.m_base.m_handle_fn = pipe_handle;
  ddsrt_atomic_st32 (&pc.conn.m_count, 1);
  struct ddsi_sock_waitset *ws = ddsi_sock_waitset_new ();
  CU_ASSERT_NEQ_FATAL (ws, NULL);
  CU_ASSERT_EQ_FATAL (pipe (pc.fds), 0);
  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pc.conn), 1);
  CU_ASSERT_EQ_FATAL (write (pc.fds[1], "x", 1), 1);
  struct ddsi_sock_waitset_ctx *ctx = ddsi_sock_waitset_wait (ws);
  struct ddsi_tran_conn *conn;
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_next_event (ctx, &conn), 0);
  CU_ASSERT_EQ_FATAL (conn, &pc.conn);
  ddsi_sock_waitset_remove (ws, conn);
  /* The participant owner may now release the connection. Dispatch still
     owns one reference until it finishes reading the pending frame. */
  CU_ASSERT_EQ_FATAL (ddsrt_atomic_ld32 (&pc.conn.m_count), 2);
  ddsi_conn_unref (conn);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&pc.conn.m_count), 1);
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);
  ddsi_sock_waitset_free (ws);
  CU_ASSERT_EQ (close (pc.fds[0]), 0);
  CU_ASSERT_EQ (close (pc.fds[1]), 0);
}

CU_Test (ddsi_sockwaitset, idle_deadline, .timeout = 5)
{
  struct ddsi_sock_waitset *ws = ddsi_sock_waitset_new ();
  CU_ASSERT_NEQ_FATAL (ws, NULL);
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), DDS_MSECS (10));
  struct ddsi_sock_waitset_ctx *ctx = ddsi_sock_waitset_wait_until (ws, deadline);
  struct ddsi_tran_conn *conn;
  if (ctx)
    CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);
  CU_ASSERT_GEQ (ddsrt_time_monotonic ().v, deadline.v);
  ddsi_sock_waitset_free (ws);
}

CU_Test (ddsi_sockwaitset, pause_readable_connection, .timeout = 5)
{
  struct pipe_conn pc = { 0 };
  pc.conn.m_base.m_handle_fn = pipe_handle;
  ddsrt_atomic_st32 (&pc.conn.m_count, 1);
  struct ddsi_sock_waitset *ws = ddsi_sock_waitset_new ();
  CU_ASSERT_NEQ_FATAL (ws, NULL);
  CU_ASSERT_EQ_FATAL (pipe (pc.fds), 0);
  CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pc.conn), 1);
  CU_ASSERT_EQ_FATAL (write (pc.fds[1], "x", 1), 1);
  CU_ASSERT_FATAL (ddsi_sock_waitset_set_read_enabled (ws, &pc.conn, false));
  const ddsrt_mtime_t deadline = ddsrt_mtime_add_duration (ddsrt_time_monotonic (), DDS_MSECS (20));
  struct ddsi_sock_waitset_ctx *ctx = ddsi_sock_waitset_wait_until (ws, deadline);
  struct ddsi_tran_conn *conn;
  if (ctx)
    CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);
  CU_ASSERT_GEQ (ddsrt_time_monotonic ().v, deadline.v);
  CU_ASSERT_FATAL (ddsi_sock_waitset_set_read_enabled (ws, &pc.conn, true));
  ctx = ddsi_sock_waitset_wait (ws);
  CU_ASSERT_NEQ_FATAL (ctx, NULL);
  CU_ASSERT_GEQ_FATAL (ddsi_sock_waitset_next_event (ctx, &conn), 0);
  CU_ASSERT_EQ (conn, &pc.conn);
  ddsi_conn_unref (conn);
  CU_ASSERT_EQ (ddsi_sock_waitset_next_event (ctx, &conn), -1);
  CU_ASSERT_FATAL (ddsi_sock_waitset_set_read_enabled (ws, &pc.conn, false));
  ddsi_sock_waitset_remove (ws, &pc.conn);
  CU_ASSERT_EQ (ddsrt_atomic_ld32 (&pc.conn.m_count), 1);
  ddsi_sock_waitset_free (ws);
  CU_ASSERT_EQ (close (pc.fds[0]), 0);
  CU_ASSERT_EQ (close (pc.fds[1]), 0);
}

CU_Test (ddsi_sockwaitset, ready_across_batches, .timeout = 10)
{
  enum { NCONNS = 80 }; /* requires more than one kqueue/epoll event batch */
  struct pipe_conn pipes[NCONNS] = { 0 };
  bool seen[NCONNS] = { false };
  struct ddsi_sock_waitset *ws = ddsi_sock_waitset_new ();
  CU_ASSERT_NEQ_FATAL (ws, NULL);
  for (size_t i = 0; i < NCONNS; i++)
  {
    pipes[i].conn.m_base.m_handle_fn = pipe_handle;
    ddsrt_atomic_st32 (&pipes[i].conn.m_count, 1);
    CU_ASSERT_EQ_FATAL (pipe (pipes[i].fds), 0);
    CU_ASSERT_EQ_FATAL (ddsi_sock_waitset_add (ws, &pipes[i].conn), 1);
    CU_ASSERT_EQ_FATAL (write (pipes[i].fds[1], "x", 1), 1);
  }
  size_t nseen = 0;
  while (nseen != NCONNS)
  {
    struct ddsi_sock_waitset_ctx *ctx = ddsi_sock_waitset_wait (ws);
    if (ctx == NULL)
      continue;
    struct ddsi_tran_conn *conn;
    while (ddsi_sock_waitset_next_event (ctx, &conn) >= 0)
    {
      struct pipe_conn *pc = (struct pipe_conn *) conn;
      const ptrdiff_t idx = pc - pipes;
      CU_ASSERT_GEQ_FATAL (idx, 0);
      CU_ASSERT_LT_FATAL (idx, NCONNS);
      CU_ASSERT_FATAL (!seen[idx]);
      seen[idx] = true;
      nseen++;
      char byte;
      CU_ASSERT_EQ_FATAL (read (pc->fds[0], &byte, 1), 1);
      ddsi_sock_waitset_remove (ws, conn);
      ddsi_conn_unref (conn);
    }
  }
  ddsi_sock_waitset_free (ws);
  for (size_t i = 0; i < NCONNS; i++)
  {
    CU_ASSERT_EQ (ddsrt_atomic_ld32 (&pipes[i].conn.m_count), 1);
    CU_ASSERT_EQ (close (pipes[i].fds[0]), 0);
    CU_ASSERT_EQ (close (pipes[i].fds[1]), 0);
  }
}
