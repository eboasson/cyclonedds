/*
 * Copyright(c) 2021 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <ctype.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "dds/ddsrt/io.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/string.h"

#include "dds/ddsi/ddsi_channel.h"
#include "dds/ddsi/q_entity.h"
#include "dds/ddsi/q_transmit.h"
#include "dds/ddsi/q_thread.h"
#include "dds/ddsi/q_xmsg.h"
#include "dds/ddsi/q_whc.h"
#include "dds/ddsi/q_xevent.h"
#include "dds/ddsi/q_radmin.h"
#include "dds/ddsi/q_receive.h"

static struct writer *ddsi_writer_from_pending_listnode (struct ddsrt_circlist_elem * const listnode)
{
  uintptr_t addr = (uintptr_t) listnode - offsetof (struct writer, pending_writes.listnode);
  return (struct writer *) addr;
}

void ddsi_channel_enqueue_writer (struct ddsi_channel *ch, struct writer *wr, seqno_t seq)
{
  ddsrt_mutex_lock (&ch->lock); // ouch ... think of a better way as it'll be often be a no-op for high-rate writers
  if (wr->pending_writes.next_seq == MAX_SEQ_NUMBER)
  {
    if (ddsrt_circlist_isempty (&ch->pending_writers))
      ddsrt_cond_signal (&ch->cond);
    ddsrt_circlist_append (&ch->pending_writers, &wr->pending_writes.listnode);
    wr->pending_writes.next_seq = seq;
  }
  ddsrt_mutex_unlock (&ch->lock);
}

void ddsi_channel_dequeue_writer (struct ddsi_channel *ch, struct writer *wr)
{
  // need something for when the writer is being deleted, not sure whether it should be this
  ddsrt_mutex_lock (&ch->lock); // ouch ... think of a better way as it'll be often be a no-op for high-rate writers
  if (wr->pending_writes.next_seq != MAX_SEQ_NUMBER)
  {
    assert (!ddsrt_circlist_isempty (&ch->pending_writers));
    ddsrt_circlist_remove (&ch->pending_writers, &wr->pending_writes.listnode);
    wr->pending_writes.next_seq = MAX_SEQ_NUMBER;
  }
  ddsrt_mutex_unlock (&ch->lock);
}

static uint32_t ddsi_channel_thread (void * const vchannel)
{
  // FIXME: lifetime of writer: if we enqueue a pointer to it in channels,
  struct ddsi_channel * const ch = vchannel;
  struct thread_state1 * const ts1 = lookup_thread_state ();
  struct nn_xpack *xp = nn_xpack_new (ch->gv, 0, false);
  thread_state_awake_fixed_domain (ts1);
  ddsrt_mutex_lock (&ch->lock);
  while (!ch->stop)
  {
    if (ddsrt_circlist_isempty (&ch->pending_writers))
    {
      thread_state_asleep (ts1);
      ddsrt_cond_wait (&ch->cond, &ch->lock);
      thread_state_awake_fixed_domain (ts1);
    }
    else
    {
      thread_state_awake_to_awake_no_nest (ts1);

      struct writer * const wr = ddsi_writer_from_pending_listnode (ddsrt_circlist_oldest (&ch->pending_writers));
      ch->pending_writers.latest = ch->pending_writers.latest->next;

      // too bad we have to lock the writer for transmit_sample_unlocks_wr, but given that we have to lock it anyway
      // might as well make use of the fact that the WHC can't change while the writer is locked
      ddsrt_mutex_lock (&wr->e.lock);

      // FIXME: if we ever do this with the writer unlocked, better make a whc sample iterator starting at next_seq
      // as things stand, there are at most two iterations of the loop
      struct whc_borrowed_sample bsample;
      while (wr->pending_writes.next_seq < MAX_SEQ_NUMBER && !whc_borrow_sample (wr->whc, wr->pending_writes.next_seq, &bsample))
        wr->pending_writes.next_seq = whc_next_seq (wr->whc, wr->pending_writes.next_seq);
      if (wr->pending_writes.next_seq == MAX_SEQ_NUMBER)
      {
        ddsrt_circlist_remove (&ch->pending_writers, &wr->pending_writes.listnode);
        ddsrt_mutex_unlock (&wr->e.lock);
      }
      else
      {
        struct whc_state whcst;
        whc_get_state (wr->whc, &whcst);
        ddsi_transmit_sample_unlocks_wr (xp, wr, &whcst, bsample.seq, bsample.plist, bsample.serdata, NULL);
        whc_return_sample (wr->whc, &bsample, false);
      }
    }
  }
  ddsrt_mutex_unlock (&ch->lock);
  thread_state_asleep (ts1);
  nn_xpack_send (xp, true);
  nn_xpack_free (xp);
  return 0;
}

struct ddsi_channel *ddsi_channel_new (struct ddsi_domaingv *gv, const struct ddsi_config_channel_listelem *def, struct ddsi_tran_conn *transmit_conn)
{
  assert (def != NULL);
  struct ddsi_channel *ch;
  if ((ch = ddsrt_malloc (sizeof (*ch))) == NULL)
    goto fail_malloc;
  ch->gv = gv;
  ch->def = def;
  ch->ts1 = NULL;

  char *tev_name;
  if (ddsrt_asprintf (&tev_name, "tev.%s", def->name) < 0)
    goto fail_tev_name;

#ifdef DDS_HAS_BANDWIDTH_LIMITING
  const bool needs_xevq = (chptr->auxiliary_bandwidth_limit > 0 || lookup_thread_properties (tev_name));
  uint32_t bwlim = chptr->auxiliary_bandwidth_limit;
#else
  const bool needs_xevq = lookup_thread_properties (&gv->config, tev_name);
  uint32_t bwlim = 0;
#endif
  if (!needs_xevq)
    ch->evq = NULL; // FIXME: wouldn't it make more sense to then point it to the global one?
  else
  {
    ch->evq = xeventq_new (gv, gv->config.max_queued_rexmit_bytes, gv->config.max_queued_rexmit_msgs, bwlim);
    if (ch->evq == NULL)
      goto fail_xeventq;
  }

  ch->dqueue = nn_dqueue_new (def->name, gv, gv->config.delivery_queue_maxsamples, user_dqueue_handler, NULL);
  if (ch->dqueue == NULL)
    goto fail_dqueue;

  ch->transmit_conn = transmit_conn;
  ch->stop = false;
  ddsrt_circlist_init (&ch->pending_writers);
  ddsrt_mutex_init (&ch->lock);
  ddsrt_cond_init (&ch->cond);
  ddsrt_free (tev_name);
  return ch;

fail_dqueue:
  if (ch->evq)
    xeventq_free (ch->evq);
fail_xeventq:
  ddsrt_free (tev_name);
fail_tev_name:
  ddsrt_free (ch);
fail_malloc:
  return NULL;
}

dds_return_t ddsi_channel_start (struct ddsi_channel *ch)
{
  dds_return_t rc;
  assert (!ch->stop && ch->ts1 == NULL);
  char *xmit_name;
  if (ddsrt_asprintf (&xmit_name, "xmit.%s", ch->def->name) < 0) {
    rc = DDS_RETCODE_ERROR;
    goto fail_xmit_name;
  }
  if (ch->evq && (rc = xeventq_start (ch->evq, ch->def->name)) != 0) {
    goto fail_xeventq;
  }
  if ((rc = create_thread (&ch->ts1, ch->gv, xmit_name, ddsi_channel_thread, ch)) != 0) {
    goto fail_create_thread;
  }
  ddsrt_free (xmit_name);
  return 0;

fail_create_thread:
  if (ch->evq)
    xeventq_stop (ch->evq);
  ch->ts1 = NULL;
fail_xeventq:
  ddsrt_free (xmit_name);
fail_xmit_name:
  return rc;
}

void ddsi_channel_stop (struct ddsi_channel *ch)
{
  if (!ch->ts1)
    return;

  if (ch->evq)
    xeventq_stop (ch->evq);

  ddsrt_mutex_lock (&ch->lock);
  assert (!ch->stop);
  ch->stop = true;
  ddsrt_cond_signal (&ch->cond);
  ddsrt_mutex_unlock (&ch->lock);
  (void) join_thread (ch->ts1);
  ch->ts1 = NULL;
}

void ddsi_channel_free (struct ddsi_channel *ch)
{
  // set of pending writes is intrusive in writers, so nothing to worry about here
  assert (ch->ts1 == NULL);
  nn_dqueue_free (ch->dqueue);
  if (ch->evq)
    xeventq_free (ch->evq);
  // FIXME: shouldn't even be using data_conn_uc given the existence of xmit_conns
  if (ch->transmit_conn && ch->transmit_conn != ch->gv->data_conn_uc)
    ddsi_conn_free (ch->transmit_conn);
  ddsrt_free (ch);
}
