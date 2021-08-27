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
#ifndef DDSI_CHANNEL_H
#define DDSI_CHANNEL_H

#include <stdbool.h>

#include "dds/ddsrt/circlist.h"
#include "dds/ddsi/ddsi_domaingv.h"

struct writer;
struct thread_state1;

struct ddsi_channel {
  struct ddsi_domaingv *gv;
  struct thread_state1 *ts1;
  char *name;

  ddsrt_mutex_t lock;
  ddsrt_cond_t cond;
  bool stop;
  struct ddsrt_circlist pending_writers;
};

void ddsi_channel_enqueue_writer (struct ddsi_channel *ch, struct writer *wr, seqno_t seq);
void ddsi_channel_dequeue_writer (struct ddsi_channel *ch, struct writer *wr);
struct ddsi_channel *ddsi_channel_new (struct ddsi_domaingv *gv, const char *name);
dds_return_t ddsi_channel_start (struct ddsi_channel *ch);
void ddsi_channel_stop (struct ddsi_channel *ch);
void ddsi_channel_free (struct ddsi_channel *ch);

#endif
