// Copyright(c) 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dds/dds.h"
#include "instances_types.h"

static const uint32_t batch = 100;

static void runpub (dds_entity_t tp, bool waitack)
{
  dds_qos_t *qos = dds_create_qos ();
  dds_qset_writer_batching (qos, true);
  const dds_entity_t wr = dds_create_writer (dds_get_parent (tp), tp, qos, NULL);
  dds_delete_qos (qos);

  uint32_t start = 0;
  dds_time_t tprint = 0;
  while (1)
  {
    dds_time_t tnow = dds_time ();
    if (tnow >= tprint) {
      printf ("pub: start = %"PRIu32"\n", start);
      tprint = tnow + DDS_SECS (1);
    }
    for (uint32_t i = 0; i < batch; i++)
    {
      const T x = { start + i, 0 };
      if (dds_write (wr, &x) < 0) abort ();
    }
    for (uint32_t i = 0; i < batch; i++)
    {
      const T x = { start + i, 0 };
      if (dds_dispose (wr, &x) < 0) abort ();
      if (dds_unregister_instance (wr, &x) < 0) abort();
    }

    dds_write_flush (wr);
    if (waitack)
    {
      if (dds_wait_for_acks (wr, DDS_SECS (10)) < 0)
        abort ();
    }
    
    start += batch;
  }
}

static void runsub (dds_entity_t tp)
{
  const dds_entity_t rd = dds_create_reader (dds_get_parent (tp), tp, NULL, NULL);
  
  // let's preallocate or a change
  T xs[10];
  void *xsptrs[sizeof (xs) / sizeof (xs[0])];
  dds_sample_info_t si[sizeof (xs) / sizeof (xs[0])];
  for (size_t i = 0; i < sizeof (xs) / sizeof (xs[0]); i++)
    xsptrs[i] = &xs[i];

  dds_time_t tprint = 0;
  uint32_t highest_seen = 0;
  while (1)
  {
    dds_time_t tnow = dds_time ();
    if (tnow >= tprint) {
      printf ("sub: max = %"PRIu32"\n", highest_seen);
      tprint = tnow + DDS_SECS (1);
    }
    int32_t n = dds_take (rd, xsptrs, si, (int32_t) (sizeof (xs) / sizeof (xs[0])), (int32_t) (sizeof (xs) / sizeof (xs[0])));
    if (n < 0) abort ();
    for (int32_t i = 0; i < n; i++)
    {
      if (xs[i].k > highest_seen)
        highest_seen = xs[i].k;
    }
  }
}

static void usage (const char *argv0)
{
  fprintf (stderr, "usage: %s {pub|pub+ack|sub} {v|tl}\n", argv0);
  exit (1);
}

int main (int argc, char **argv)
{
  // generally no error checking, where there is some it calls abort
  bool ispub = false, waitack = false, istl = false;

  if (argc != 3)
    usage (argv[0]);
  if (strcmp (argv[1], "pub") == 0) {
    ispub = true;
  } else if (strcmp (argv[1], "pub+ack") == 0) {
    ispub = true; waitack = true;
  } else if (strcmp (argv[1], "sub") == 0) {
    ispub = false;
  } else {
    usage (argv[0]);
  }
  if (strcmp (argv[2], "v") == 0) {
    istl = true;
  } else if (strcmp (argv[2], "tl") == 0) {
    istl = false;
  } else {
    usage (argv[0]);
  }
  const dds_entity_t pp = dds_create_participant (0, NULL, NULL);

  dds_qos_t *qos = dds_create_qos ();
  dds_qset_reliability (qos, DDS_RELIABILITY_RELIABLE, 0);
  if (istl)
    dds_qset_durability (qos, DDS_DURABILITY_TRANSIENT_LOCAL);
  const dds_entity_t tp = dds_create_topic (pp, &T_desc, "instances_topic", qos, NULL);
  dds_delete_qos (qos);
  if (ispub)
    runpub (tp, waitack);
  else
    runsub (tp);
  dds_delete (pp);
}
