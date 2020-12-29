/*
 * Copyright(c) 2020 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <stdio.h>

#include "dds/ddsrt/misc.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/threads.h"
#include "dds/ddsrt/environ.h"

#include "dds/dds.h"
#include "test_common.h"

struct writethread_arg {
  dds_entity_t wr;
  ddsrt_atomic_uint32_t stop;
};

static uint32_t writethread (void *varg)
{
  struct writethread_arg * const arg = varg;
  Space_Type1 data = { 0, 0, 0 };
  dds_return_t ret = 0;
  while (!ddsrt_atomic_ld32 (&arg->stop) && ret == 0)
  {
    data.long_1++;
    ret = dds_write (arg->wr, &data);
  }
  ddsrt_atomic_or32 (&arg->stop, (ret != 0) ? 2 : 0);
  return 0;
}

struct listener_arg {
  ddsrt_atomic_uint32_t taken;
  ddsrt_atomic_uint32_t badparam;
  ddsrt_atomic_uint32_t error;
};

static void data_avail (dds_entity_t rd, void *varg)
{
  struct listener_arg * const arg = varg;
  dds_return_t rc;
  Space_Type1 sample;
  void *sampleptr = &sample;
  dds_sample_info_t si;
  rc = dds_take (rd, &sampleptr, &si, 1, 1);
  if (rc < 0)
  {
    // there's a race condition during reader creation and destruction
    // where the handle is inaccessible but the listener can trigger,
    // so treat "bad parameter" as an okay-ish case
    if (rc == DDS_RETCODE_BAD_PARAMETER)
      ddsrt_atomic_inc32 (&arg->badparam);
    else
    {
      printf ("data_avail: take failed rc %d\n", (int) rc);
      ddsrt_atomic_inc32 (&arg->error);
    }
  }
  ddsrt_atomic_add32 (&arg->taken, (rc > 0 ? (uint32_t) rc : 0));
}

CU_Test(ddsc_data_avail_stress, delete_reader)
{
  dds_return_t rc;

  const char *config = "${CYCLONEDDS_URI}${CYCLONEDDS_URI:+,}<Discovery><ExternalDomainId>0</ExternalDomainId></Discovery>";
  char *conf_pub = ddsrt_expand_envvars (config, 0);
  char *conf_sub = ddsrt_expand_envvars (config, 1);
  const dds_entity_t pub_dom = dds_create_domain (0, conf_pub);
  CU_ASSERT_FATAL (pub_dom > 0);
  const dds_entity_t sub_dom = dds_create_domain (1, conf_sub);
  CU_ASSERT_FATAL (sub_dom > 0);
  ddsrt_free (conf_pub);
  ddsrt_free (conf_sub);

  const dds_entity_t pub_pp = dds_create_participant (0, NULL, NULL);
  CU_ASSERT_FATAL (pub_pp > 0);
  const dds_entity_t sub_pp = dds_create_participant (1, NULL, NULL);
  CU_ASSERT_FATAL (sub_pp > 0);

  char tpname[100];
  create_unique_topic_name ("ddsc_data_avail_stress_delete_reader", tpname, sizeof (tpname));

  dds_qos_t * const qos = dds_create_qos ();
  CU_ASSERT_FATAL (qos != NULL);
  dds_qset_reliability (qos, DDS_RELIABILITY_RELIABLE, DDS_SECS (1));
  dds_qset_writer_data_lifecycle (qos, false);
  const dds_entity_t pub_tp = dds_create_topic (pub_pp, &Space_Type1_desc, tpname, qos, NULL);
  CU_ASSERT_FATAL (pub_tp > 0);
  const dds_entity_t sub_tp = dds_create_topic (sub_pp, &Space_Type1_desc, tpname, qos, NULL);
  CU_ASSERT_FATAL (sub_tp > 0);
  dds_delete_qos (qos);

  const dds_entity_t wr = dds_create_writer (pub_pp, pub_tp, NULL, NULL);
  CU_ASSERT_FATAL (wr > 0);
  
  ddsrt_thread_t wrtid;
  struct writethread_arg wrarg = {
    .wr = wr,
    .stop = DDSRT_ATOMIC_UINT32_INIT (0)
  };
  ddsrt_threadattr_t tattr;
  ddsrt_threadattr_init (&tattr);
  rc = ddsrt_thread_create (&wrtid, "writer", &tattr, writethread, &wrarg);
  CU_ASSERT_FATAL (rc == 0);

  struct listener_arg larg = {
    .taken = DDSRT_ATOMIC_UINT32_INIT (0),
    .badparam = DDSRT_ATOMIC_UINT32_INIT (0),
    .error = DDSRT_ATOMIC_UINT32_INIT (0)
  };
  dds_listener_t * const list = dds_create_listener (&larg);
  CU_ASSERT_FATAL (list != NULL);
  dds_lset_data_available (list, data_avail);
  
  const dds_time_t tend = dds_time () + DDS_SECS (3);
  uint32_t nreaders = 0;
  while (!ddsrt_atomic_ld32 (&wrarg.stop) && !ddsrt_atomic_ld32 (&larg.error) && dds_time () < tend)
  {
    nreaders++;
    const uint32_t taken0 = ddsrt_atomic_ld32 (&larg.taken);
    const dds_entity_t rd = dds_create_reader (sub_pp, sub_tp, NULL, list);
    CU_ASSERT_FATAL (rd > 0);
    while (!ddsrt_atomic_ld32 (&wrarg.stop) && !ddsrt_atomic_ld32 (&larg.error) && dds_time () < tend && ddsrt_atomic_ld32 (&larg.taken) == taken0)
    {
#if defined __APPLE__
      pthread_yield_np();
#else
      dds_sleepfor (DDS_MSECS (1));
#endif
    }
    rc = dds_delete (rd);
    CU_ASSERT_FATAL (rc == 0);
  }
  ddsrt_atomic_or32 (&wrarg.stop, 1);
  DDSRT_JOINSTR (wrtid, NULL);

  printf ("nreaders %"PRIu32"\n", nreaders);
  printf ("error %"PRIu32"\n", ddsrt_atomic_ld32 (&larg.error));
  printf ("taken %"PRIu32"\n", ddsrt_atomic_ld32 (&larg.taken));
  printf ("badparam %"PRIu32"\n", ddsrt_atomic_ld32 (&larg.badparam));
  printf ("stop %"PRIu32"\n", ddsrt_atomic_ld32 (&wrarg.stop));

  CU_ASSERT_FATAL (nreaders > 1000);
  CU_ASSERT_FATAL (!ddsrt_atomic_ld32 (&larg.error));
  CU_ASSERT_FATAL (ddsrt_atomic_ld32 (&larg.taken) > 1000);
  CU_ASSERT_FATAL (!(ddsrt_atomic_ld32 (&wrarg.stop) & 2));
  
  dds_delete_listener (list);
  dds_delete (sub_dom);
  dds_delete (pub_dom);
}
