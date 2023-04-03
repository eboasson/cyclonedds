/*
 * Copyright(c) 2022 ZettaScale Technology, Incorporated
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <stdlib.h>

#include "dds/dds.h"
#include "config_env.h"

#include "dds/version.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/cdtors.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsi/ddsi_xqos.h"
#include "ddsi__misc.h"

#include "test_common.h"

#include "VIDataModels.h"

#define FORCE_ENV

static void config__check_env (const char *env_variable, const char *expected_value)
{
  const char *env_uri = NULL;
  ddsrt_getenv (env_variable, &env_uri);
#ifdef FORCE_ENV
  {
    bool env_ok;

    if (env_uri == NULL)
      env_ok = false;
    else if (strncmp (env_uri, expected_value, strlen (expected_value)) != 0)
      env_ok = false;
    else
      env_ok = true;

    if (!env_ok)
    {
      dds_return_t r = ddsrt_setenv (env_variable, expected_value);
      CU_ASSERT_EQUAL_FATAL (r, DDS_RETCODE_OK);
    }
  }
#else
  CU_ASSERT_PTR_NOT_NULL_FATAL (env_uri);
  CU_ASSERT_STRING_EQUAL_FATAL (env_uri, expected_value);
#endif /* FORCE_ENV */
}

#define MAX_SAMPLES 8

//create stub virtual interface

//add config file

CU_Test (ddsc_virtual_interface, create, .init = ddsrt_init, .fini = ddsrt_fini)
{
  dds_return_t rc;
  void *samples[MAX_SAMPLES];
  dds_sample_info_t infos[MAX_SAMPLES];
  dds_entity_t participant, topic, writer, reader;

  config__check_env ("CYCLONEDDS_URI", CONFIG_ENV_VIRTUAL_INTERFACE);

  participant = dds_create_participant (DDS_DOMAIN_DEFAULT, NULL, NULL);
  CU_ASSERT_FATAL (participant > 0);

  topic = dds_create_topic (participant, &SC_Model_desc, "SC_Model", NULL, NULL);
  CU_ASSERT_FATAL (topic > 0);

  writer = dds_create_writer (participant, topic, NULL, NULL);
  CU_ASSERT_FATAL (writer > 0);

  reader = dds_create_reader (participant, topic, NULL, NULL);
  CU_ASSERT_FATAL (reader > 0);

  // write
  SC_Model mod = {.a = 0x1, .b = 0x4, .c = 0x9};
  rc = dds_write(writer, &mod);
  CU_ASSERT_EQUAL_FATAL (rc, DDS_RETCODE_OK);

  // read
  samples[0] = SC_Model__alloc ();
  rc = dds_read (reader, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
  CU_ASSERT_EQUAL_FATAL (rc, 1);

  SC_Model_free (samples[0], DDS_FREE_ALL);
  dds_delete (participant);
}
