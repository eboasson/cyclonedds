/*
 * Copyright(c) 2022 ZettaScale Technology and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_config_impl.h"
#include "dds/ddsi/ddsi_virtual_interface_loader.h"
#include "dds__virtual_interface.h"


bool ddsi_virtual_interface_load(struct ddsi_domaingv *gv, struct ddsi_config_virtual_interface *config, ddsi_virtual_interface_t **out)
{
  ddsi_virtual_interface_create_fn creator = NULL;
  const char *toload;
  ddsrt_dynlib_t handle;
  char load_fn[100];
  bool ok = true;
  ddsi_virtual_interface_t *vi = NULL;

  if (!config->library || config->library[0] == '\0')
    toload = config->name;
  else
    toload = config->library;

  if (ddsrt_dlopen(toload, true, &handle) != DDS_RETCODE_OK)
  {
    char buf[1024];
    if (DDS_RETCODE_OK == ddsrt_dlerror(buf, sizeof(buf)))
      GVERROR("Failed to load virtual interface library '%s' with error \"%s\".\n", toload, buf);
    else
      GVERROR("Failed to load virtual interface library '%s' with an unknown error.\n", toload);
    ok = false;
    goto err;
  }

  (void) snprintf(load_fn, 100, "%s_create_virtual_interface", config->name);

  if (ddsrt_dlsym(handle, load_fn, (void**)&creator) != DDS_RETCODE_OK)
  {
    GVERROR("Failed to initialize virtual interface '%s', could not load init function '%s'.\n", config->name, load_fn);
    ok = false;
    goto err;
  }

  if (!(ok = creator(&vi, calculate_interface_identifier(gv, config->name), config->config)))
    GVERROR("Failed to initialize virtual interface '%s'.\n", config->name);
  else
    vi->priority = config->priority.value;

err:
  if (!ok)
  {
    if (handle)
      ddsrt_dlclose(handle);
  }
  else
    *out = vi;

  return ok;
}
