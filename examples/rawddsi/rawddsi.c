/*
 * Copyright(c) 2019 ADLINK Technology Limited and others
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
#include <stdint.h>
#include <string.h>
#include <dds/dds.h>

#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/q_thread.h"
#include "dds/ddsi/q_config.h"
#include "dds/ddsi/q_globals.h"
#include "dds/ddsi/q_entity.h"
#include "dds/ddsi/q_radmin.h"
#include "dds/ddsi/q_plist.h"
#include "dds/ddsi/q_transmit.h"
#include "dds/ddsi/q_xmsg.h"
#include "dds/ddsi/ddsi_tkmap.h"
#include "dds/ddsi/ddsi_sertopic.h"
#include "dds/ddsi/ddsi_serdata.h"
#include "dds/ddsi/ddsi_builtin_topic_if.h"
#include "dds/ddsi/ddsi_rhc.h"
#include "dds__whc.h"

struct generic_proxy_endpoint { // FIXME: should add to q_entity.h
  struct entity_common e;
  struct proxy_endpoint_common c;
};

struct btif_sertopic {
  struct ddsi_sertopic c;
  struct q_globals *gv;
};

struct btif_serdata {
  struct ddsi_serdata c;
  ddsi_guid_t guid;
  uint64_t iid;
  dds_qos_t qos;
};

static struct btif_sertopic btif_sertopic;

static void btif_sertopic_free (struct ddsi_sertopic *tpcmn)
{
  (void) tpcmn;
}
static void btif_sertopic_zero_samples (const struct ddsi_sertopic *d, void *samples, size_t count)
{
  (void) d; (void) samples; (void) count;
}
static void btif_sertopic_realloc_samples (void **ptrs, const struct ddsi_sertopic *d, void *old, size_t oldcount, size_t count)
{
  (void) ptrs; (void) d; (void) old; (void) oldcount; (void) count;
}
static void btif_sertopic_free_samples (const struct ddsi_sertopic *d, void **ptrs, size_t count, dds_free_op_t op)
{
  (void) d; (void) ptrs; (void) count; (void) op;
}

static const struct ddsi_sertopic_ops btif_sertopic_ops = {
  .free = btif_sertopic_free,
  .zero_samples = btif_sertopic_zero_samples,
  .realloc_samples = btif_sertopic_realloc_samples,
  .free_samples = btif_sertopic_free_samples
};

static uint32_t btif_serdata_size (const struct ddsi_serdata *dcmn)
{
  (void) dcmn;
  return 0;
}

static void btif_serdata_free (struct ddsi_serdata *dcmn)
{
  struct btif_serdata *d = (struct btif_serdata *) dcmn;
  if (d->c.kind == SDK_DATA)
    nn_xqos_fini (&d->qos);
  free (d);
}

static struct ddsi_serdata *btif_serdata_from_keyhash (const struct ddsi_sertopic *tpcmn, const struct nn_keyhash *keyhash)
{
  const struct btif_sertopic *tp = (const struct btif_sertopic *) tpcmn;
  struct entity_common *entity = ephash_lookup_guid_untyped (tp->gv->guid_hash, (const ddsi_guid_t *) keyhash->value);
  struct btif_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, &tp->c, entity ? SDK_DATA : SDK_KEY);
  memcpy (&sd->guid, keyhash->value, sizeof (sd->guid));
  if (entity == NULL)
  {
    sd->iid = 0;
    nn_xqos_init_empty (&sd->qos);
  }
  else
  {
    sd->iid = entity->iid;
    ddsrt_mutex_lock (&entity->qos_lock);
    switch (entity->kind)
    {
      case EK_PARTICIPANT:
      case EK_READER:
      case EK_WRITER:
        /* filtered out by is_visible */
        abort ();
        break;
      case EK_PROXY_PARTICIPANT:
        nn_xqos_copy (&sd->qos, &((const struct proxy_participant *) entity)->plist->qos);
        break;
      case EK_PROXY_READER:
      case EK_PROXY_WRITER:
        nn_xqos_copy (&sd->qos, ((const struct generic_proxy_endpoint *) entity)->c.xqos);
        break;
    }
    ddsrt_mutex_unlock (&entity->qos_lock);
  }
  return &sd->c;
}

static struct ddsi_serdata *btif_serdata_to_topicless (const struct ddsi_serdata *dcmn)
{
  const struct btif_serdata *d = (const struct btif_serdata *) dcmn;
  struct btif_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, d->c.topic, SDK_KEY);
  sd->guid = d->guid;
  return &sd->c;
}

static void btif_serdata_to_ser (const struct ddsi_serdata *dcmn, size_t off, size_t sz, void *buf)
{
  (void) dcmn; (void) off; (void) sz; (void) buf;
}

static struct ddsi_serdata *btif_serdata_to_ser_ref (const struct ddsi_serdata *dcmn, size_t off, size_t sz, ddsrt_iovec_t *ref)
{
  (void) dcmn; (void) off; (void) sz; (void) ref;
  return NULL;
}
static void btif_serdata_to_ser_unref (struct ddsi_serdata *dcmn, const ddsrt_iovec_t *ref)
{
  (void) dcmn; (void) ref;
}

static bool btif_serdata_to_sample (const struct ddsi_serdata *dcmn, void *sample, void **bufptr, void *buflim)
{
  (void) dcmn; (void) sample; (void) bufptr; (void) buflim;
  return false;
}

static bool btif_serdata_topicless_to_sample (const struct ddsi_sertopic *topic, const struct ddsi_serdata *dcmn, void *sample, void **bufptr, void *buflim)
{
  (void) topic; (void) dcmn; (void) sample; (void) bufptr; (void) buflim;
  return false;
}

static bool btif_serdata_eqkey (const struct ddsi_serdata *acmn, const struct ddsi_serdata *bcmn)
{
  const struct btif_serdata *a = (const struct btif_serdata *) acmn;
  const struct btif_serdata *b = (const struct btif_serdata *) bcmn;
  return memcmp (&a->guid, &b->guid, sizeof (a->guid)) == 0;
}

static size_t btif_serdata_print (const struct ddsi_sertopic *tpcmn, const struct ddsi_serdata *dcmn, char *buf, size_t bufsize)
{
  (void) tpcmn; (void) dcmn; (void) buf; (void) bufsize;
  return (size_t) snprintf (buf, bufsize, "<builtin>");
}

static const struct ddsi_serdata_ops btif_serdata_ops = {
  .eqkey = btif_serdata_eqkey,
  .get_size = btif_serdata_size,
  .from_ser = 0,
  .from_keyhash = btif_serdata_from_keyhash,
  .from_sample = 0,
  .to_ser = btif_serdata_to_ser,
  .to_ser_ref = btif_serdata_to_ser_ref,
  .to_ser_unref = btif_serdata_to_ser_unref,
  .to_sample = btif_serdata_to_sample,
  .to_topicless = btif_serdata_to_topicless,
  .topicless_to_sample = btif_serdata_topicless_to_sample,
  .free = btif_serdata_free,
  .print = btif_serdata_print
};

static bool btif_is_builtintopic (const struct ddsi_sertopic *topic, void *arg)
{
  (void) topic; (void) arg;
  return false;
}

static bool btif_is_visible (const struct ddsi_guid *guid, nn_vendorid_t vendorid, void *arg)
{
  struct q_globals *gv = arg;
  struct entity_common *entity = ephash_lookup_guid_untyped (gv->guid_hash, guid);
  if (entity == NULL)
    return false;
  switch (entity->kind)
  {
    case EK_PROXY_PARTICIPANT:
    case EK_PROXY_READER:
    case EK_PROXY_WRITER:
      return ! is_builtin_endpoint (guid->entityid, vendorid);
    default:
      /* not interested in local readers, writers */
      return false;
  }
}

static struct ddsi_tkmap_instance *btif_get_tkmap_entry (const struct ddsi_guid *guid, void *arg)
{
  struct q_globals *gv = arg;
  struct ddsi_tkmap_instance *tk;
  struct ddsi_serdata *sd;
  struct nn_keyhash kh;
  memcpy (&kh, guid, sizeof (kh));
  /* any random builtin topic will do (provided it has a GUID for a key), because what matters is the "class" of the topic, not the actual topic; also, this is called early in the initialisation of the entity with this GUID, which simply causes serdata_from_keyhash to create a key-only serdata because the key lookup fails. */
  sd = ddsi_serdata_from_keyhash (&btif_sertopic.c, &kh);
  tk = ddsi_tkmap_find (gv->m_tkmap, sd, true);
  ddsi_serdata_unref (sd);
  return tk;
}

static void btif_write (const struct entity_common *e, nn_wctime_t timestamp, bool alive, void *arg)
{
  struct q_globals *gv = arg;
  if (btif_is_visible (&e->guid, get_entity_vendorid (e), arg))
  {
    const char *kind = "?";
    switch (e->kind)
    {
      case EK_PROXY_PARTICIPANT: kind = "participant"; break;
      case EK_PROXY_READER: kind = "reader"; break;
      case EK_PROXY_WRITER: kind = "writer"; break;
      case EK_PARTICIPANT: case EK_READER: case EK_WRITER: abort ();
    }
    printf ("%"PRId64" %s %"PRIx32":%"PRIx32":%"PRIx32":%"PRIx32" [%"PRIu64"] %s\n", timestamp.v, kind, e->guid.prefix.u[0], e->guid.prefix.u[1], e->guid.prefix.u[2], e->guid.entityid.u, e->iid, alive ? "alive" : "dead");
    if (e->kind == EK_PROXY_READER || e->kind == EK_PROXY_WRITER)
    {
      struct generic_proxy_endpoint *x = ephash_lookup_guid_untyped (gv->guid_hash, &e->guid);
      assert ((x->c.xqos->present & QP_TOPIC_NAME) && (x->c.xqos->present & QP_TYPE_NAME));
      printf ("  topic %s type %s\n", x->c.xqos->topic_name, x->c.xqos->type_name);
    }
  }
}

/**********************************/

struct raw_sertopic {
  struct ddsi_sertopic c;
  struct q_globals *gv;
};

struct raw_serdata {
  struct ddsi_serdata c;
  uint32_t size;
  unsigned char *blob;
};

static struct raw_sertopic raw_sertopic;

static void raw_sertopic_free (struct ddsi_sertopic *tpcmn)
{
  (void) tpcmn;
}
static void raw_sertopic_zero_samples (const struct ddsi_sertopic *d, void *samples, size_t count)
{
  (void) d; (void) samples; (void) count;
}
static void raw_sertopic_realloc_samples (void **ptrs, const struct ddsi_sertopic *d, void *old, size_t oldcount, size_t count)
{
  (void) ptrs; (void) d; (void) old; (void) oldcount; (void) count;
}
static void raw_sertopic_free_samples (const struct ddsi_sertopic *d, void **ptrs, size_t count, dds_free_op_t op)
{
  (void) d; (void) ptrs; (void) count; (void) op;
}

static const struct ddsi_sertopic_ops raw_sertopic_ops = {
  .free = raw_sertopic_free,
  .zero_samples = raw_sertopic_zero_samples,
  .realloc_samples = raw_sertopic_realloc_samples,
  .free_samples = raw_sertopic_free_samples
};

static uint32_t raw_serdata_size (const struct ddsi_serdata *dcmn)
{
  struct raw_serdata *d = (struct raw_serdata *) dcmn;
  return d->size;
}

static void raw_serdata_free (struct ddsi_serdata *dcmn)
{
  struct raw_serdata *d = (struct raw_serdata *) dcmn;
  if (d->blob)
    free (d->blob);
  free (d);
}

static struct ddsi_serdata *raw_serdata_from_ser (const struct ddsi_sertopic *tpcmn, enum ddsi_serdata_kind kind, const struct nn_rdata *fragchain, size_t size)
{
  const struct raw_sertopic *tp = (const struct raw_sertopic *) tpcmn;
  struct raw_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, &tp->c, kind);
  assert (size <= UINT32_MAX); // it's not like DDSI can have objects > 4GB
  sd->size = (uint32_t) size;
  sd->blob = malloc (size + 4); // + 4 so we have room for padding
  uint32_t off = 0;
  while (fragchain) {
    if (fragchain->maxp1 > off) {
      /* only copy if this fragment adds data */
      const unsigned char * payload =
        NN_RMSG_PAYLOADOFF(fragchain->rmsg, NN_RDATA_PAYLOAD_OFF(fragchain));
      memcpy (sd->blob + off, payload + off - fragchain->min, fragchain->maxp1 - off);
      off = fragchain->maxp1;
    }
    fragchain = fragchain->nextfrag;
  }
  memset (sd->blob + off, 0, 4);
  return &sd->c;
}

static struct ddsi_serdata *raw_serdata_from_keyhash (const struct ddsi_sertopic *tpcmn, const struct nn_keyhash *keyhash)
{
  (void) keyhash;
  const struct raw_sertopic *tp = (const struct raw_sertopic *) tpcmn;
  struct raw_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, &tp->c, SDK_KEY);
  sd->size = 0;
  sd->blob = NULL;
  return &sd->c;
}

static struct ddsi_serdata *raw_serdata_to_topicless (const struct ddsi_serdata *dcmn)
{
  const struct raw_serdata *d = (const struct raw_serdata *) dcmn;
  struct raw_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, d->c.topic, SDK_KEY);
  sd->c.topic = NULL;
  sd->size = 0;
  sd->blob = NULL;
  return &sd->c;
}

static void raw_serdata_to_ser (const struct ddsi_serdata *dcmn, size_t off, size_t sz, void *buf)
{
  const struct raw_serdata *d = (const struct raw_serdata *) dcmn;
  memcpy (buf, d->blob + off, sz);
}

static struct ddsi_serdata *raw_serdata_to_ser_ref (const struct ddsi_serdata *dcmn, size_t off, size_t sz, ddsrt_iovec_t *ref)
{
  const struct raw_serdata *d = (const struct raw_serdata *) dcmn;
  ref->iov_base = d->blob + off;
  ref->iov_len = sz;
  return ddsi_serdata_ref (&d->c);
}

static void raw_serdata_to_ser_unref (struct ddsi_serdata *dcmn, const ddsrt_iovec_t *ref)
{
  (void) ref;
  ddsi_serdata_unref (dcmn);
}

static bool raw_serdata_to_sample (const struct ddsi_serdata *dcmn, void *sample, void **bufptr, void *buflim)
{
  (void) dcmn; (void) sample; (void) bufptr; (void) buflim;
  return false;
}

static bool raw_serdata_topicless_to_sample (const struct ddsi_sertopic *topic, const struct ddsi_serdata *dcmn, void *sample, void **bufptr, void *buflim)
{
  (void) topic; (void) dcmn; (void) sample; (void) bufptr; (void) buflim;
  return false;
}

static bool raw_serdata_eqkey (const struct ddsi_serdata *acmn, const struct ddsi_serdata *bcmn)
{
  (void) acmn; (void) bcmn;
  return true;
}

static size_t raw_serdata_print (const struct ddsi_sertopic *tpcmn, const struct ddsi_serdata *dcmn, char *buf, size_t bufsize)
{
  (void) tpcmn; (void) dcmn; (void) buf; (void) bufsize;
  return (size_t) snprintf (buf, bufsize, "<raw>");
}

static const struct ddsi_serdata_ops raw_serdata_ops = {
  .eqkey = raw_serdata_eqkey,
  .get_size = raw_serdata_size,
  .from_ser = raw_serdata_from_ser,
  .from_keyhash = raw_serdata_from_keyhash,
  .from_sample = 0,
  .to_ser = raw_serdata_to_ser,
  .to_ser_ref = raw_serdata_to_ser_ref,
  .to_ser_unref = raw_serdata_to_ser_unref,
  .to_sample = raw_serdata_to_sample,
  .to_topicless = raw_serdata_to_topicless,
  .topicless_to_sample = raw_serdata_topicless_to_sample,
  .free = raw_serdata_free,
  .print = raw_serdata_print
};

/**********************************/

static void fake_rhc_free (struct ddsi_rhc *rhc)
{
  free (rhc);
}

static bool fake_rhc_store (struct ddsi_rhc * __restrict rhc, const struct ddsi_writer_info * __restrict wrinfo, struct ddsi_serdata * __restrict sample, struct ddsi_tkmap_instance * __restrict tk)
{
  assert (sample->ops == &raw_serdata_ops);
  const struct raw_serdata *d = (struct raw_serdata *) sample;

  (void) rhc; (void) tk;
  printf ("%"PRId64" %"PRIx32":%"PRIx32":%"PRIx32":%"PRIx32" iid %"PRIu64"\n", sample->timestamp.v, wrinfo->guid.prefix.u[0], wrinfo->guid.prefix.u[1], wrinfo->guid.prefix.u[2], wrinfo->guid.entityid.u, wrinfo->iid);
  for (uint32_t i = 0; i < d->size; i += 16)
  {
    uint32_t j;
    printf ("%4d  ", i);
    for (j = 0; i + j < d->size && j < 16; j++)
    {
      if (j == 8) printf (" ");
      printf (" %02x", d->blob[i+j]);
    }
    printf ("%*s   ", 3*(16-j) + (j<8), "");
    for (j = 0; i + j < d->size && j < 16; j++)
    {
      if (j == 8) printf (" ");
      printf ("%c", (d->blob[i+j] >= 32 && d->blob[i+j] <= 127) ? d->blob[i+j] : '.');
    }
    printf ("\n");
  }
  return true;
}

static void fake_rhc_unregister_wr (struct ddsi_rhc * __restrict rhc, const struct ddsi_writer_info * __restrict wrinfo)
{
  (void) rhc; (void) wrinfo;
}

static void fake_rhc_relinquish_ownership (struct ddsi_rhc * __restrict rhc, const uint64_t wr_iid)
{
  (void) rhc; (void) wr_iid;
}

static void fake_rhc_set_qos (struct ddsi_rhc *rhc, const struct dds_qos *qos)
{
  (void) rhc; (void) qos;
}

static struct ddsi_rhc_ops fake_rhc_ops = {
  .free = fake_rhc_free,
  .store = fake_rhc_store,
  .unregister_wr = fake_rhc_unregister_wr,
  .relinquish_ownership = fake_rhc_relinquish_ownership,
  .set_qos = fake_rhc_set_qos
};

/**********************************/

int main (int argc, char **argv)
{
  uint32_t domid = DDS_DOMAIN_DEFAULT;
  struct cfgst *cfgst;
  struct q_globals gv;
  struct ddsi_builtin_topic_interface btif = {
    .arg = &gv,
    .builtintopic_is_builtintopic = btif_is_builtintopic,
    .builtintopic_is_visible = btif_is_visible,
    .builtintopic_get_tkmap_entry = btif_get_tkmap_entry,
    .builtintopic_write = btif_write
  };

  if (argc > 1)
  {
    char *endp;
    uintmax_t x = strtoumax (argv[1], &endp, 0);
    if (*argv[1] == 0 || *endp != 0 || x >= UINT32_MAX)
    {
      fprintf (stderr, "%s: invalid domain id\n", argv[1]);
      return 1;
    }
  }

  ddsi_iid_init ();
  thread_states_init (64);

  memset (&dds_global, 0, sizeof (dds_global));
  ddsrt_mutex_init (&dds_global.m_mutex);

  memset (&gv, 0, sizeof (gv));
  cfgst = config_init ("<Tr><V>finest</><O>rawddsi.log", &gv.config, domid);
  rtps_config_prep (&gv, cfgst);
  rtps_init (&gv);

  ddsi_sertopic_init (&btif_sertopic.c, "<builtin>", "<builtin>", &btif_sertopic_ops, &btif_serdata_ops, false);
  btif_sertopic.gv = &gv;
  gv.builtin_topic_interface = &btif;

  ddsi_sertopic_init (&raw_sertopic.c, "bark", "nighttime", &raw_sertopic_ops, &raw_serdata_ops, false);

  rtps_start (&gv);

  ddsi_guid_t ppguid, rdguid, wrguid;
  struct reader *rd;
  struct writer *wr;
  nn_plist_t plist;
  nn_plist_init_empty (&plist);
  plist.qos.present = QP_HISTORY;
  plist.qos.history.kind = DDS_HISTORY_KEEP_ALL;

  struct thread_state1 * const ts1 = lookup_thread_state ();

  thread_state_awake (ts1, &gv);
  new_participant (&ppguid, &gv, 0, &plist);

  /* reader doesn't take ownership of rhc anymore ... */
  struct ddsi_rhc fake_rhc;
  fake_rhc.ops = &fake_rhc_ops;
  new_reader (&rd, &gv, &rdguid, NULL, &ppguid, &raw_sertopic.c, &plist.qos, &fake_rhc, 0, NULL);

  /* ... but writer still takes ownership of whc */
  struct whc *whc = whc_new(&gv, false, 1, 0);
  new_writer (&wr, &gv, &wrguid, NULL, &ppguid, &raw_sertopic.c, &plist.qos, whc, 0, NULL);
  thread_state_asleep (ts1);

  /* make a sample ... many ways to do this, most more elegant than this one */
  struct fake_sample {
    struct nn_rmsg rmsg;
    char cdr_hdr_and_payload[16];
    struct nn_rdata frag;
  } fake_sample = {
    .cdr_hdr_and_payload = { 0,1,0,0, 4,0,0,0, 'a','a','p',0, 0,0,0,0 },
    .frag = {
      .rmsg = &fake_sample.rmsg,
      .nextfrag = NULL,
      .min = 0,
      .maxp1 = 16,
      .payload_zoff = 0
    }
  };

  struct nn_xpack *xp = nn_xpack_new (gv.data_conn_uc, 0, false);
  while (1)
  {
    struct ddsi_serdata *sd = raw_serdata_from_ser (&raw_sertopic.c, SDK_DATA, &fake_sample.frag, fake_sample.frag.maxp1);
    sd->timestamp = now ();
    sd->statusinfo = 0;

    (*(uint32_t *) (fake_sample.cdr_hdr_and_payload + 12))++;

    /* write_sample takes over ownership of data, we want to retain */
    thread_state_awake (ts1, &gv);
    write_sample_gc_notk (ts1, xp, wr, sd);
    thread_state_asleep (ts1);

    /* no auto-flush yet (except when full) */
    nn_xpack_send (xp, true);

    dds_sleepfor (DDS_SECS (1));
  }

  rtps_stop (&gv);
  thread_state_awake (lookup_thread_state (), &gv);
  delete_participant (&gv, &ppguid);
  thread_state_asleep (lookup_thread_state ());

  rtps_fini (&gv);
  config_fini (cfgst);
  thread_states_fini ();
  ddsi_iid_fini ();
  return 0;
}
