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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dds/dds.h>

#include "dds/ddsrt/heap.h"
#include "dds/ddsi/ddsi_iid.h"
#include "dds/ddsi/q_thread.h"
#include "dds/ddsi/q_config.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/q_entity.h"
#include "dds/ddsi/q_radmin.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds/ddsi/q_transmit.h"
#include "dds/ddsi/q_xmsg.h"
#include "dds/ddsi/q_addrset.h"
#include "dds/ddsi/ddsi_tkmap.h"
#include "dds/ddsi/ddsi_sertype.h"
#include "dds/ddsi/ddsi_serdata.h"
#include "dds/ddsi/ddsi_builtin_topic_if.h"
#include "dds/ddsi/ddsi_rhc.h"
#include "dds/ddsi/ddsi_vnet.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds__whc.h"
#include "dds__types.h"

struct btif_sertype {
  struct ddsi_sertype c;
  struct ddsi_domaingv *gv;
};

struct btif_serdata {
  struct ddsi_serdata c;
  ddsi_guid_t guid;
  uint64_t iid;
  dds_qos_t qos;
};

static struct btif_sertype btif_sertype;

static void btif_sertype_free (struct ddsi_sertype *tpcmn)
{
  (void) tpcmn;
}
static void btif_sertype_zero_samples (const struct ddsi_sertype *d, void *samples, size_t count)
{
  (void) d; (void) samples; (void) count;
}
static void btif_sertype_realloc_samples (void **ptrs, const struct ddsi_sertype *d, void *old, size_t oldcount, size_t count)
{
  (void) ptrs; (void) d; (void) old; (void) oldcount; (void) count;
}
static void btif_sertype_free_samples (const struct ddsi_sertype *d, void **ptrs, size_t count, dds_free_op_t op)
{
  (void) d; (void) ptrs; (void) count; (void) op;
}

static const struct ddsi_sertype_ops btif_sertype_ops = {
  .version = ddsi_sertype_v0,
  .free = btif_sertype_free,
  .zero_samples = btif_sertype_zero_samples,
  .realloc_samples = btif_sertype_realloc_samples,
  .free_samples = btif_sertype_free_samples
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
    ddsi_xqos_fini (&d->qos);
  free (d);
}

static struct ddsi_serdata *btif_serdata_from_keyhash (const struct ddsi_sertype *tpcmn, const struct ddsi_keyhash *keyhash)
{
  const struct btif_sertype *tp = (const struct btif_sertype *) tpcmn;
  struct entity_common *entity = entidx_lookup_guid_untyped (tp->gv->entity_index, (const ddsi_guid_t *) keyhash->value);
  struct btif_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, &tp->c, entity ? SDK_DATA : SDK_KEY);
  memcpy (&sd->guid, keyhash->value, sizeof (sd->guid));
  if (entity == NULL)
  {
    sd->iid = 0;
    ddsi_xqos_init_empty (&sd->qos);
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
        ddsi_xqos_copy (&sd->qos, &((const struct proxy_participant *) entity)->plist->qos);
        break;
      case EK_PROXY_READER:
      case EK_PROXY_WRITER:
        ddsi_xqos_copy (&sd->qos, ((const struct generic_proxy_endpoint *) entity)->c.xqos);
        break;
      default:
        break;
    }
    ddsrt_mutex_unlock (&entity->qos_lock);
  }
  return &sd->c;
}

static struct ddsi_serdata *btif_serdata_to_untyped (const struct ddsi_serdata *dcmn)
{
  const struct btif_serdata *d = (const struct btif_serdata *) dcmn;
  struct btif_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, d->c.type, SDK_KEY);
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

static bool btif_serdata_untyped_to_sample (const struct ddsi_sertype *type, const struct ddsi_serdata *dcmn, void *sample, void **bufptr, void *buflim)
{
  (void) type; (void) dcmn; (void) sample; (void) bufptr; (void) buflim;
  return false;
}

static bool btif_serdata_eqkey (const struct ddsi_serdata *acmn, const struct ddsi_serdata *bcmn)
{
  const struct btif_serdata *a = (const struct btif_serdata *) acmn;
  const struct btif_serdata *b = (const struct btif_serdata *) bcmn;
  return memcmp (&a->guid, &b->guid, sizeof (a->guid)) == 0;
}

static size_t btif_serdata_print (const struct ddsi_sertype *tpcmn, const struct ddsi_serdata *dcmn, char *buf, size_t bufsize)
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
  .to_untyped = btif_serdata_to_untyped,
  .untyped_to_sample = btif_serdata_untyped_to_sample,
  .free = btif_serdata_free,
  .print = btif_serdata_print
};

static bool btif_is_builtintopic (const struct ddsi_sertype *type, void *arg)
{
  (void) type; (void) arg;
  return false;
}

static bool btif_is_visible (const struct ddsi_guid *guid, nn_vendorid_t vendorid, void *arg)
{
  struct ddsi_domaingv *gv = arg;
  struct entity_common *entity = entidx_lookup_guid_untyped (gv->entity_index, guid);
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
  struct ddsi_domaingv *gv = arg;
  struct ddsi_tkmap_instance *tk;
  struct ddsi_serdata *sd;
  struct ddsi_keyhash kh;
  memcpy (&kh, guid, sizeof (kh));
  /* any random builtin topic will do (provided it has a GUID for a key), because what matters is the "class" of the topic, not the actual topic; also, this is called early in the initialisation of the entity with this GUID, which simply causes serdata_from_keyhash to create a key-only serdata because the key lookup fails. */
  sd = ddsi_serdata_from_keyhash (&btif_sertype.c, &kh);
  tk = ddsi_tkmap_find (gv->m_tkmap, sd, true);
  ddsi_serdata_unref (sd);
  return tk;
}

static void btif_write (const struct entity_common *e, ddsrt_wctime_t timestamp, bool alive, void *arg)
{
  struct ddsi_domaingv *gv = arg;
  if (btif_is_visible (&e->guid, get_entity_vendorid (e), arg))
  {
    const char *kind = "?";
    switch (e->kind)
    {
      case EK_PROXY_PARTICIPANT: kind = "participant"; break;
      case EK_PROXY_READER: kind = "reader"; break;
      case EK_PROXY_WRITER: kind = "writer"; break;
      default: abort ();
    }
    printf ("%"PRId64" %s %"PRIx32":%"PRIx32":%"PRIx32":%"PRIx32" [%"PRIu64"] %s\n", timestamp.v, kind, e->guid.prefix.u[0], e->guid.prefix.u[1], e->guid.prefix.u[2], e->guid.entityid.u, e->iid, alive ? "alive" : "dead");
    if (e->kind == EK_PROXY_READER || e->kind == EK_PROXY_WRITER)
    {
      struct generic_proxy_endpoint *x = entidx_lookup_guid_untyped (gv->entity_index, &e->guid);
      assert ((x->c.xqos->present & QP_TOPIC_NAME) && (x->c.xqos->present & QP_TYPE_NAME));
      printf ("  topic %s type %s\n", x->c.xqos->topic_name, x->c.xqos->type_name);
    }
  }
}

/**********************************/

struct raw_sertype {
  struct ddsi_sertype c;
  struct ddsi_domaingv *gv;
};

struct raw_serdata {
  struct ddsi_serdata c;
  uint32_t size;
  unsigned char *blob;
};

static struct raw_sertype raw_sertype;

static void raw_sertype_free (struct ddsi_sertype *tpcmn)
{
  (void) tpcmn;
}
static void raw_sertype_zero_samples (const struct ddsi_sertype *d, void *samples, size_t count)
{
  (void) d; (void) samples; (void) count;
}
static void raw_sertype_realloc_samples (void **ptrs, const struct ddsi_sertype *d, void *old, size_t oldcount, size_t count)
{
  (void) ptrs; (void) d; (void) old; (void) oldcount; (void) count;
}
static void raw_sertype_free_samples (const struct ddsi_sertype *d, void **ptrs, size_t count, dds_free_op_t op)
{
  (void) d; (void) ptrs; (void) count; (void) op;
}

static const struct ddsi_sertype_ops raw_sertype_ops = {
  .version = ddsi_sertype_v0,
  .free = raw_sertype_free,
  .zero_samples = raw_sertype_zero_samples,
  .realloc_samples = raw_sertype_realloc_samples,
  .free_samples = raw_sertype_free_samples
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

static struct ddsi_serdata *raw_serdata_from_ser (const struct ddsi_sertype *tpcmn, enum ddsi_serdata_kind kind, const struct nn_rdata *fragchain, size_t size)
{
  const struct raw_sertype *tp = (const struct raw_sertype *) tpcmn;
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

static struct ddsi_serdata *raw_serdata_from_keyhash (const struct ddsi_sertype *tpcmn, const struct ddsi_keyhash *keyhash)
{
  (void) keyhash;
  const struct raw_sertype *tp = (const struct raw_sertype *) tpcmn;
  struct raw_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, &tp->c, SDK_KEY);
  sd->size = 0;
  sd->blob = NULL;
  return &sd->c;
}

static struct ddsi_serdata *raw_serdata_to_untyped (const struct ddsi_serdata *dcmn)
{
  const struct raw_serdata *d = (const struct raw_serdata *) dcmn;
  struct raw_serdata *sd = malloc (sizeof (*sd));
  ddsi_serdata_init (&sd->c, d->c.type, SDK_KEY);
  sd->c.type = NULL;
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

static bool raw_serdata_untyped_to_sample (const struct ddsi_sertype *type, const struct ddsi_serdata *dcmn, void *sample, void **bufptr, void *buflim)
{
  (void) type; (void) dcmn; (void) sample; (void) bufptr; (void) buflim;
  return false;
}

static bool raw_serdata_eqkey (const struct ddsi_serdata *acmn, const struct ddsi_serdata *bcmn)
{
  (void) acmn; (void) bcmn;
  return true;
}

static size_t raw_serdata_print (const struct ddsi_sertype *tpcmn, const struct ddsi_serdata *dcmn, char *buf, size_t bufsize)
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
  .to_untyped = raw_serdata_to_untyped,
  .untyped_to_sample = raw_serdata_untyped_to_sample,
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

static ddsrt_iovec_t *fakeconn_get_iov (ddsi_tran_conn_t conn)
{
  return (ddsrt_iovec_t *) ((unsigned char *) (conn + 1) + 128 - sizeof (ddsrt_iovec_t));
}

static size_t iovlen_sum (size_t niov, const ddsrt_iovec_t *iov)
{
  size_t tot = 0;
  while (niov--)
    tot += iov++->iov_len;
  return tot;
}

static ssize_t fakeconn_write (ddsi_tran_conn_t conn, const ddsi_locator_t *dst, size_t niov, const ddsrt_iovec_t *iov, uint32_t flags)
{
  (void) dst;
  (void) flags;

  ddsrt_iovec_t * const fakeconn_iov = fakeconn_get_iov (conn);
  assert (fakeconn_iov->iov_base == NULL);

  size_t len = iovlen_sum (niov, iov);
  fakeconn_iov->iov_len = (ddsrt_iov_len_t) len;
  fakeconn_iov->iov_base = ddsrt_malloc (len);
  char *ptr = fakeconn_iov->iov_base;
  for (size_t i = 0; i < niov; i++)
  {
    memcpy (ptr, iov[i].iov_base, iov[i].iov_len);
    ptr += iov[i].iov_len;
  }
  return (ssize_t) len;
}

static ssize_t fakeconn_read (ddsi_tran_conn_t conn, unsigned char * buf, size_t len, bool allow_spurious, ddsi_locator_t *srcloc)
{
  (void) allow_spurious;
  if (srcloc)
    memset (srcloc, 0, sizeof (*srcloc));
  ddsrt_iovec_t * const fakeconn_iov = fakeconn_get_iov (conn);
  assert (fakeconn_iov->iov_base != NULL);
  size_t n = fakeconn_iov->iov_len < len ? fakeconn_iov->iov_len : len;
  memcpy (buf, fakeconn_iov->iov_base, n);
  ddsrt_free (fakeconn_iov->iov_base);
  fakeconn_iov->iov_base = NULL;
  fakeconn_iov->iov_len = 0;
  return (ssize_t) n;
}

/**********************************/

int main (int argc, char **argv)
{
  uint32_t domid = DDS_DOMAIN_DEFAULT;
  struct cfgst *cfgst;
  struct ddsi_domaingv gv;
  struct ddsi_builtin_topic_interface btif = {
    .arg = &gv,
    .builtintopic_is_builtintopic = btif_is_builtintopic,
    .builtintopic_is_visible = btif_is_visible,
    .builtintopic_get_tkmap_entry = btif_get_tkmap_entry,
    .builtintopic_write_endpoint = btif_write
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
  cfgst = config_init ("<Tr><V>finest</><O>process-packets.log", &gv.config, domid);
  rtps_config_prep (&gv, cfgst);
  rtps_init (&gv);

  /* Abuse some other code to get a "connection" independent of the actual network stack
     and for which we can safely override the "read" and "write" functions.  The "123" is
     arbitrary, anything goes as long as the locator type in "vnet_init" doesn't collide
     with an existing one. */
  ddsi_vnet_init (&gv, "fake", 123);
  ddsi_tran_factory_t fakenet = ddsi_factory_find (&gv, "fake");
  assert (fakenet);
  ddsi_tran_conn_t fakeconn;
  ddsi_factory_create_conn (&fakeconn, fakenet, 0, &(const struct ddsi_tran_qos){
      .m_purpose = DDSI_TRAN_QOS_XMIT, /* this happens to work, even if it needs ... */
      .m_interface = &gv.interfaces[0] /* ... a lie! who cares? */
    });
  /* really want to have a place to store the data ... it is actually a little bit larger
     than the sizeof, so while this does work, don't try this at home! */
  fakeconn = ddsrt_realloc (fakeconn, sizeof (struct ddsi_tran_conn) + 128);
  fakeconn->m_read_fn = &fakeconn_read;
  fakeconn->m_write_fn = &fakeconn_write;

  ddsi_sertype_init (&btif_sertype.c, "<builtin>", &btif_sertype_ops, &btif_serdata_ops, false);
  btif_sertype.gv = &gv;
  gv.builtin_topic_interface = &btif;

  ddsi_sertype_init (&raw_sertype.c, "nighttime", &raw_sertype_ops, &raw_serdata_ops, false);
  rtps_start (&gv);

  ddsi_guid_t ppguid, rdguid, wrguid;
  struct reader *rd;
  struct writer *wr;
  ddsi_plist_t plist;
  ddsi_plist_init_empty (&plist);
  plist.qos.present = QP_HISTORY;
  plist.qos.history.kind = DDS_HISTORY_KEEP_ALL;
  ddsi_xqos_mergein_missing (&plist.qos, &gv.default_xqos_wr, ~(uint64_t)0);

  struct thread_state1 * const ts1 = lookup_thread_state ();
  /* Processing incoming packets doesn't like to run on anything other than a thread
     created internally by rtps_start(), so fake it.  At that point, the "gv" pointer
     must also be set and tied to the one domain. */
  ts1->state = THREAD_STATE_ALIVE;
  ddsrt_atomic_stvoidp (&ts1->gv, &gv);

  thread_state_awake (ts1, &gv);
  new_participant (&ppguid, &gv, 0, &plist);
  struct participant *pp = entidx_lookup_participant_guid (gv.entity_index, &ppguid);
  assert (pp != NULL);

  /* reader doesn't take ownership of rhc anymore ... */
  struct ddsi_rhc fake_rhc;
  fake_rhc.ops = &fake_rhc_ops;
  new_reader (&rd, &rdguid, NULL, pp, "bark", &raw_sertype.c, &plist.qos, &fake_rhc, 0, NULL);

  /* ... but writer still takes ownership of whc */
  struct whc_writer_info *wrinfo = whc_make_wrinfo (NULL, &plist.qos);
  struct whc *whc = whc_new (&gv, wrinfo);
  new_writer (&wr, &wrguid, NULL, pp, "bark", &raw_sertype.c, &plist.qos, whc, 0, NULL);
  whc_free_wrinfo (wrinfo);
  thread_state_asleep (ts1);

  /* Really, really want the writer to send data out, but it normally does this only when
     there are proxy readers.  We could make a proxy reader, but in the absence of any,
     pushing our fake locator into the writer's address set should work!  (The moment a
     proxy reader shows up, it'll recalculate the address set and throw out the fake
     locator.)  None of this is necessary if you have a "proper" source of packets and
     don't need to rely on a writer to construct them. */
  ddsi_xlocator_t fakeloc = {
    .conn = fakeconn,
    .c = { .kind = (int32_t) ddsi_conn_type (fakeconn), .port = ddsi_conn_port (fakeconn) }
  };
  add_xlocator_to_addrset (&gv, wr->as, &fakeloc);

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

  /* fake receiver: see recv_thread() in src/core/ddsi/src/q_receive.c and comments in
     src/core/ddsi/src/q_radmin.c */
  struct nn_rbufpool *rbpool = nn_rbufpool_new (&gv.logconfig, gv.config.rbuf_size, gv.config.rmsg_chunk_size);
  nn_rbufpool_setowner (rbpool, ddsrt_thread_self ());

  struct nn_xpack *xp = nn_xpack_new (&gv, 0, false);
  while (1)
  {
    /* raw sending: */
    struct ddsi_serdata *sd = raw_serdata_from_ser (&raw_sertype.c, SDK_DATA, &fake_sample.frag, fake_sample.frag.maxp1);
    sd->timestamp = ddsrt_time_wallclock ();
    sd->statusinfo = 0;

    (*(uint32_t *) (fake_sample.cdr_hdr_and_payload + 12))++;

    /* write_sample takes over ownership of data, we want to retain */
    thread_state_awake (ts1, &gv);
    write_sample_gc_notk (ts1, xp, wr, sd);
    thread_state_asleep (ts1);

    /* no auto-flush yet (except when full) */
    nn_xpack_send (xp, true);

    /* nn_xpack_send should have passed the message into fakeconn_write (assuming no real
       proxy readers showed up), process it before the next packet asserts on the presence
       of a packet (note that this also assumes that it fits in a single message!)

       If the packets come from an external source, neither the writer nor the reader is
       required, and instead of fiddling with the writer's address set to force it to pass
       the data to our "fakeconn", one could just load the packet directly in "fakeconn"
       and call do_packet.  Much easier. */
    bool do_packet (struct thread_state1 * const ts1, struct ddsi_domaingv *gv, ddsi_tran_conn_t conn, const ddsi_guid_prefix_t *guidprefix, struct nn_rbufpool *rbpool);
    do_packet (ts1, &gv, fakeconn, NULL, rbpool);

    dds_sleepfor (DDS_SECS (1));
  }

  /* undo the hack to make the main thread palatable to do_packet() */
  ts1->state = THREAD_STATE_LAZILY_CREATED;

  nn_rbufpool_free (rbpool);
  ddsi_conn_free (fakeconn);

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
