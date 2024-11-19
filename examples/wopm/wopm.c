#include <stdio.h>
#include <stdlib.h>

#include "dds/dds.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/misc.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/threads.h"

#include "wopm_type.h"

struct on_publication_matched_arg {
  ddsrt_cond_t cv;
  ddsrt_mutex_t lk;
  uint32_t count;
  bool wr_ready;
  dds_entity_t wr;
};

static const bool printprio = false;

static void on_publication_matched (const dds_entity_t wr, dds_publication_matched_status_t st, void *varg)
{
  (void) wr;
  struct on_publication_matched_arg *arg = varg;
  ddsrt_mutex_lock (&arg->lk);
  arg->count = st.current_count;
  if (arg->count == 2)
    ddsrt_cond_signal (&arg->cv);
  ddsrt_mutex_unlock (&arg->lk);
}

static uint32_t do_write (void *varg)
{
  struct on_publication_matched_arg *arg = varg;
  if (printprio)
  {
    int cl;
    struct sched_param sp1;
    pthread_getschedparam (pthread_self (), &cl, &sp1);
    printf ("wr: %d %d\n", cl, sp1.sched_priority);
  }
  ddsrt_mutex_lock (&arg->lk);
  arg->wr_ready = true;
  ddsrt_cond_signal (&arg->cv);
  while (arg->count != 2)
    ddsrt_cond_wait (&arg->cv, &arg->lk);
  ddsrt_mutex_unlock (&arg->lk);
  return (uint32_t) dds_write (arg->wr, &(WOPM) { 1 });
}

int main (int argc, char **argv)
{
  (void)argc; (void)argv;
  struct on_publication_matched_arg listarg;
  ddsrt_mutex_init (&listarg.lk);
  ddsrt_cond_init (&listarg.cv);

  const char *xx[] = { "/\r", "-\r", "\\\r", "|\r" };
  size_t xxi = 0;
  while (true)
  {
    fputs (xx[xxi], stdout); fflush (stdout);
    if (++xxi == sizeof (xx) / sizeof (xx[0]))
      xxi = 0;

    const dds_entity_t dp = dds_create_participant (DDS_DOMAIN_DEFAULT, NULL, NULL);
    const dds_entity_t tp = dds_create_topic (dp, &WOPM_desc, "write_first_write_after_second_local_reader", NULL, NULL);

    listarg.count = 0;
    listarg.wr_ready = false;
    dds_listener_t * const list = dds_create_listener (&listarg);
    dds_lset_publication_matched (list, on_publication_matched);
    listarg.wr = dds_create_writer (dp, tp, NULL, list);
    dds_delete_listener (list);
    ddsrt_thread_t wrtid;
    ddsrt_threadattr_t tattr;
    ddsrt_threadattr_init (&tattr);
    tattr.schedClass = DDSRT_SCHED_TIMESHARE;
    tattr.schedPriority = sched_get_priority_max (SCHED_OTHER);
    ddsrt_thread_create (&wrtid, "ddsc_write", &tattr, do_write, &listarg);

    ddsrt_mutex_lock (&listarg.lk);
    while (!listarg.wr_ready)
      ddsrt_cond_wait (&listarg.cv, &listarg.lk);
    ddsrt_mutex_unlock (&listarg.lk);

    const struct sched_param sp = { .sched_priority = sched_get_priority_min (SCHED_OTHER) };
    if (pthread_setschedparam (pthread_self (), SCHED_OTHER, &sp))
      abort ();
    if (printprio)
    {
      int cl;
      struct sched_param sp1;
      pthread_getschedparam (pthread_self (), &cl, &sp1);
      printf ("m: %d %d\n", cl, sp1.sched_priority);
    }

    const dds_entity_t rd0 = dds_create_reader (dp, tp, NULL, NULL);
    const dds_entity_t rd1 = dds_create_reader (dp, tp, NULL, NULL);

    dds_time_t timeout = dds_time () + DDS_SECS (1);
    int32_t n = 0;
    while (n != 2 && dds_time () < timeout)
    {
      WOPM samp;
      void *sampptr = &samp;
      dds_sample_info_t si;
      n += dds_take (rd0, &sampptr, &si, 1, 1);
      n += dds_take (rd1, &sampptr, &si, 1, 1);
    }
    if (n != 2)
    {
      abort ();
    }

    ddsrt_thread_join (wrtid, NULL);
    dds_delete (listarg.wr);
    dds_delete (rd0);
    dds_delete (rd1);

    dds_delete (dp);

    if (printprio)
    {
      break;
    }
  }

  ddsrt_cond_destroy (&listarg.cv);
  ddsrt_mutex_destroy (&listarg.lk);
}
