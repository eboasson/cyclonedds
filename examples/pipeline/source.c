#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))
#include <unistd.h>
#endif
#if defined(_POSIX_VERSION)
#include <signal.h>
#include <sys/time.h>
#endif
#include "dds/dds.h"
#include "Pipeline.h"
#include "common.h"

int main (int argc, char ** argv)
{
  dds_return_t rc;
  dds_duration_t interval;

  if (argc != 3)
  {
    printf ("usage: %s topic interval(0,1000[ms])\n", argv[0]);
    return 2;
  }
  if ((interval = atoi (argv[2])) <= 0 || interval >= 1000)
  {
    printf ("invalid interval: %s\n", argv[2]);
    return 2;
  }
  interval *= DDS_NSECS_IN_MSEC;

#if defined(_POSIX_VERSION)
  sigset_t sigalrm_mask;
  sigemptyset (&sigalrm_mask);
  sigaddset (&sigalrm_mask, SIGALRM);
  if (sigprocmask (SIG_BLOCK, &sigalrm_mask, NULL) == -1)
  {
    perror ("sigprocmask failed");
    return 1;
  }
#endif

  const dds_entity_t dp = dds_create_participant (DDS_DOMAIN_DEFAULT, NULL, NULL);
  if (dp < 0)
  {
    fprintf (stderr, "failed to create participant: %s\n", dds_strretcode (dp));
    return 1;
  }

  const dds_entity_t wtp = create_topic (dp, argv[1]);
  if (wtp < 0)
  {
    fprintf (stderr, "failed to create topic %s: %s\n", argv[1], dds_strretcode (wtp));
    goto fail;
  }
  const dds_entity_t wr = dds_create_writer (dp, wtp, NULL, NULL);
  if (wr < 0)
  {
    fprintf (stderr, "failed to create writer for topic %s: %s\n", argv[1], dds_strretcode (wr));
    goto fail;
  }

  Pipeline_Msg * const msg = malloc (sizeof (*msg));
  memset (msg, 0, sizeof (*msg));

#if defined(_POSIX_VERSION)
  struct itimerval val = {
    .it_value = { .tv_sec = 0, .tv_usec = (int) (interval / 1000) },
    .it_interval = { .tv_sec = 0, .tv_usec = (int) (interval / 1000) }
  };
  if (setitimer (ITIMER_REAL, &val, NULL) == -1)
  {
    perror ("failed to set timer");
    goto fail;
  }
#endif

  while (1)
  {
    if ((rc = dds_write (wr, msg)) < 0)
    {
      fprintf (stderr, "write failed: %s\n", dds_strretcode (rc));
      free (msg);
      goto fail;
    }
    msg->seqno++;
#if defined(_POSIX_VERSION)
    {
      int sig;
      if (sigwait (&sigalrm_mask, &sig) == -1)
      {
        perror ("sigwait failed");
        free (msg);
        goto fail;
      }
    }
#else
    dds_sleepfor (interval);
#endif
  }

 fail:
  (void) dds_delete (dp);
  return 1;
}
