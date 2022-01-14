#include <stdio.h>
#include <stdlib.h>
#include "dds/dds.h"
#include "Pipeline.h"
#include "common.h"

int main (int argc, char ** argv)
{
  dds_return_t rc;

  if (argc != 2)
  {
    printf ("usage: %s topic\n", argv[0]);
    return 2;
  }

  const dds_entity_t dp = dds_create_participant (DDS_DOMAIN_DEFAULT, NULL, NULL);
  if (dp < 0)
  {
    fprintf (stderr, "failed to create participant: %s\n", dds_strretcode (dp));
    return 1;
  }

  const dds_entity_t rtp = create_topic (dp, argv[1]);
  if (rtp < 0)
  {
    fprintf (stderr, "failed to create topic %s: %s\n", argv[1], dds_strretcode (rtp));
    goto fail;
  }
  const dds_entity_t rd = dds_create_reader (dp, rtp, NULL, NULL);
  if (rd < 0)
  {
    fprintf (stderr, "failed to create reader for topic %s: %s\n", argv[1], dds_strretcode (rd));
    goto fail;
  }
  const dds_entity_t rdcond = dds_create_readcondition (rd, DDS_ANY_STATE);
  if (rdcond < 0)
  {
    fprintf (stderr, "failed to create read condition for topic %s: %s\n", argv[1], dds_strretcode (rd));
    goto fail;
  }

  const dds_entity_t ws = dds_create_waitset (dp);
  if ((rc = dds_waitset_attach (ws, rdcond, 0)) < 0)
  {
    fprintf (stderr, "failed to attach reader topic %s read condition to waitset: %s\n", argv[1], dds_strretcode (rc));
    goto fail;
  }

#define N 1
  void *ptr[N] = { NULL };
  dds_sample_info_t si[N];
  dds_time_t tstart = dds_time ();
  while (1)
  {
    if ((rc = dds_waitset_wait (ws, NULL, 0, DDS_INFINITY)) < 0)
    {
      fprintf (stderr, "waitset_wait failed: %s\n", dds_strretcode (rc));
      goto fail;
    }

    const int32_t n = dds_take (rdcond, ptr, si, N, N);
    if (n < 0)
    {
      fprintf (stderr, "take failed: %s\n", dds_strretcode (rc));
      goto fail;
    }
    for (int32_t i = 0; i < n; i++)
    {
      if (si[i].valid_data)
      {
        Pipeline_Msg * const msg = ptr[i];
        printf ("%f %u\n", (dds_time () - tstart) / 1e9, (unsigned) msg->seqno);
        fflush (stdout);
      }
    }
    if ((rc = dds_return_loan (rd, ptr, n)) < 0)
    {
      fprintf (stderr, "return_loan failed: %s\n", dds_strretcode (rc));
      goto fail;
    }
  }

 fail:
  (void) dds_delete (dp);
  return 1;
}
