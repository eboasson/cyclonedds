#include "dds/dds.h"
#include "HelloWorldData.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* An array of one message (aka sample in dds terms) will be used. */
#define MAX_SAMPLES 8
#define SUB_PREFIX "===[Subscriber] "

int main (int argc, char ** argv)
{
  dds_entity_t participant;
  dds_entity_t topic;
  dds_entity_t reader;
  HelloWorldData_Msg *msg;
  void *samples[MAX_SAMPLES];
  dds_sample_info_t infos[MAX_SAMPLES];
  dds_return_t rc;
  (void)argc;
  (void)argv;

  /* Create a Participant. */
  participant = dds_create_participant (DDS_DOMAIN_DEFAULT, NULL, NULL);
  if (participant < 0)
    DDS_FATAL("dds_create_participant: %s\n", dds_strretcode(-participant));

  /* Create a Topic. */
  topic = dds_create_topic (
    participant, &HelloWorldData_Msg_desc, "HelloWorldData_Msg", NULL, NULL);
  if (topic < 0)
    DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topic));

  /* Create a reliable Reader. */
  dds_qos_t *qos = dds_create_qos();
  dds_qset_history (qos, DDS_HISTORY_KEEP_LAST, 2);
  dds_qset_reliability (qos, DDS_RELIABILITY_BEST_EFFORT, DDS_SECS (0));
  reader = dds_create_reader (participant, topic, qos, NULL);
  dds_delete_qos(qos);
  if (reader < 0)
    DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));

  printf (SUB_PREFIX "Waiting for a sample ...\n");
  fflush (stdout);

  samples[0] = NULL;

  /* Poll until data has been read. */
  int sequential_sleeps = 0;
  int msgsread = 0;
  while (true)
  {
    /* Do the actual read.
     * The return value contains the number of read samples. */
    rc = dds_read (reader, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
    if (rc < 0) {
      DDS_FATAL("dds_read: %s\n", dds_strretcode(-rc));
    }

    /* Check if we read some data and it is valid. */
    for (int32_t i = 0; i < rc; i++)
    {
      if (infos[i].valid_data && infos[i].sample_state == DDS_NOT_READ_SAMPLE_STATE)
      {
        /* Print Message. */
        msg = (HelloWorldData_Msg*) samples[i];
        printf (SUB_PREFIX "Message: %p (a = %8d, b = %8d, c = %8d, s = \"%s\")\n", msg, msg->a, msg->b, msg->c, msg->s);
        fflush (stdout);
        msgsread++;
        sequential_sleeps = 0;
      }
    }

    /*if (rc > 0)
      dds_return_loan(reader, samples, rc);*/


    /* Polling sleep. */
    dds_sleepfor (DDS_MSECS (500));
    if (msgsread && ++sequential_sleeps > 5) {
      printf (SUB_PREFIX "Done waiting for data after %d messages.\n", msgsread);
      break;
    }
  }

  printf (SUB_PREFIX "Done reading, cleaning up.\n");

  /* Deleting the participant will delete all its children recursively as well. */
  rc = dds_delete (participant);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

  printf (SUB_PREFIX "Finished, exiting.\n");

  return EXIT_SUCCESS;
}
