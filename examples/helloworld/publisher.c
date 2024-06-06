#include "dds/dds.h"
#include "HelloWorldData.h"
#include <stdio.h>
#include <stdlib.h>

//
#include <string.h>
#include <arpa/inet.h>
#include "dds/ddsc/dds_internal_api.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_addrset.h"
#include "dds/ddsi/ddsi_tran.h"

static void add_spdp_address (const dds_entity_t pp, const struct sockaddr_in *ipv4)
{
  struct ddsi_domaingv * const gv = dds_get_domaingv (pp);
  ddsi_locator_t loc;
  memset (&loc, 0, sizeof (loc));
  loc.kind = DDSI_LOCATOR_KIND_UDPv4;
  loc.port = ntohs (ipv4->sin_port);
  memcpy (loc.address + 12, &ipv4->sin_addr, 4);
  ddsi_add_locator_to_addrset (gv, gv->as_disc, &loc);
}
//

int main (int argc, char ** argv)
{
  dds_entity_t participant;
  dds_entity_t topic;
  dds_entity_t writer;
  dds_return_t rc;
  HelloWorldData_Msg msg;
  uint32_t status = 0;
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

  /* Create a Writer. */
  writer = dds_create_writer (participant, topic, NULL, NULL);
  if (writer < 0)
    DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));

  printf("=== [Publisher]  Waiting for a reader to be discovered ...\n");
  fflush (stdout);

  rc = dds_set_status_mask(writer, DDS_PUBLICATION_MATCHED_STATUS);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_set_status_mask: %s\n", dds_strretcode(-rc));

  int count = 0;
  while(!(status & DDS_PUBLICATION_MATCHED_STATUS))
  {
    rc = dds_get_status_changes (writer, &status);
    if (rc != DDS_RETCODE_OK)
      DDS_FATAL("dds_get_status_changes: %s\n", dds_strretcode(-rc));

    /* Polling sleep. */
    dds_sleepfor (DDS_MSECS (20));

    if (++count == 500) // about 10s
    {
      printf ("adding 127.0.0.1:7410\n");
      struct sockaddr_in a;
      memset (&a, 0, sizeof (a));
      a.sin_family = AF_INET;
      a.sin_port = htons (7410);
      inet_aton ("127.0.0.1", &a.sin_addr);
      add_spdp_address (participant, &a);
    }
  }

  /* Create a message to write. */
  msg.userID = 1;
  msg.message = "Hello World";

  printf ("=== [Publisher]  Writing : ");
  printf ("Message (%"PRId32", %s)\n", msg.userID, msg.message);
  fflush (stdout);

  rc = dds_write (writer, &msg);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_write: %s\n", dds_strretcode(-rc));

  /* Deleting the participant will delete all its children recursively as well. */
  rc = dds_delete (participant);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

  return EXIT_SUCCESS;
}
