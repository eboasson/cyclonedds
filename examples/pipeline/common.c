#include "dds/dds.h"
#include "Pipeline.h"
#include "common.h"

dds_entity_t create_topic (dds_entity_t dp, const char *name)
{
  dds_qos_t * const tpqos = dds_create_qos ();
  dds_qset_reliability (tpqos, DDS_RELIABILITY_RELIABLE, DDS_SECS (1));
  dds_qset_history (tpqos, DDS_HISTORY_KEEP_LAST, 3);
  const dds_entity_t tp = dds_create_topic (dp, &Pipeline_Msg_desc, name, tpqos, NULL);
  dds_delete_qos (tpqos);
  return tp;
}
