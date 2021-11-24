#ifndef _TEST_TEAMS_MEMBERS_H_
#define _TEST_TEAMS_MEMBERS_H_
#include "tlvf/CmduMessageRx.h"
#include "tlvf/CmduMessageTx.h"
#include "tlvf/tlvftypes.h"
#include "tlvf/wfa_map/tlvTeamsMembers.h"
#include <mapf/common/logger.h>

using namespace ieee1905_1;
using namespace wfa_map;

uint8_t test_teams_members_build(uint8_t *tx_buffer, size_t len);
void test_teams_members_parse(uint8_t *tx_buffer, size_t len);
#endif
