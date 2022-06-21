//#ifndef _TEST_TEAMS_MEMBERS_H_
//#define _TEST_TEAMS_MEMBERS_H_
#include "tlvf/CmduMessageRx.h"
#include "tlvf/CmduMessageTx.h"
#include "tlvf/tlvftypes.h"
#include "tlvf/wfa_map/tlvTeamMembers.h"

using namespace ieee1905_1;
using namespace wfa_map;

uint8_t build_cmdu(uint8_t *buffer, size_t len);
void parse_and_print_cmdu(uint8_t *buffer, size_t len);
//#endif
