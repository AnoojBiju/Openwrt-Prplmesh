//#ifndef _TEST_TEAMS_MEMBERS_H_
//#define _TEST_TEAMS_MEMBERS_H_
#include "tlvf/wfa_map/tlvTeamsMembers.h"
#include <asm/byteorder.h>
#include <cstddef>
#include <mapf/common/logger.h>
#include <memory>
#include <ostream>
#include <stdint.h>
#include <string.h>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tlvf/swap.h>
#include <tuple>
#include <vector>

uint8_t test_teams_members_build(uint8_t *tx_buffer, size_t len);
void test_teams_members_parse(uint8_t *tx_buffer, size_t len);
int test_teams_members_using_cmdu(void);

//#endif //_TEST_TEAMS_MEMBERS_H_
