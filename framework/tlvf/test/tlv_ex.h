#ifndef TLV_EX_H_
#define TLV_EX_H_

#include <iostream>

/**
 * @brief Build a CMDU which of type TEAM_MEMBERS_MESSAGE and fill
 * it with TLV of type tlvTeamsMember. The values of the TLV are
 * arbitrary.
 * 
 * @return 0 on success, -1 on fail. 
 */
int build_cmdu();


#endif
