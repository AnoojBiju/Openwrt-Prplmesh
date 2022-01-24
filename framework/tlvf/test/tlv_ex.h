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

/**
 * @brief Parses TEAM_MEMBERS_MESSAGE and print it's content.
 * 
 * @param rx_buf a buffer which contains raw CMDU message
 * @param buf_len the length of the buffer
 * @return 0 on success, -1 on fail
 */
int parse_and_print_cmdu(uint8_t *rx_buf, size_t buf_len);

#endif
