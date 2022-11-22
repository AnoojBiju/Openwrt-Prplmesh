/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef __BWL_NL80211_USLM_UTILS_H__
#define __BWL_NL80211_USLM_UTILS_H__

#include <string>
#include <vector>

#include "bwl/base_wlan_hal_types.h"
#include "uslm_messages.h"

class uslm_utils {
public:
    /**
     * @brief Sends a message to the USLM server to register a new STA of interest.
     * 
     * @param sta_mac The STA MAC to ask the server to collect metrics for.
     * @param fd The file descriptor to write over.
     * @return true on success
     * @return false on failure
     */
    static bool send_sta_link_metrics_request_message(const std::string &sta_mac, int fd);

    /**
     * @brief Sends a message to the USLM server to fetch STA stats.
     * 
     * @param sta_mac The STA MAC to request stats for.
     * @param fd The file descriptor to write over.
     * @return true on success
     * @return false on failure
     */
    static bool send_register_sta_message(const std::string &sta_mac, int fd);

    /**
     * @brief Sends a message to the USLM server to unregister a STA.
     * 
     * @param sta_mac The STA to stop listening for.
     * @param fd The file descriptor to write over.
     * @return true on success
     * @return false on failure
     */
    static bool send_unregister_sta_message(const std::string &sta_mac, int fd);

    /**
     * @brief Parse station link metric stats from a binary blob.
     * 
     * @param buf The raw response data.
     * @param buflen The length of the raw response data, in bytes.
     * @param stats_out The struct to write link metrics data to.
     * @return true on successful parsing (stats_out will be populated)
     * @return false on failure (stats_out will not be populated, and may contain garbage data)
     */
    static bool parse_station_stats_from_buf(const uint8_t *buf, size_t buflen,
                                             bwl::sUnassociatedStationStats &stats_out);

    static error_code_t get_response_error_code(const response &);

private:
    static bool send_message(const std::string &mac, int fd, message_type_t message_type);
};

#endif // __BWL_NL80211_USLM_UTILS_H__
