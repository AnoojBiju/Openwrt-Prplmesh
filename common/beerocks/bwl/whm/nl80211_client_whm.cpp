/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "nl80211_client_whm.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

namespace bwl {

bool nl80211_client_whm::get_interfaces(std::vector<std::string> &interfaces)
{
    interfaces.clear();
    return false;
}

bool nl80211_client_whm::get_interface_info(const std::string &interface_name,
                                            interface_info &interface_info)
{
    return false;
}

bool nl80211_client_whm::get_radio_info(const std::string &interface_name, radio_info &radio_info)
{
    return false;
}

bool nl80211_client_whm::get_sta_info(const std::string &interface_name,
                                      const sMacAddr &sta_mac_address, sta_info &sta_info)
{
    return false;
}

bool nl80211_client_whm::get_survey_info(const std::string &interface_name, SurveyInfo &survey_info)
{
    return false;
}

bool nl80211_client_whm::set_tx_power_limit(const std::string &interface_name, uint32_t limit)
{
    return false;
}

bool nl80211_client_whm::get_tx_power_dbm(const std::string &interface_name, uint32_t &power)
{
    return false;
}

bool nl80211_client_whm::channel_scan_abort(const std::string &interface_name) { return false; }

bool nl80211_client_whm::add_key(const std::string &interface_name, const sKeyInfo &key_info)
{
    return false;
}

bool nl80211_client_whm::add_station(const std::string &interface_name, const sMacAddr &mac,
                                     assoc_frame::AssocReqFrame &assoc_req, uint16_t aid)
{
    return false;
}

} // namespace bwl
