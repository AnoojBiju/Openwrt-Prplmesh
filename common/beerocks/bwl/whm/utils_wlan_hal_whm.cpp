/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "utils_wlan_hal_whm.h"
#include <easylogging++.h>

namespace bwl {
namespace whm {

eRadioState utils_wlan_hal_whm::radio_state_from_string(const std::string &state)
{
    if (state == "Down") {
        return eRadioState::DISABLED;
    } else if (state == "Up") {
        return eRadioState::ENABLED;
    } else {
        return eRadioState::UNKNOWN;
    }
}

const std::map<std::string, WiFiSec> utils_wlan_hal_whm::security_type_table = {
    {"INVALID", WiFiSec::Invalid},
    {"None", WiFiSec::None},
    {"WEP-64", WiFiSec::WEP_64},
    {"WEP-128", WiFiSec::WEP_128},
    {"WPA-Personal", WiFiSec::WPA_PSK},
    {"WPA2-Personal", WiFiSec::WPA2_PSK},
    {"WPA-WPA2-Personal", WiFiSec::WPA_WPA2_PSK},
    {"WPA2-WPA3-Personal", WiFiSec::WPA2_WP3_PSK},
    {"WPA3-Personal", WiFiSec::WPA3_PSK},
};

std::string utils_wlan_hal_whm::security_type_to_string(const WiFiSec &security_type)
{
    for (const auto &map_it : security_type_table) {
        if (map_it.second == security_type) {
            return map_it.first;
        }
    }
    return "INVALID";
}

WiFiSec utils_wlan_hal_whm::security_type_from_string(const std::string &security_type)
{
    auto map_it = security_type_table.find(security_type);
    return map_it == security_type_table.end() ? WiFiSec::Invalid : map_it->second;
}

} // namespace whm
} // namespace bwl
