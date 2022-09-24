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

std::string utils_wlan_hal_whm::security_val(WiFiSec sec)
{
    switch (sec) {
    case WiFiSec::None:
        return "NONE";
    case WiFiSec::WEP_64:
        return "WEP-64";
    case WiFiSec::WEP_128:
        return "WEP-128";
    case WiFiSec::WPA_PSK:
        return "WPA-Personal";
    case WiFiSec::WPA2_PSK:
        return "WPA2-Personal";
    case WiFiSec::WPA_WPA2_PSK:
        return "WPA-WPA2-Personal";

    default:
        return "INVALID";
    }
}

} // namespace whm
} // namespace bwl
