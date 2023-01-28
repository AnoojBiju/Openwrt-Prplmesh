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

bwl::eChannelScanResultChannelBandwidth utils_wlan_hal_whm::get_bandwidth_from_int(const int32_t bw)
{
    using namespace bwl;
    if (bw == 20) {
        return eChannelScanResultChannelBandwidth::eChannel_Bandwidth_20MHz;
    } else if (bw == 40) {
        return eChannelScanResultChannelBandwidth::eChannel_Bandwidth_40MHz;
    } else if (bw == 80) {
        return eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80MHz;
    } else if (bw == 160) {
        return eChannelScanResultChannelBandwidth::eChannel_Bandwidth_160MHz;
    } else {
        return bwl::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_NA;
    }
}

bwl::eChannelScanResultOperatingFrequencyBand
utils_wlan_hal_whm::eFreqType_to_eCh_scan_Op_Fr_Ba(const beerocks::eFreqType freq_type)
{
    using namespace beerocks;
    switch (freq_type) {
    case FREQ_24G: {
        return bwl::eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_2_4GHz;
    }
    case FREQ_5G: {
        return bwl::eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_5GHz;
    }
    case FREQ_24G_5G: {
        return bwl::eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_2_4GHz;
    }
    default: {
        return bwl::eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_NA;
    }
    }
};

} // namespace whm
} // namespace bwl
