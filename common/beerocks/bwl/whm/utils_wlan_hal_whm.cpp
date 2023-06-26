/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "utils_wlan_hal_whm.h"
#include <easylogging++.h>
#include <unordered_set>

namespace bwl {
namespace whm {
namespace utils_wlan_hal_whm {

eRadioState radio_state_from_string(const std::string &state)
{
    if (state == "Down") {
        return eRadioState::DISABLED;
    } else if (state == "Up" || state == "Dormant") {
        return eRadioState::ENABLED;
    } else {
        return eRadioState::UNKNOWN;
    }
}

eRadioState radio_state_from_bool(const bool flag)
{
    if (flag == false) {
        return eRadioState::DISABLED;
    } else {
        return eRadioState::ENABLED;
    }
}

const std::map<std::string, WiFiSec> security_type_table = {
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

std::string security_type_to_string(const WiFiSec &security_type)
{
    for (const auto &map_it : security_type_table) {
        if (map_it.second == security_type) {
            return map_it.first;
        }
    }
    return "INVALID";
}

WiFiSec security_type_from_string(const std::string &security_type)
{
    auto map_it = security_type_table.find(security_type);
    return map_it == security_type_table.end() ? WiFiSec::Invalid : map_it->second;
}

bwl::eChannelScanResultChannelBandwidth get_bandwidth_from_int(const int32_t bw)
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
eFreqType_to_eCh_scan_Op_Fr_Ba(const beerocks::eFreqType freq_type)
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

std::vector<eChannelScanResultEncryptionMode>
get_scan_result_encryption_modes_from_str(const std::string &encryption_modes_str)
{
    std::vector<eChannelScanResultEncryptionMode> encryption_modes_vect;
    if (encryption_modes_str.find("Default") != std::string::npos) {
        encryption_modes_vect.push_back(bwl::eChannelScanResultEncryptionMode::eEncryption_Mode_NA);
    }
    if (encryption_modes_str.find("AES") != std::string::npos) {
        encryption_modes_vect.push_back(
            bwl::eChannelScanResultEncryptionMode::eEncryption_Mode_AES);
    }
    if (encryption_modes_str.find("TKIP") != std::string::npos) {
        encryption_modes_vect.push_back(
            bwl::eChannelScanResultEncryptionMode::eEncryption_Mode_TKIP);
    }
    return encryption_modes_vect;
}

std::vector<eChannelScanResultStandards>
get_scan_result_operating_standards_from_str(const std::string &standards_str)
{
    std::vector<eChannelScanResultStandards> supported_standards;
    std::unordered_set<std::string>
        all_standards; // split the standards received as a string, mostly to differentiate between a, ac and ax
    const char *delim = ",";
    std::string standards_to_consume(standards_str);
    char *token = strtok(&standards_to_consume[0], delim);
    while (token) {
        all_standards.insert(std::string(token));
        token = strtok(NULL, delim);
    }

    if (all_standards.find("a") != all_standards.end()) {
        supported_standards.push_back(bwl::eChannelScanResultStandards::eStandard_802_11a);
    }
    if (all_standards.find("b") != all_standards.end()) {
        supported_standards.push_back(bwl::eChannelScanResultStandards::eStandard_802_11b);
    }
    if (all_standards.find("g") != all_standards.end()) {
        supported_standards.push_back(bwl::eChannelScanResultStandards::eStandard_802_11g);
    }
    if (all_standards.find("n") != all_standards.end()) {
        supported_standards.push_back(bwl::eChannelScanResultStandards::eStandard_802_11n);
    }
    if (all_standards.find("ac") != all_standards.end()) {
        supported_standards.push_back(bwl::eChannelScanResultStandards::eStandard_802_11ac);
    }
    if (all_standards.find("ax") != all_standards.end()) {
        supported_standards.push_back(bwl::eChannelScanResultStandards::eStandard_802_11ax);
    }
    return supported_standards;
}

std::vector<eChannelScanResultSecurityMode>
get_scan_security_modes_from_str(const std::string &security_modes_str)
{
    std::vector<eChannelScanResultSecurityMode> security_modes;
    if (security_modes_str.find("WEP-") != std::string::npos) {
        security_modes.push_back(bwl::eChannelScanResultSecurityMode::eSecurity_Mode_WEP);
    }
    if (security_modes_str.find("WPA-") != std::string::npos) {
        security_modes.push_back(bwl::eChannelScanResultSecurityMode::eSecurity_Mode_WPA);
    }
    if (security_modes_str.find("WPA2-") != std::string::npos) {
        security_modes.push_back(bwl::eChannelScanResultSecurityMode::eSecurity_Mode_WPA2);
    }
    if (security_modes_str.find("WPA3-") != std::string::npos) {
        security_modes.push_back(bwl::eChannelScanResultSecurityMode::eSecurity_Mode_WPA3);
    }
    return security_modes;
}

} // namespace utils_wlan_hal_whm
} // namespace whm
} // namespace bwl
