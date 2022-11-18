/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "wbapi_utils.h"

namespace beerocks {
namespace wbapi {

const std::map<std::string, beerocks::eWiFiBandwidth> wbapi_utils::band_width_table = {
    {"20MHz", beerocks::eWiFiBandwidth::BANDWIDTH_20},
    {"40MHz", beerocks::eWiFiBandwidth::BANDWIDTH_40},
    {"80MHz", beerocks::eWiFiBandwidth::BANDWIDTH_80},
    {"160MHz", beerocks::eWiFiBandwidth::BANDWIDTH_160},
};

beerocks::eWiFiBandwidth wbapi_utils::bandwith_from_string(const std::string &bandwidth)
{
    auto map_it = band_width_table.find(bandwidth);
    if (map_it != band_width_table.end()) {
        return map_it->second;
    }
    LOG(WARNING) << "not Supported bandwidth value: " << bandwidth;
    return beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN;
}

const std::map<std::string, std::pair<std::string, beerocks::eFreqType>>
    wbapi_utils::band_freq_table = {
        {"2.4GHz", {"24g", beerocks::eFreqType::FREQ_24G}},
        {"5GHz", {"5g", beerocks::eFreqType::FREQ_5G}},
        {"6GHz", {"6g", beerocks::eFreqType::FREQ_6G}},
};

beerocks::eFreqType wbapi_utils::band_to_freq(const std::string &band)
{
    auto map_it = band_freq_table.find(band);
    if (map_it != band_freq_table.end()) {
        return map_it->second.second;
    }
    LOG(WARNING) << "not Supported FreqBand value: " << band;
    return beerocks::eFreqType::FREQ_UNKNOWN;
}

std::string wbapi_utils::band_short_name(const std::string &band)
{
    auto map_it = band_freq_table.find(band);
    if (map_it != band_freq_table.end()) {
        return map_it->second.first;
    }
    LOG(WARNING) << "not Supported FreqBand value: " << band;
    return "";
}

const std::map<std::string, std::vector<WSC::eWscAuth>> wbapi_utils::security_mode_table = {
    {"None", {WSC::eWscAuth::WSC_AUTH_OPEN}},
    {"WPA-Personal", {WSC::eWscAuth::WSC_AUTH_WPAPSK, WSC::eWscAuth::WSC_AUTH_WPA}},
    {"WPA2-Personal", {WSC::eWscAuth::WSC_AUTH_WPA2PSK, WSC::eWscAuth::WSC_AUTH_WPA2}},
    {"WPA-WPA2-Personal",
     {WSC::eWscAuth(WSC::eWscAuth::WSC_AUTH_WPA2PSK | WSC::eWscAuth::WSC_AUTH_WPAPSK)}},
    {"WPA2-WPA3-Personal",
     {WSC::eWscAuth(WSC::eWscAuth::WSC_AUTH_WPA2PSK | WSC::eWscAuth::WSC_AUTH_SAE)}},
    {"WPA3-Personal", {WSC::eWscAuth::WSC_AUTH_SAE}},
};

std::string wbapi_utils::security_mode_to_string(const WSC::eWscAuth &security_mode)
{
    auto map_it =
        std::find_if(security_mode_table.begin(), security_mode_table.end(),
                     [&](const std::pair<std::string, std::vector<WSC::eWscAuth>> &element) {
                         auto secMode_it =
                             std::find(element.second.begin(), element.second.end(), security_mode);
                         return (secMode_it != element.second.end());
                     });
    if (map_it != security_mode_table.end()) {
        return map_it->first;
    }
    return "None";
}

WSC::eWscAuth wbapi_utils::security_mode_from_string(const std::string &security_mode)
{
    auto map_it = security_mode_table.find(security_mode);
    if (map_it != security_mode_table.end()) {
        return map_it->second.at(0);
    }
    return WSC::eWscAuth::WSC_AUTH_OPEN;
}

const std::map<std::string, std::vector<WSC::eWscEncr>> wbapi_utils::encryption_type_table = {
    {"AES", {WSC::eWscEncr::WSC_ENCR_AES}},
    {"TKIP", {WSC::eWscEncr::WSC_ENCR_TKIP}},
    {"TKIP-AES", {WSC::eWscEncr::WSC_ENCR_AES}},
};

std::string wbapi_utils::encryption_type_to_string(const WSC::eWscEncr &encryption_type)
{
    auto map_it =
        std::find_if(encryption_type_table.begin(), encryption_type_table.end(),
                     [&](const std::pair<std::string, std::vector<WSC::eWscEncr>> &element) {
                         auto secType_it = std::find(element.second.begin(), element.second.end(),
                                                     encryption_type);
                         return (secType_it != element.second.end());
                     });
    if (map_it != encryption_type_table.end()) {
        return map_it->first;
    }
    return "Default";
}

WSC::eWscEncr wbapi_utils::encryption_type_from_string(const std::string &encryption_type)
{
    auto map_it = encryption_type_table.find(encryption_type);
    if (map_it != encryption_type_table.end()) {
        return map_it->second.at(0);
    }
    return WSC::eWscEncr::WSC_ENCR_NONE;
}

int wbapi_utils::get_object_id(const std::string &object_path)
{
    auto str = object_path;
    if (str.back() == '.') {
        str.pop_back();
    }
    auto pos = str.rfind('.');
    if (pos == std::string::npos) {
        return 0;
    }
    auto token = str.substr(pos + 1);
    if (token.find_first_not_of("0123456789") != std::string::npos) {
        return 0;
    }
    return stoi(token);
}

std::string wbapi_utils::search_path_wifi() { return std::string("WiFi."); }

std::string wbapi_utils::search_path_radio() { return search_path_wifi() + "Radio."; }

std::string wbapi_utils::search_path_ssid() { return search_path_wifi() + "SSID."; }

std::string wbapi_utils::search_path_ap() { return search_path_wifi() + "AccessPoint."; }

std::string wbapi_utils::search_path_ep() { return search_path_wifi() + "EndPoint."; }

std::string wbapi_utils::search_path_radio_iface() { return search_path_radio() + "*.Name"; }

std::string wbapi_utils::search_path_radio_by_iface(const std::string &rad_ifname)
{
    return search_path_radio() + "[Name == '" + rad_ifname + "'].";
}

std::string wbapi_utils::search_path_ssid_iface() { return search_path_ssid() + "*.Name"; }

std::string wbapi_utils::search_path_ssid_by_iface(const std::string &ssid_ifname)
{
    return search_path_ssid() + "[Name == '" + ssid_ifname + "'].";
}

std::string wbapi_utils::search_path_ssid_by_bssid(const std::string &bssid)
{
    std::string macLc(bssid);
    std::transform(macLc.begin(), macLc.end(), macLc.begin(), ::tolower);
    std::string macUc(bssid);
    std::transform(macUc.begin(), macUc.end(), macUc.begin(), ::toupper);
    return search_path_ssid() + "[BSSID == '" + macLc + "' || BSSID == '" + macUc + "'].";
}

std::string wbapi_utils::search_path_ssid_iface_by_bssid(const std::string &bssid)
{
    return search_path_ssid_by_bssid(bssid) + "Name";
}

std::string wbapi_utils::search_path_ap_iface() { return search_path_ssid() + "*.Alias"; }

std::string wbapi_utils::search_path_ap_by_iface(const std::string &vap_ifname)
{
    return search_path_ap() + "[Alias == '" + vap_ifname + "'].";
}

std::string wbapi_utils::search_path_ap_by_radRef(const std::string &radioRef)
{
    return search_path_ap() + "[RadioReference == '" + radioRef + "'].";
}

std::string wbapi_utils::search_path_ap_iface_by_radRef(const std::string &radioRef)
{
    return search_path_ap_by_radRef(radioRef) + "Alias";
}

std::string wbapi_utils::search_path_assocDev_by_mac(const std::string &vap_ifname,
                                                     const std::string &mac)
{
    std::string macLc(mac);
    std::transform(macLc.begin(), macLc.end(), macLc.begin(), ::tolower);
    std::string macUc(mac);
    std::transform(macUc.begin(), macUc.end(), macUc.begin(), ::toupper);
    return search_path_ap_by_iface(vap_ifname) + "AssociatedDevice." + "[MACAddress == '" + macLc +
           "' || MACAddress == '" + macUc + "'].";
}

std::string wbapi_utils::search_path_mac_filtering(const std::string &vap_ifname)
{
    return search_path_ap_by_iface(vap_ifname) + "MACFiltering.";
}

std::string wbapi_utils::search_path_mac_filtering_entry_by_mac(const std::string &vap_ifname,
                                                                const std::string &mac)
{
    std::string macLc(mac);
    std::transform(macLc.begin(), macLc.end(), macLc.begin(), ::tolower);
    std::string macUc(mac);
    std::transform(macUc.begin(), macUc.end(), macUc.begin(), ::toupper);
    return search_path_mac_filtering(vap_ifname) + "Entry." + "[MACAddress == '" + macLc +
           "' || MACAddress == '" + macUc + "'].";
}

std::string wbapi_utils::search_path_ep_by_iface(const std::string &ep_ifname)
{
    return search_path_ep() + "[IntfName == '" + ep_ifname + "'].";
}

std::string wbapi_utils::search_path_ep_profiles_by_iface(const std::string &ep_ifname)
{
    return search_path_ep_by_iface(ep_ifname) + "Profile.";
}

std::string wbapi_utils::search_path_ep_profile_by_id(const std::string &ep_ifname,
                                                      uint32_t profile_id)
{
    return search_path_ep_profiles_by_iface(ep_ifname) + std::to_string(profile_id) + ".";
}

std::string wbapi_utils::get_path_ap_of_assocDev(const std::string &assocDev_path)
{
    auto pos = assocDev_path.rfind("AssociatedDevice");
    if (pos == std::string::npos) {
        return "";
    }
    return assocDev_path.substr(0, pos);
}

std::string wbapi_utils::get_path_radio_iface(const std::string &radio_path)
{
    if (!radio_path.empty()) {
        return radio_path + "Name";
    }
    return "";
}

std::string wbapi_utils::get_path_ap_iface(const std::string &ap_path)
{
    if (!ap_path.empty()) {
        return ap_path + "Alias";
    }
    return "";
}

std::string wbapi_utils::get_path_radio_reference(const AmbiorixVariant &obj)
{
    std::string value;
    if (obj.read_child<>(value, "RadioReference")) {
        value += ".";
    }
    return value;
}

std::string wbapi_utils::get_path_ssid_reference(const AmbiorixVariant &obj)
{
    std::string value;
    if (obj.read_child<>(value, "SSIDReference")) {
        value += ".";
    }
    return value;
}

std::string wbapi_utils::get_ap_iface(const AmbiorixVariant &obj)
{
    std::string value;
    obj.read_child<>(value, "Alias");
    return value;
}

std::string wbapi_utils::get_ap_status(const AmbiorixVariant &obj)
{
    std::string value;
    obj.read_child<>(value, "Status");
    return value;
}

std::string wbapi_utils::get_ssid_mac(const AmbiorixVariant &obj)
{
    std::string macLc;
    if (obj.read_child<>(macLc, "MACAddress")) {
        std::transform(macLc.begin(), macLc.end(), macLc.begin(), ::tolower);
    }
    return macLc;
}

std::string wbapi_utils::get_radio_iface(const AmbiorixVariant &obj)
{
    std::string value;
    obj.read_child<>(value, "Name");
    return value;
}

std::string wbapi_utils::get_ssid_iface(const AmbiorixVariant &obj)
{
    std::string value;
    obj.read_child<>(value, "Name");
    return value;
}

std::string wbapi_utils::get_ep_iface(const AmbiorixVariant &obj)
{
    std::string value;
    obj.read_child<>(value, "IntfName");
    return value;
}

} // namespace wbapi
} // namespace beerocks
