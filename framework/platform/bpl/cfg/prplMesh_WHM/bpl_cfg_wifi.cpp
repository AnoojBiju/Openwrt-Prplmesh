/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "../common/utils/utils.h"
#include "../common/utils/utils_net.h"
#include <bcl/beerocks_string_utils.h>
#include <bpl/bpl_cfg.h>
#include <mapf/common/logger.h>
#include <mapf/common/utils.h>

#include <tlvf/WSC/eWscAuth.h>
#include <tlvf/WSC/eWscEncr.h>

#include "bpl_cfg_pwhm.h"

using namespace mapf;
using namespace beerocks;
using namespace wbapi;

namespace beerocks {
namespace bpl {

static AmbiorixVariantSmartPtr bpl_cfg_get_wifi_ssid_object(const std::string &iface)
{
    return m_ambiorix_cl.get_object(wbapi_utils::search_path_ssid_by_iface(iface));
}

static AmbiorixVariantSmartPtr bpl_cfg_get_wifi_radio_object(const std::string &rad_iface)
{
    return m_ambiorix_cl.get_object(wbapi_utils::search_path_radio_by_iface(rad_iface));
}

static AmbiorixVariantSmartPtr bpl_cfg_get_wifi_radio_object(const AmbiorixVariant &ap_obj)
{
    return m_ambiorix_cl.get_object(wbapi_utils::get_path_radio_reference(ap_obj));
}

static AmbiorixVariantSmartPtr bpl_cfg_get_wifi_security_object(const std::string &iface)
{
    return m_ambiorix_cl.get_object(wbapi_utils::search_path_ap_by_iface(iface) + "Security.");
}

int cfg_get_all_prplmesh_wifi_interfaces(BPL_WLAN_IFACE *interfaces, int *num_of_interfaces)
{
    if (!interfaces) {
        MAPF_ERR("cfg_get_all_prplmesh_wifi_interfaces: invalid input: interfaces is nullptr");
        return RETURN_ERR;
    }
    if (!num_of_interfaces) {
        MAPF_ERR(
            "cfg_get_all_prplmesh_wifi_interfaces: invalid input: num_of_interfaces is nullptr");
        return RETURN_ERR;
    }
    if (*num_of_interfaces < 1) {
        MAPF_ERR(
            "cfg_get_all_prplmesh_wifi_interfaces: invalid input: max num_of_interfaces value < 1");
        return RETURN_ERR;
    }

    int interfaces_count = 0;

    // pwhm dm path: WiFi.Radio.*.Name?
    auto radios = m_ambiorix_cl.get_object_multi<AmbiorixVariantMapSmartPtr>(
        wbapi_utils::search_path_radio_iface());
    if (radios) {
        for (auto const &it : *radios) {
            auto &radio = it.second;
            auto ifname = wbapi_utils::get_radio_iface(radio);
            if (ifname.empty()) {
                continue;
            }
            mapf::utils::copy_string(interfaces[interfaces_count].ifname, ifname.c_str(),
                                     BPL_IFNAME_LEN);
            interfaces[interfaces_count].radio_num = interfaces_count;
            interfaces_count++;
        }
    }

    *num_of_interfaces = interfaces_count;

    return RETURN_OK;
}

int cfg_get_wifi_params(const char iface[BPL_IFNAME_LEN], struct BPL_WLAN_PARAMS *wlan_params)
{
    if (!iface || !wlan_params) {
        MAPF_ERR("cfg_get_wifi_params: invalid input: iface = "
                 << intptr_t(iface) << " wlan_params = " << intptr_t(wlan_params));
        return RETURN_ERR;
    }

    auto radio_obj = bpl_cfg_get_wifi_radio_object(iface);
    if (!radio_obj) {
        return RETURN_ERR;
    }

    radio_obj->read_child(wlan_params->enabled, "Enable");
    radio_obj->read_child(wlan_params->channel, "Channel");

    bool ieee80211h_supported = false;
    radio_obj->read_child(ieee80211h_supported, "IEEE80211hSupported");
    bool ieee80211h_enabled = false;
    radio_obj->read_child(ieee80211h_enabled, "IEEE80211hEnabled");
    wlan_params->sub_band_dfs = ieee80211h_supported && ieee80211h_enabled;

    std::string country_code;
    if (radio_obj->read_child(country_code, "RegulatoryDomain")) {
        wlan_params->country_code[0] = country_code.at(0);
        wlan_params->country_code[1] = country_code.at(1);
        wlan_params->country_code[2] = '\0';
    }

    return RETURN_OK;
}

bool bpl_cfg_get_wireless_settings(std::list<son::wireless_utils::sBssInfoConf> &wireless_settings)
{
    auto aps =
        m_ambiorix_cl.get_object_multi<AmbiorixVariantMapSmartPtr>(wbapi_utils::search_path_ap());
    if (!aps) {
        return false;
    }

    for (auto const &it : *aps) {
        auto &ap   = it.second;
        auto iface = wbapi_utils::get_ap_iface(ap);
        if (iface.empty()) {
            continue;
        }
        son::wireless_utils::sBssInfoConf configuration;
        auto radio_obj = bpl_cfg_get_wifi_radio_object(ap);
        if (radio_obj) {
            std::string band_str;
            if (radio_obj->read_child(band_str, "OperatingFrequencyBand")) {
                band_str = wbapi_utils::band_short_name(band_str);
            }
            configuration.operating_class = son::wireless_utils::string_to_wsc_oper_class(band_str);
        }

        std::string multi_ap_type_str;
        if (ap.read_child(multi_ap_type_str, "MultiAPType")) {
            if (multi_ap_type_str.find("FronthaulBSS") != std::string::npos) {
                configuration.fronthaul = true;
            }
            if (multi_ap_type_str.find("BackhaulBSS") != std::string::npos) {
                configuration.backhaul = true;
            }
        }
        bool ap_enable = false;
        ap.read_child(ap_enable, "Enable");
        if (ap_enable && bpl_cfg_get_wifi_credentials(iface, configuration)) {
            LOG(DEBUG) << "add " << configuration.ssid << " to wireless settings size "
                       << wireless_settings.size() << " path " << it.first;
            wireless_settings.push_back(configuration);
        } else {
            LOG(DEBUG) << " ap " << it.first << " is disabled";
        }
    }

    return true;
}

bool bpl_cfg_get_wifi_credentials(const std::string &iface,
                                  son::wireless_utils::sBssInfoConf &configuration)
{
    auto ssid_obj = bpl_cfg_get_wifi_ssid_object(iface);
    if (!ssid_obj) {
        LOG(ERROR) << "Failed to get ssid obj of iface " << iface;
        return false;
    }

    auto ap_sec_obj = bpl_cfg_get_wifi_security_object(iface);
    if (!ap_sec_obj) {
        return false;
    }

    configuration.bssid = tlvf::mac_from_string(wbapi_utils::get_ssid_mac(*ssid_obj));
    ssid_obj->read_child(configuration.ssid, "SSID");

    std::string mode_enabled;
    if (ap_sec_obj->read_child(mode_enabled, "ModeEnabled")) {
        configuration.authentication_type = wbapi_utils::security_mode_from_string(mode_enabled);
    }

    std::string encryption_mode;
    if (ap_sec_obj->read_child(encryption_mode, "EncryptionMode")) {
        configuration.encryption_type = wbapi_utils::encryption_type_from_string(encryption_mode);
    }

    std::string key_pass_phrase;
    if (ap_sec_obj->read_child(key_pass_phrase, "KeyPassPhrase")) {
        configuration.network_key = key_pass_phrase;
    }

    return true;
}

bool bpl_cfg_set_wifi_credentials(const std::string &iface,
                                  const son::wireless_utils::sBssInfoConf &configuration)
{
    std::string wifi_ssid_path = wbapi_utils::search_path_ssid_by_iface(iface);
    AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
    new_obj.add_child("SSID", configuration.ssid);
    bool ret = m_ambiorix_cl.update_object(wifi_ssid_path, new_obj);

    // update WiFi.SSID.iface. object
    if (!ret) {
        MAPF_ERR("Failed to update WiFi.SSID.iface. object " << wifi_ssid_path);
        return false;
    }

    auto security_mode   = wbapi_utils::security_mode_to_string(configuration.authentication_type);
    auto encryption_type = wbapi_utils::encryption_type_to_string(configuration.encryption_type);

    std::string wifi_ap_sec_path = wbapi_utils::search_path_ap_by_iface(iface) + "Security.";
    new_obj.set_type(AMXC_VAR_ID_HTABLE);
    new_obj.add_child("ModeEnabled", security_mode);
    new_obj.add_child("EncryptionMode", encryption_type);
    new_obj.add_child("KeyPassPhrase", configuration.network_key);
    ret = m_ambiorix_cl.update_object(wifi_ap_sec_path, new_obj);

    // update WiFi.AccessPoint.iface.Security. object
    if (!ret) {
        MAPF_ERR("Failed to update WiFi.AccessPoint.iface.Security. object" << wifi_ap_sec_path);
        return false;
    }

    return true;
}

bool bpl_cfg_get_mandatory_interfaces(std::string &mandatory_interfaces)
{

    // For pHWM implementation this feature is not used.
    // This means we will not create son_slaves for currently-not-existing interfaces.
    mandatory_interfaces.clear();

    return true;
}

int cfg_get_sta_iface(const char iface[BPL_IFNAME_LEN], char sta_iface[BPL_IFNAME_LEN])
{
    if (!iface || !sta_iface) {
        MAPF_ERR("cfg_get_sta_iface: invalid input: iface or sta_iface are NULL");
        return RETURN_ERR;
    }

    // Get the current radio reference for the given iface
    std::string radio_path;
    if (!m_ambiorix_cl.resolve_path(wbapi_utils::search_path_radio_by_iface(iface), radio_path)) {
        return RETURN_ERR;
    }

    // Find the endpoint that its radioreference is the current one
    auto result =
        m_ambiorix_cl.get_object_multi<AmbiorixVariantMapSmartPtr>(wbapi_utils::search_path_ep());
    if (!result) {
        return false;
    }
    std::string ep_radio_path;
    std::string ep_ifname;
    for (auto &it : *result) {
        auto &ep = it.second;
        if ((ep.empty()) ||
            !(m_ambiorix_cl.resolve_path(wbapi_utils::get_path_radio_reference(ep),
                                         ep_radio_path)) ||
            (ep_radio_path != radio_path) || !(ep.read_child(ep_ifname, "IntfName"))) {
            continue;
        }

        // The sta iface is the value of the endpoint IntfName field
        // Ex: WiFi.EndPoint.ep5g0.IntfName="wlan1"
        mapf::utils::copy_string(sta_iface, ep_ifname.c_str(), BPL_IFNAME_LEN);
        return RETURN_OK;
    }

    return RETURN_ERR;
}

void cfg_wifi_reset_wps_credentials()
{

    std::vector<std::string> endpoint_paths, profile_paths;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);

    const std::string aux_alias = "reset_aux";

    // create new auxiliary profiles for all EndPoint instances
    m_ambiorix_cl.resolve_path_multi("WiFi.EndPoint.*.", endpoint_paths);

    int profile_id = -1;

    for (const auto &endpoint : endpoint_paths) {
        args.set_type(AMXC_VAR_ID_HTABLE);
        args.add_child("Alias", aux_alias);
        m_ambiorix_cl.add_instance(endpoint + ".Profile.", args, profile_id);
        LOG(DEBUG) << "add aux profile " << endpoint;
    }

    // enable the auxiliary profiles
    m_ambiorix_cl.resolve_path_multi(wbapi_utils::search_path_ep_profiles_by_alias(aux_alias),
                                     profile_paths);

    for (const auto &profile : profile_paths) {
        args.set_type(AMXC_VAR_ID_HTABLE);
        args.add_child("Enable", "1");
        m_ambiorix_cl.update_object(profile, args);
        LOG(DEBUG) << "enable aux profile " << profile;
    }

    // set ProfileReference to the auxiliary profile
    // this should trigger the regeneration of a wpa_supp.cfg with an empty network{} section
    for (const auto &endpoint : endpoint_paths) {
        std::string aux_profile;
        if (!m_ambiorix_cl.resolve_path(endpoint + "Profile.[Alias == '" + aux_alias + "']",
                                        aux_profile)) {
            continue;
        }
        args.set_type(AMXC_VAR_ID_HTABLE);
        args.add_child("ProfileReference", aux_profile);
        m_ambiorix_cl.update_object(endpoint, args);
        LOG(DEBUG) << "set aux profile " << aux_profile << " as profile reference for " << endpoint;
    }

    // clear all EndPoint.ProfileReference objects
    for (const auto &endpoint : endpoint_paths) {
        LOG(DEBUG) << "ProfileReference reset " << endpoint;
        args.set_type(AMXC_VAR_ID_HTABLE);
        args.add_child("ProfileReference", "");
        m_ambiorix_cl.update_object(endpoint, args);
    }

    m_ambiorix_cl.resolve_path_multi("WiFi.EndPoint.*.Profile.*", profile_paths);

    // remove all profiles
    for (const auto &profile : profile_paths) {
        LOG(DEBUG) << "remove profile " << profile;
        m_ambiorix_cl.remove_instance(profile, 0); // second argument is ignored
    }
    LOG(INFO) << "reset wps credentials";
}

int cfg_get_hostap_iface(int32_t radio_num, char hostap_iface[BPL_IFNAME_LEN])
{
    if (!hostap_iface) {
        MAPF_ERR("cfg_get_hostap_iface: invalid input: hostap_iface is NULL");
        return RETURN_ERR;
    }

    if (radio_num < 0) {
        MAPF_ERR("cfg_get_hostap_iface: invalid input: radio_num < 0");
        return RETURN_ERR;
    }

    beerocks::bpl::BPL_WLAN_IFACE interfaces[beerocks::MAX_RADIOS_PER_AGENT] = {0};
    int num_of_interfaces = beerocks::MAX_RADIOS_PER_AGENT;
    if (cfg_get_all_prplmesh_wifi_interfaces(interfaces, &num_of_interfaces)) {
        MAPF_ERR("ERROR: Failed to read interfaces map");
        return RETURN_ERR;
    }
    for (int i = 0; i < num_of_interfaces; i++) {
        if (interfaces[i].radio_num == radio_num) {
            mapf::utils::copy_string(hostap_iface, interfaces[i].ifname, BPL_IFNAME_LEN);
            return RETURN_OK;
        }
    }
    return RETURN_ERR;
}

bool bpl_cfg_get_monitored_BSSs_by_radio_iface(const std::string &iface,
                                               std::set<std::string> &monitored_BSSs)
{
    return true;
}

bool bpl_cfg_get_wpa_supplicant_ctrl_path(const std::string &iface, std::string &wpa_ctrl_path)
{
    wpa_ctrl_path = "/var/run/wpa_supplicant/" + iface;
    return true;
}

bool bpl_cfg_get_hostapd_ctrl_path(const std::string &iface, std::string &hostapd_ctrl_path)
{
    hostapd_ctrl_path = "/var/run/hostapd/" + iface;
    return true;
}

} // namespace bpl
} // namespace beerocks
