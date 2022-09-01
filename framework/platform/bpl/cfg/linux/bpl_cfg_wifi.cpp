/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "../common/utils/utils.h"
#include "../common/utils/utils_net.h"
#include "bpl_cfg_linux.h"
#include <bcl/beerocks_string_utils.h>
#include <bpl/bpl_cfg.h>

#include <mapf/common/logger.h>
#include <mapf/common/utils.h>

#include <tlvf/WSC/eWscAuth.h>
#include <tlvf/WSC/eWscEncr.h>

using namespace mapf;

namespace beerocks {
namespace bpl {

extern bool radio_num_to_wlan_iface_name(const int32_t radio_num, std::string &iface_str);

int cfg_get_all_prplmesh_wifi_interfaces(BPL_WLAN_IFACE *interfaces, int *num_of_interfaces)
{
    if (!interfaces) {
        MAPF_ERR("cfg_get_all_prplmesh_wifi_interfaces: invalid input: interfaces is NULL");
        return RETURN_ERR;
    }
    if (!num_of_interfaces) {
        MAPF_ERR("cfg_get_all_prplmesh_wifi_interfaces: invalid input: num_of_interfaces is NULL");
        return RETURN_ERR;
    }
    if (*num_of_interfaces < 1) {
        MAPF_ERR(
            "cfg_get_all_prplmesh_wifi_interfaces: invalid input: max num_of_interfaces value < 1");
        return RETURN_ERR;
    }

    int interfaces_count = 0;
    for (int index = 0; index < *num_of_interfaces; index++) {
        if (cfg_get_hostap_iface(index, interfaces[interfaces_count].ifname) == RETURN_ERR) {
            MAPF_ERR("cfg_get_all_prplmesh_wifi_interfaces: failed to get wifi interface for agent"
                     << index);
        }
        interfaces[interfaces_count++].radio_num = index;
    }

    *num_of_interfaces = interfaces_count;

    return RETURN_OK;
}

int cfg_get_wifi_params(const char *iface, struct BPL_WLAN_PARAMS *wlan_params)
{
    if (!iface || !wlan_params) {
        return RETURN_ERR;
    }
    wlan_params->enabled      = 1;
    wlan_params->channel      = 0;
    wlan_params->sub_band_dfs = false;

    return RETURN_OK;
}

bool bpl_cfg_get_wireless_settings(std::list<son::wireless_utils::sBssInfoConf> &wireless_settings)
{
    int num_of_interfaces = beerocks::IRE_MAX_SLAVES;
    for (int index = 0; index < num_of_interfaces; index++) {
        char iface[BPL_IFNAME_LEN];
        if (cfg_get_hostap_iface(index, iface) == RETURN_ERR) {
            break;
        }

        son::wireless_utils::sBssInfoConf configuration;
        if (bpl_cfg_get_wifi_credentials(iface, configuration)) {
            wireless_settings.push_back(configuration);
        }
    }

    return true;
}

bool bpl_cfg_get_wifi_credentials(const std::string &iface,
                                  son::wireless_utils::sBssInfoConf &configuration)
{
    // Filter returns true if given parameter name starts with "wireless.<iface>."
    const std::string prefix = "wireless." + iface + ".";
    auto filter              = [prefix](const std::string &name) {
        return name.compare(0, prefix.size(), prefix) == 0;
    };

    // Read all configuration parameters for the given interface.
    std::unordered_map<std::string, std::string> parameters;
    if (!cfg_get_params(parameters, filter) || (parameters.empty())) {
        MAPF_ERR("Failed to read WiFi credentials for interface " << iface);
        return false;
    }

    // Fill in wireless credentials from parameter values read from configuration file.
    configuration.ssid = parameters[prefix + "ssid"];

    auto get_authentication_type = [](const std::string &security_mode) {
        if ((security_mode == "wpa2") || (security_mode == "wpa2-psk")) {
            return WSC::eWscAuth::WSC_AUTH_WPA2PSK;
        }
        return WSC::eWscAuth::WSC_AUTH_OPEN;
    };
    configuration.authentication_type =
        get_authentication_type(parameters[prefix + "security_mode"]);

    auto get_encryption_type = [](const std::string &security_mode) {
        if ((security_mode == "wpa2") || (security_mode == "wpa2-psk")) {
            return WSC::eWscEncr::WSC_ENCR_AES;
        }
        return WSC::eWscEncr::WSC_ENCR_NONE;
    };
    configuration.encryption_type = get_encryption_type(parameters[prefix + "security_mode"]);

    configuration.network_key = parameters[prefix + "psk"];

    return true;
}

bool bpl_cfg_set_wifi_credentials(const std::string &iface,
                                  const son::wireless_utils::sBssInfoConf &configuration)
{
    // Read all configuration parameters
    std::unordered_map<std::string, std::string> parameters;
    if (!cfg_get_params(parameters)) {
        MAPF_ERR("Failed to read configuration parameters");
        return false;
    }

    // Overwrite configuration parameters with wireless credentials for the given interface
    const std::string prefix    = "wireless." + iface + ".";
    parameters[prefix + "ssid"] = configuration.ssid;

    auto get_security_mode = [](WSC::eWscAuth authentication_type, WSC::eWscEncr encryption_type) {
        std::string security_mode = "none";
        if ((authentication_type == WSC::eWscAuth::WSC_AUTH_WPA2PSK) &&
            (encryption_type == WSC::eWscEncr::WSC_ENCR_AES)) {
            security_mode = "wpa2-psk";
        }
        return security_mode;
    };

    parameters[prefix + "security_mode"] =
        get_security_mode(configuration.authentication_type, configuration.encryption_type);

    parameters[prefix + "psk"] = configuration.network_key;

    // Save configuration parameters
    if (!cfg_set_params(parameters)) {
        MAPF_ERR("Failed to write configuration parameters");
        return false;
    }

    return true;
}

bool bpl_cfg_get_wpa_supplicant_ctrl_path(const std::string &iface, std::string &wpa_ctrl_path)
{
    const std::string param = "wpa_supplicant_ctrl_path_" + iface;

    if (!cfg_get_param(param, wpa_ctrl_path)) {
        MAPF_ERR("Failed to read: " << param);
        return false;
    }

    return true;
}

bool bpl_cfg_get_hostapd_ctrl_path(const std::string &iface, std::string &hostapd_ctrl_path)
{
    const std::string param = "hostapd_ctrl_path_" + iface;

    if (!cfg_get_param(param, hostapd_ctrl_path)) {
        MAPF_ERR("Failed to read: " << param);
        return false;
    }

    return true;
}

bool bpl_cfg_get_mandatory_interfaces(std::string &mandatory_interfaces)
{

    // For linux implementation this feature is not used.
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

    //get sta ifname based on conf: must have a wpa_suppl ctrl sock file
    std::string wpa_ctrl_path;
    if (!beerocks::bpl::bpl_cfg_get_wpa_supplicant_ctrl_path(std::string(iface), wpa_ctrl_path) ||
        wpa_ctrl_path.empty()) {
        MAPF_INFO("cfg_get_sta_iface: no sta_iface for hostap_iface (" + std::string(iface) + ")");
        return RETURN_ERR;
    }
    //get sock filename : last token
    std::stringstream path(wpa_ctrl_path);
    std::string token;
    while (std::getline(path, token, '/'))
        ;
    mapf::utils::copy_string(sta_iface, token.c_str(), BPL_IFNAME_LEN);
    return RETURN_OK;
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

    std::string iface_str;
    if (!radio_num_to_wlan_iface_name(radio_num, iface_str)) {
        MAPF_ERR("cfg_get_hostap_iface: unknown iface index: " + std::to_string(radio_num));
        return RETURN_ERR;
    }

    mapf::utils::copy_string(hostap_iface, iface_str.c_str(), BPL_IFNAME_LEN);
    return RETURN_OK;
}

bool bpl_cfg_get_monitored_BSSs_by_radio_iface(const std::string &iface,
                                               std::set<std::string> &monitored_BSSs)
{
    return true;
}

} // namespace bpl
} // namespace beerocks
