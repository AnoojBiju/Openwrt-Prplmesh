/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl/bpl_cfg.h>

#include "../../common/uci/bpl_uci.h"
#include "../../common/utils/utils.h"
#include "../../common/utils/utils_net.h"

#include "bpl_cfg_helper.h"
#include "bpl_cfg_uci.h"

#include <bcl/beerocks_string_utils.h>
#include <mapf/common/logger.h>
#include <mapf/common/utils.h>

using namespace mapf;

namespace beerocks {
namespace bpl {

static bool bpl_cfg_get_bss_configuration(const std::string &section_name,
                                          son::wireless_utils::sBssInfoConf &configuration)
{
    OptionsUnorderedMap options;
    if (!uci_get_section("wireless", "wifi-iface", section_name, options)) {
        LOG(ERROR) << "Failed to get values for section " << section_name;
        return false;
    }

    // Fill in wireless credentials from option values read from UCI configuration.
    configuration.ssid = options["ssid"];

    auto starts_with = [](const std::string &prefix, const std::string &value) {
        return (value.compare(0, prefix.size(), prefix) == 0);
    };

    auto contains = [](const std::string &substring, const std::string &value) {
        return (value.find(substring) != std::string::npos);
    };

    auto get_authentication_type = [&](const std::string &encryption) {
        if ("none" == encryption || encryption.empty()) {
            return WSC::eWscAuth::WSC_AUTH_OPEN;
        } else if (starts_with("psk2", encryption)) {
            return WSC::eWscAuth::WSC_AUTH_WPA2PSK;
        } else if ("sae" == encryption) {
            return WSC::eWscAuth::WSC_AUTH_SAE;
        }
        return WSC::eWscAuth::WSC_AUTH_INVALID;
    };
    configuration.authentication_type = get_authentication_type(options["encryption"]);

    auto get_encryption_type = [&](const std::string &encryption) {
        if ("none" == encryption || encryption.empty()) {
            return WSC::eWscEncr::WSC_ENCR_NONE;
        } else if (contains("+tkip", encryption)) {
            return WSC::eWscEncr::WSC_ENCR_TKIP;
        } else if (("psk2" == encryption) || ("sae" == encryption) ||
                   contains("+aes", encryption) || contains("+ccmp", encryption)) {
            return WSC::eWscEncr::WSC_ENCR_AES;
        }
        return WSC::eWscEncr::WSC_ENCR_INVALID;
    };
    configuration.encryption_type = get_encryption_type(options["encryption"]);

    configuration.network_key = options["key"];

    return true;
}

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

    std::unordered_map<std::string, std::string> hostapd_ifaces;
    if (cfg_get_prplmesh_hostapd_ifaces(hostapd_ifaces) == RETURN_ERR) {
        MAPF_DBG("cfg_get_all_prplmesh_wifi_interfaces: failed to get avaliable interfaces");
        return RETURN_ERR;
    }

    if (*num_of_interfaces < (int)hostapd_ifaces.size()) {
        MAPF_ERR("cfg_get_all_prplmesh_wifi_interfaces: invalid input: max num_of_interfaces < "
                 "number of avaliable interfaces");
        return RETURN_ERR;
    }

    int iface_idx = 0;
    for (const auto &iface_iter : hostapd_ifaces) {
        // the `first` element of iface_iter is a string structured "radioN" where N represents the
        // given interface's index
        interfaces[iface_idx].radio_num = atoi(iface_iter.first.substr(5).c_str());
        strncpy_s(interfaces[iface_idx].ifname, BPL_IFNAME_LEN, iface_iter.second.c_str(),
                  BPL_IFNAME_LEN - 1);
        iface_idx++;
    }

    *num_of_interfaces = iface_idx;

    return RETURN_OK;
}

int cfg_get_wifi_params(const char iface[BPL_IFNAME_LEN], struct BPL_WLAN_PARAMS *wlan_params)
{
    if (!iface || !wlan_params) {
        MAPF_ERR("cfg_get_wifi_params: invalid input: iface = "
                 << intptr_t(iface) << " wlan_params = " << intptr_t(wlan_params));
        return RETURN_ERR;
    }

    // The UCI "disabled" setting is optional, defaults to false if not present
    bool disabled = false;
    cfg_uci_get_wireless_bool(TYPE_RADIO, iface, "disabled", &disabled);
    wlan_params->enabled = !disabled;

    if (cfg_uci_get_wireless_bool(TYPE_RADIO, iface, "sub_band_dfs", &wlan_params->sub_band_dfs) ==
        RETURN_ERR) {
        // Failed to find "sub_band_dfs", set to to default value.
        wlan_params->sub_band_dfs = false;
    }

    // The UCI "channel" setting is not documented as optional, but for Intel
    // wireless (as probably for other drivers) it is. We do not want to
    // fail when wifi still works fine, so default to "auto" (0) and if
    // can't get the channel from UCI just move on.
    wlan_params->channel = 0;
    cfg_get_channel(iface, &wlan_params->channel);

    // country code
    char alpha_2[MAX_UCI_BUF_LEN] = {0};
    cfg_uci_get_wireless_from_ifname(TYPE_RADIO, iface, "country", alpha_2);

    wlan_params->country_code[0] = alpha_2[0];
    wlan_params->country_code[1] = alpha_2[1];

    return RETURN_OK;
}

bool bpl_cfg_get_wireless_settings(std::list<son::wireless_utils::sBssInfoConf> &wireless_settings)
{
    // Get all "wireless.wifi-iface" section names in UCI configuration
    const std::string package_name = "wireless";
    const std::string section_type = "wifi-iface";
    std::vector<std::string> sections;
    if (!uci_get_all_sections(package_name, section_type, sections)) {
        LOG(ERROR) << "Failed to get section names";
        return false;
    }

    // Read SSID and WiFi credentials from each "wireless.wifi-iface" section found.
    for (const auto &section_name : sections) {
        std::string mode;
        if (!uci_get_option(package_name, section_type, section_name, "mode", mode)) {
            LOG(DEBUG) << "Failed to get 'mode' from section " << section_name;
            continue;
        }

        // Silently ignore sections that do not configure an AP.
        if (mode != "ap") {
            continue;
        }

        std::string hidden;
        uci_get_option(package_name, section_type, section_name, "hidden", hidden);
        // the hidden option might not exist, in which case we treat
        // it as if it was 0 (i.e. we don't skip the section).

        std::string disabled;
        uci_get_option(package_name, section_type, section_name, "disabled", disabled);
        // the disabled option might not exist, in which case we treat
        // it as if it was 0 (i.e. we don't skip the section).

        if (hidden == "1" || disabled == "1") {
            LOG(INFO) << "Skipping section for hidden or disabled BSS: " << section_name;
            continue;
        }

        std::string ssid;
        uci_get_option(package_name, section_type, section_name, "ssid", ssid);
        // the SSID might not be set, in which case we treat
        // it as if it was an empty string (i.e. we *do* skip the section).
        if (ssid.empty()) {
            LOG(INFO) << "Skipping configuration for section with unset or empty SSID: "
                      << section_name;
            continue;
        }

        son::wireless_utils::sBssInfoConf configuration;
        if (!bpl_cfg_get_bss_configuration(section_name, configuration)) {
            LOG(DEBUG) << "Failed to get SSID and WiFi credentials from section " << section_name;
            continue;
        }

        if (configuration.authentication_type == WSC::eWscAuth::WSC_AUTH_INVALID ||
            configuration.encryption_type == WSC::eWscEncr::WSC_ENCR_INVALID) {
            LOG(INFO) << "Skipping configuration for section with invalid authentication or "
                         "encryption type: "
                      << section_name;
            continue;
        }

        // Operating classes are not specified in UCI configuration, but we can guess based on
        // the mode used by hostapd that was set for the radio.
        // To get the mode, first get the device and then the mode inside the section for that
        // device.
        std::string device;
        if (!uci_get_option(package_name, section_type, section_name, "device", device)) {
            LOG(DEBUG) << "Failed to get 'device' from section " << section_name;
            continue;
        }

        // Option "hwmode" in device section selects the wireless protocol to use, possible values
        // are 11b, 11g, and 11a.
        std::string hwmode;
        if (!uci_get_option(package_name, "wifi-device", device, "hwmode", hwmode)) {
            LOG(DEBUG) << "Failed to get 'hwmode' from section " << device;
            continue;
        }

        // The mode used by upstream hostapd (11b, 11g, 11n, 11ac, 11ax) is governed by several parameters in
        // the configuration file. However, as explained in the comment below from hostapd.conf, the
        // hw_mode parameter is sufficient to determine the band.
        //
        // # Operation mode (a = IEEE 802.11a (5 GHz), b = IEEE 802.11b (2.4 GHz),
        // # g = IEEE 802.11g (2.4 GHz), ad = IEEE 802.11ad (60 GHz); a/g options are used
        // # with IEEE 802.11n (HT), too, to specify band). For IEEE 802.11ac (VHT), this
        // # needs to be set to hw_mode=a. For IEEE 802.11ax (HE) on 6 GHz this needs
        // # to be set to hw_mode=a.
        //
        // Note that this will need to be revisited for 6GHz operation, which we don't support at
        // the moment.
        //
        // For MaxLinear's devices, by default '11bgnax' is used for 2.4Ghz bands, and '11anacax' is
        // used for 5Ghz bands (see 'files/scripts/lib/netifd/wireless/mac80211.sh' in the swpal package).
        if (hwmode.empty() || (hwmode == "11b") || (hwmode == "11g") || hwmode == "11bgnax") {
            configuration.operating_class.splice(
                configuration.operating_class.end(),
                son::wireless_utils::string_to_wsc_oper_class("24g"));
        } else if (hwmode == "11a" || hwmode == "11anacax") {
            configuration.operating_class.splice(
                configuration.operating_class.end(),
                son::wireless_utils::string_to_wsc_oper_class("5g"));
        } else {
            LOG(DEBUG) << "Failed to get frequency band for SSID " << configuration.ssid
                       << " from hwmode " << hwmode;
            continue;
        }

        // Multi - AP
        std::string management_mode;
        uci_get_option("prplmesh", "prplmesh", "config", "management_mode", management_mode);
        if (management_mode == "Not-Multi-AP") {
            configuration.fronthaul = true;
            configuration.backhaul  = false;
        } else {
            std::string multi_ap;
            uci_get_option(package_name, section_type, section_name, "multi_ap", multi_ap);
            if (multi_ap.empty()) {
                LOG(INFO)
                    << "multi_ap configuration is not found, assign as only fronthaul support";
                configuration.fronthaul = true;
                configuration.backhaul  = false;
            } else {
                switch (beerocks::string_utils::stoi(multi_ap)) {
                case beerocks::eBssType::BSS_TYPE_BACKHAUL:
                    configuration.fronthaul = false;
                    configuration.backhaul  = true;
                    break;
                case beerocks::eBssType::BSS_TYPE_FRONTHAUL:
                    configuration.fronthaul = true;
                    configuration.backhaul  = false;
                    break;
                case beerocks::eBssType::BSS_TYPE_BACK_FRONTHAUL:
                    configuration.fronthaul = true;
                    configuration.backhaul  = true;
                    break;
                default:
                    LOG(ERROR) << "Multi AP configuration value is unrecognized " << multi_ap
                               << ", assign as only fronthaul support";
                    configuration.fronthaul = true;
                    configuration.backhaul  = false;
                    break;
                }
            }
        }

        wireless_settings.push_back(configuration);

        LOG(DEBUG) << "Configuration added for SSID " << configuration.ssid
                   << " (hwmode = " << hwmode << ")";
    }

    return true;
}

bool bpl_cfg_get_wifi_credentials(const std::string &iface,
                                  son::wireless_utils::sBssInfoConf &configuration)
{
    // Find the "wireless.wifi-iface" section in UCI configuration for the given interface
    std::string section_name;
    if (!uci_find_section_by_option("wireless", "wifi-iface", "ifname", iface, section_name)) {
        LOG(ERROR) << "Failed to find configuration section for interface " << iface;
        return false;
    }

    if (section_name.empty()) {
        LOG(ERROR) << "Configuration for interface " << iface << " not found";
        return false;
    }

    // Get SSID and wireless credentials for the given interface.
    if (!bpl_cfg_get_bss_configuration(section_name, configuration)) {
        LOG(ERROR) << "Failed to get wireless configuration for interface " << iface
                   << " at section " << section_name;
        return false;
    }

    return true;
}

bool bpl_cfg_set_wifi_credentials(const std::string &iface,
                                  const son::wireless_utils::sBssInfoConf &configuration)
{
    // Find the "wireless.wifi-iface" section in UCI configuration for the given interface
    const std::string package_name = "wireless";
    const std::string section_type = "wifi-iface";
    const std::string option_name  = "ifname";
    std::string section_name;
    if (!uci_find_section_by_option(package_name, section_type, option_name, iface, section_name)) {
        LOG(ERROR) << "Failed to find configuration section for interface " << iface;
        return false;
    }

    if (section_name.empty()) {
        LOG(ERROR) << "Configuration for interface " << iface << " not found";
        return false;
    }

    // Overwrite UCI configuration with wireless credentials for the given interface
    OptionsUnorderedMap options;
    options["ssid"] = configuration.ssid;

    auto get_encryption = [](WSC::eWscAuth authentication_type, WSC::eWscEncr encryption_type) {
        std::string encryption = "none";
        if (authentication_type == WSC::eWscAuth::WSC_AUTH_WPA2PSK) {
            encryption = "psk2";
            if (encryption_type == WSC::eWscEncr::WSC_ENCR_TKIP) {
                encryption += "+tkip";
            } else if (encryption_type == WSC::eWscEncr::WSC_ENCR_AES) {
                encryption += "+aes";
            }
        } else if (authentication_type == WSC::eWscAuth::WSC_AUTH_SAE) {
            encryption = "sae";
        }
        return encryption;
    };
    options["encryption"] =
        get_encryption(configuration.authentication_type, configuration.encryption_type);

    options["key"] = configuration.network_key;

    // Write UCI options in the "wireless.wifi-iface" section for the given interface.
    if (!uci_set_section(package_name, section_type, section_name, options, true)) {
        LOG(ERROR) << "Failed to set wireless configuration for interface " << iface
                   << " at section " << section_name;
        return false;
    }

    return true;
}

bool bpl_cfg_get_mandatory_interfaces(std::string &mandatory_interfaces)
{
    mandatory_interfaces.clear();

    constexpr int MANDATORY_INTERFACES_SIZE = BPL_IFNAME_LEN * BPL_NUM_OF_INTERFACES + 1;
    char tmp_mandatory_interfaces[MANDATORY_INTERFACES_SIZE];

    if (cfg_get_prplmesh_param("mandatory_interfaces", tmp_mandatory_interfaces,
                               MANDATORY_INTERFACES_SIZE) < 0) {
        LOG(DEBUG) << "Optional parameter mandatory_interfaces doesn't exist";
        return true;
    }

    mandatory_interfaces = std::string(tmp_mandatory_interfaces);

    return true;
}

bool bpl_cfg_get_wpa_supplicant_ctrl_path(const std::string &iface, std::string &wpa_ctrl_path)
{
    const char *path{"/var/run/wpa_supplicant/"};
    wpa_ctrl_path = path + iface;
    return true;
}

bool bpl_cfg_get_hostapd_ctrl_path(const std::string &iface, std::string &hostapd_ctrl_path)
{
    const char *path{"/var/run/hostapd/"};
    hostapd_ctrl_path = path + iface;
    return true;
}

int cfg_get_sta_iface(const char iface[BPL_IFNAME_LEN], char sta_iface[BPL_IFNAME_LEN])
{
    if (!iface || !sta_iface) {
        MAPF_ERR("cfg_get_sta_iface: invalid input: iface or sta_iface are NULL");
        return RETURN_ERR;
    }

    // Find the "prplmesh.wifi-device" section in UCI configuration for the given interface
    const std::string package_name = "prplmesh";
    const std::string section_type = "wifi-device";
    std::string section_name;
    if (!uci_find_section_by_option(package_name, section_type, "hostap_iface", iface,
                                    section_name)) {
        LOG(ERROR) << "Failed to find configuration section for interface " << iface;
        return RETURN_ERR;
    }

    if (section_name.empty()) {
        LOG(ERROR) << "Configuration for interface " << iface << " not found";
        return RETURN_ERR;
    }

    // Get the name of the STA interface for the given Host AP interface
    std::string option_value;
    if (!uci_get_option(package_name, section_type, section_name, "sta_iface", option_value)) {
        LOG(ERROR) << "Failed to get STA interface for Host AP interface " << iface;
        return RETURN_ERR;
    }

    mapf::utils::copy_string(sta_iface, option_value.c_str(), BPL_IFNAME_LEN);

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

    return cfg_get_prplmesh_radio_param(radio_num, "hostap_iface", hostap_iface, BPL_IFNAME_LEN);
}

bool bpl_cfg_get_monitored_BSSs_by_radio_iface(const std::string &iface,
                                               std::set<std::string> &monitored_BSSs)
{
    // To get the correct VAP list for a given interface name, we first need to get all the
    // avaliable ifaces in relation to their sections.
    // Key: Section, Value: Radio iface
    std::unordered_map<std::string, std::string> radio_ifaces;
    if (cfg_get_prplmesh_hostapd_ifaces(radio_ifaces) == RETURN_ERR) {
        LOG(ERROR) << "Failed to get avaliable interfaces!";
        return false;
    }
    // Iterate over the interface names to find the matching section
    const auto it = std::find_if(radio_ifaces.begin(), radio_ifaces.end(),
                                 [&iface](std::pair<std::string, std::string> const &item) {
                                     return (item.second == iface);
                                 });
    if (it == radio_ifaces.end()) {
        LOG(ERROR) << "Failed to find matching iface " << iface;
        return false;
    }
    // Once the correct section is found we can get the monitored_bsss option.
    const std::string package_name = "prplmesh";
    const std::string section_type = "wifi-device";
    const std::string option_name  = "hostap_iface_monitor_vaps";
    std::string monitored_bsss;
    if (!uci_get_option(package_name, section_type, (*it).first, option_name, monitored_bsss)) {
        LOG(DEBUG) << "Failed to get 'hostap_iface_monitor_vaps' from section " << (*it).first;
        return true;
    }
    // the monitored_bsss option is a list seperated by the ',' delimiter
    auto monitored_BSSs_vec = beerocks::string_utils::str_split(monitored_bsss, ',');
    monitored_BSSs =
        std::move(std::set<std::string>(monitored_BSSs_vec.begin(), monitored_BSSs_vec.end()));
    return true;
    // break monitor vaps to vector
}

} // namespace bpl
} // namespace beerocks
