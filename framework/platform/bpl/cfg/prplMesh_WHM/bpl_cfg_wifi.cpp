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

namespace beerocks {
namespace bpl {

static amxc_var_t *bpl_cfg_get_wifi_ap_object(const std::string &iface)
{
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 1);

    if (aps) {
        amxc_var_for_each(ap, aps)
        {
            const char *ifname = GET_CHAR(ap, "Alias");
            if (!ifname) {
                continue;
            }
            if (std::string(ifname) == iface) {
                return ap;
            }
        }
    }

    return nullptr;
}

static amxc_var_t *bpl_cfg_get_wifi_ssid_object(const std::string &iface)
{
    amxc_var_t *ap_obj = bpl_cfg_get_wifi_ap_object(iface);
    if (!ap_obj) {
        return nullptr;
    }

    const char *ssid_ref_val = GET_CHAR(ap_obj, "SSIDReference");

    std::string wifi_ssid_path = std::string(ssid_ref_val) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *ssid_obj       = m_ambiorix_cl->get_object(wifi_ssid_path, 0);
    if (!ssid_obj) {
        LOG(ERROR) << "failed to get ssid object, iface:" << iface;
    }
    return ssid_obj;
}

static amxc_var_t *bpl_cfg_get_wifi_radio_object(const std::string &iface)
{
    amxc_var_t *ap_obj = bpl_cfg_get_wifi_ap_object(iface);
    if (!ap_obj) {
        return nullptr;
    }

    const char *radio_ref_val = GET_CHAR(ap_obj, "RadioReference");

    std::string wifi_radio_path = std::string(radio_ref_val) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *radio_obj       = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object, iface:" << iface;
    }

    return radio_obj;
}

static amxc_var_t *bpl_cfg_get_wifi_security_object(const std::string &iface)
{
    amxc_var_t *ap_obj = bpl_cfg_get_wifi_ap_object(iface);
    if (!ap_obj) {
        return nullptr;
    }

    const char *ap_path = amxc_var_key(ap_obj);
    int vap_id          = beerocks::wbapi::wbapi_utils::get_object_id(std::string(ap_path));

    std::string wifi_ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                               std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                               std::to_string(vap_id) + AMX_CL_OBJ_DELIMITER;
    const std::string sec_path         = "Security.";
    const std::string wifi_ap_sec_path = wifi_ap_path + sec_path;

    amxc_var_t *ap_sec_obj = m_ambiorix_cl->get_object(wifi_ap_sec_path, 0);
    if (!ap_sec_obj) {
        LOG(ERROR) << "failed to get ap security object, iface:" << iface;
    }
    return ap_sec_obj;
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

    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER;
    amxc_var_t *aps = m_ambiorix_cl->get_object(ap_path, 1);

    int interfaces_count = 0;
    if (aps) {
        amxc_var_for_each(ap, aps)
        {
            const char *ifname = GET_CHAR(ap, "Alias");
            if (!ifname) {
                continue;
            }
            mapf::utils::copy_string(interfaces[interfaces_count].ifname, ifname, BPL_IFNAME_LEN);
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

    amxc_var_t *radio_obj = bpl_cfg_get_wifi_radio_object(iface);
    if (!radio_obj) {
        return RETURN_ERR;
    }

    wlan_params->enabled = GET_UINT32(radio_obj, "Enable");
    wlan_params->channel = GET_UINT32(radio_obj, "Channel");

    // TODO: read sub_band_dfs + country_code wifi params (PPM-2108).

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

        amxc_var_t *radio_obj = bpl_cfg_get_wifi_radio_object(iface);
        if (!radio_obj) {
            break;
        }

        bool ap_mode = GET_BOOL(radio_obj, "AP_Mode");
        if (!ap_mode) {
            break;
        }

        amxc_var_t *ap_obj = bpl_cfg_get_wifi_ap_object(iface);
        if (!ap_obj) {
            break;
        }

        son::wireless_utils::sBssInfoConf configuration;
        configuration.fronthaul   = false;
        configuration.backhaul    = false;
        const char *multi_ap_type = GET_CHAR(ap_obj, "MultiAPType");
        if (multi_ap_type) {
            std::string multi_ap_type_str = std::string(multi_ap_type);
            if (multi_ap_type_str.find("FronthaulBSS") != std::string::npos) {
                configuration.fronthaul = true;
            }
            if (multi_ap_type_str.find("BackhaulBSS") != std::string::npos) {
                configuration.backhaul = true;
            }
        }

        if (bpl_cfg_get_wifi_credentials(iface, configuration)) {
            wireless_settings.push_back(configuration);
        }
    }

    return true;
}

bool bpl_cfg_get_wifi_credentials(const std::string &iface,
                                  son::wireless_utils::sBssInfoConf &configuration)
{
    amxc_var_t *radio_obj = bpl_cfg_get_wifi_radio_object(iface);
    if (!radio_obj) {
        return false;
    }
    configuration.operating_class = {GET_UINT32(radio_obj, "OperatingClass")};

    amxc_var_t *ssid_obj = bpl_cfg_get_wifi_ssid_object(iface);
    if (!ssid_obj) {
        return false;
    }
    configuration.ssid = std::string(GET_CHAR(ssid_obj, "SSID"));

    amxc_var_t *ap_sec_obj = bpl_cfg_get_wifi_security_object(iface);
    if (!ap_sec_obj) {
        return false;
    }

    std::string mode_enabled = std::string(GET_CHAR(ap_sec_obj, "ModeEnabled"));
    configuration.authentication_type =
        beerocks::wbapi::wbapi_utils::security_mode_from_string(mode_enabled);

    std::string encryption_mode = std::string(GET_CHAR(ap_sec_obj, "EncryptionMode"));
    configuration.encryption_type =
        beerocks::wbapi::wbapi_utils::encryption_type_from_string(encryption_mode);

    std::string key_pass_phrase = std::string(GET_CHAR(ap_sec_obj, "KeyPassPhrase"));
    configuration.network_key   = key_pass_phrase;

    return true;
}

bool bpl_cfg_set_wifi_credentials(const std::string &iface,
                                  const son::wireless_utils::sBssInfoConf &configuration)
{
    std::string wifi_ssid_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                 std::string(AMX_CL_SSID_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + iface +
                                 AMX_CL_OBJ_DELIMITER;
    amxc_var_t new_obj;
    amxc_var_init(&new_obj);
    amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&new_obj, "SSID", configuration.ssid.c_str());
    bool ret = m_ambiorix_cl->update_object(wifi_ssid_path, &new_obj);
    amxc_var_clean(&new_obj);

    // update WiFi.SSID.iface. object
    if (!ret) {
        MAPF_ERR("Failed to update WiFi.SSID.iface. object");
        return false;
    }

    std::string security_mode =
        beerocks::wbapi::wbapi_utils::security_mode_to_string(configuration.authentication_type);
    std::string encryption_type =
        beerocks::wbapi::wbapi_utils::encryption_type_to_string(configuration.encryption_type);

    std::string wifi_ap_sec_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                   std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + iface +
                                   AMX_CL_OBJ_DELIMITER + "Security.";
    amxc_var_init(&new_obj);
    amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&new_obj, "ModeEnabled", security_mode.c_str());
    amxc_var_add_new_key_cstring_t(&new_obj, "EncryptionMode", encryption_type.c_str());
    amxc_var_add_new_key_cstring_t(&new_obj, "KeyPassPhrase", configuration.network_key.c_str());
    ret = m_ambiorix_cl->update_object(wifi_ap_sec_path, &new_obj);
    amxc_var_clean(&new_obj);

    // update WiFi.AccessPoint.iface.Security. object
    if (!ret) {
        MAPF_ERR("Failed to update WiFi.AccessPoint.iface.Security. object");
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

    mapf::utils::copy_string(sta_iface, iface, BPL_IFNAME_LEN);
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

    beerocks::bpl::BPL_WLAN_IFACE interfaces[beerocks::IRE_MAX_SLAVES] = {0};
    int num_of_interfaces                                              = beerocks::IRE_MAX_SLAVES;
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
