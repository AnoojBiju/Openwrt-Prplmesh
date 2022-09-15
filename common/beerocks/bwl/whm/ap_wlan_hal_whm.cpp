/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "ap_wlan_hal_whm.h"

#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_os_utils.h>
#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_assoc_frame_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <easylogging++.h>
#include <math.h>
#include <sstream>
//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace bwl {
namespace whm {

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

// NOTE: Since *base_wlan_hal_whm* inherits *base_wlan_hal* virtually, we
//       need to explicitly call it's from any deriving class
ap_wlan_hal_whm::ap_wlan_hal_whm(const std::string &iface_name, hal_event_cb_t callback,
                                 const hal_conf_t &hal_conf)
    : base_wlan_hal(bwl::HALType::AccessPoint, iface_name, IfaceType::Intel, callback, hal_conf),
      base_wlan_hal_whm(bwl::HALType::AccessPoint, iface_name, callback, hal_conf)
{
    subscribe_to_radio_events(iface_name);
    subscribe_to_ap_events(iface_name);
    subscribe_to_sta_events(iface_name);
}

ap_wlan_hal_whm::~ap_wlan_hal_whm() {}

HALState ap_wlan_hal_whm::attach(bool block)
{
    auto state = base_wlan_hal_whm::attach(block);

    // On Operational send the AP_Attached event to the AP Manager
    if (state == HALState::Operational) {
        event_queue_push(Event::AP_Attached);
    }

    return state;
}

void ap_wlan_hal_whm::subscribe_to_radio_events(const std::string &iface_name)
{
    // subscribe to the WiFi.Radio.iface_name.Status
    std::string wifi_radio_path;
    if (!whm_get_radio_path(iface_name, wifi_radio_path)) {
        return;
    }
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = AMX_CL_OBJECT_CHANGED_EVT;
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        amxc_var_t *params = GET_ARG(event_data, "parameters");
        amxc_var_for_each(param, params)
        {
            const char *key = amxc_var_key(param);
            if (!key) {
                continue;
            }
            if (std::string(key) != "Status") {
                continue;
            }
            amxc_var_t *status = GET_ARG(params, key);
            if (!status) {
                continue;
            }
            const char *status_val = GET_CHAR(status, "to");
            if (!status_val) {
                continue;
            }
            ap_wlan_hal::Event event = ap_wlan_hal::Event::Invalid;
            if (std::string(status_val) == "Up") {
                event = ap_wlan_hal::Event::Interface_Enabled;
            } else {
                event = ap_wlan_hal::Event::Interface_Disabled;
            }
            (static_cast<ap_wlan_hal_whm *>(context))->process_whm_event(event, event_data);
        }
    };
    event_callback->context = this;
    m_ambiorix_cl->subscribe_to_object_event(wifi_radio_path, event_callback);
}

void ap_wlan_hal_whm::subscribe_to_ap_events(const std::string &iface_name)
{
    std::string wifi_ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                               std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                               "[Alias == '" + iface_name + "']" + AMX_CL_OBJ_DELIMITER;
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = AMX_CL_OBJECT_CHANGED_EVT;
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        amxc_var_t *params = GET_ARG(event_data, "parameters");
        amxc_var_for_each(param, params)
        {
            const char *key = amxc_var_key(param);
            if (!key) {
                continue;
            }
            if (std::string(key) != "Status") {
                continue;
            }
            amxc_var_t *status = GET_ARG(params, key);
            if (!status) {
                continue;
            }
            const char *status_val = GET_CHAR(status, "to");
            if (!status_val) {
                continue;
            }
            ap_wlan_hal::Event event = ap_wlan_hal::Event::Invalid;
            if (std::string(status_val) == "Enabled") {
                event = ap_wlan_hal::Event::AP_Enabled;
            } else {
                event = ap_wlan_hal::Event::AP_Disabled;
            }
            (static_cast<ap_wlan_hal_whm *>(context))->process_whm_event(event, event_data);
        }
    };
    event_callback->context = this;
    m_ambiorix_cl->subscribe_to_object_event(wifi_ap_path, event_callback);
}

void ap_wlan_hal_whm::subscribe_to_sta_events(const std::string &iface_name)
{
    std::string wifi_ap_sta_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                   std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                                   whm_get_vap_instance_name(iface_name) + AMX_CL_OBJ_DELIMITER +
                                   "AssociatedDevice.";
    sAmxClEventCallback *event_callback = new sAmxClEventCallback();
    event_callback->event_type          = AMX_CL_OBJECT_CHANGED_EVT;
    event_callback->callback_fn         = [](amxc_var_t *event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        amxc_var_t *params = GET_ARG(event_data, "parameters");
        amxc_var_for_each(param, params)
        {
            const char *key = amxc_var_key(param);
            if (!key) {
                continue;
            }
            if (std::string(key) != "Active") {
                continue;
            }
            amxc_var_t *active = GET_ARG(params, key);
            if (!active) {
                continue;
            }
            const bool active_val    = GET_BOOL(active, "to");
            ap_wlan_hal::Event event = ap_wlan_hal::Event::Invalid;
            if (active_val) {
                event = ap_wlan_hal::Event::STA_Connected;
            } else {
                event = ap_wlan_hal::Event::STA_Disconnected;
            }
            (static_cast<ap_wlan_hal_whm *>(context))->process_whm_event(event, event_data);
        }
    };
    event_callback->context = this;
    m_ambiorix_cl->subscribe_to_object_event(wifi_ap_sta_path, event_callback);
}

bool ap_wlan_hal_whm::refresh_radio_info()
{
    std::string wifi_radio_path;
    if (!whm_get_radio_path(get_iface_name(), wifi_radio_path)) {
        return false;
    }

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return false;
    }

    const char *op_fr_band = GET_CHAR(radio_obj, "OperatingFrequencyBand");
    if (op_fr_band) {
        m_radio_info.frequency_band =
            beerocks::wbapi::wbapi_utils::band_to_freq(std::string(op_fr_band));
    }

    const char *max_ch_band = GET_CHAR(radio_obj, "MaxChannelBandwidth");
    if (op_fr_band) {
        m_radio_info.max_bandwidth =
            beerocks::wbapi::wbapi_utils::bandwith_from_string(std::string(max_ch_band));
    }

    amxc_var_delete(&radio_obj);

    // TODO: read radio capabilities and supported channel list (PPM-2120)

    return base_wlan_hal_whm::refresh_radio_info();
}

bool ap_wlan_hal_whm::enable()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::disable()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_start_disabled(bool enable, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_channel(int chan, beerocks::eWiFiBandwidth bw, int center_channel)
{
    std::string wifi_radio_path;
    if (!whm_get_radio_path(get_iface_name(), wifi_radio_path)) {
        return false;
    }

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return false;
    }

    bool auto_channel_enable = GET_BOOL(radio_obj, "AutoChannelEnable");
    amxc_var_delete(&radio_obj);
    if (auto_channel_enable) {
        LOG(ERROR) << "unable to set channel!, AutoChannelEnable option is enabled";
        return false;
    }

    amxc_var_t new_obj;
    amxc_var_init(&new_obj);
    amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_uint8_t(&new_obj, "Channel", chan);
    bool ret = m_ambiorix_cl->update_object(wifi_radio_path, &new_obj);
    amxc_var_clean(&new_obj);

    if (!ret) {
        LOG(ERROR) << "unable to set channel!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_whm::sta_allow(const std::string &mac, const std::string &bssid)
{
    auto vap_id = get_vap_id_with_mac(bssid);
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }

    std::string ifname          = m_radio_info.available_vaps[vap_id].bss;
    std::string mac_filter_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                  std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                                  "[Alias = " + ifname + "]" + AMX_CL_OBJ_DELIMITER +
                                  "MACFiltering.";
    amxc_var_t *mac_filter_obj = m_ambiorix_cl->get_object(mac_filter_path, 0);
    if (!mac_filter_obj) {
        LOG(ERROR) << "failed to get MACFiltering object";
        return false;
    }

    std::string mode = GET_CHAR(mac_filter_obj, "Mode");
    amxc_var_delete(&mac_filter_obj);
    if (mode == "Off") {
        LOG(TRACE) << "MACFiltering mode is off, sta allowed";
        return true;
    }

    // check if the sta is included in accesslist entries
    bool sta_found           = false;
    std::string entries_path = mac_filter_path + "Entry.";
    amxc_var_t *entries      = m_ambiorix_cl->get_object(entries_path, 2);
    if (entries) {
        amxc_var_for_each(entry, entries)
        {
            const char *entry_mac = GET_CHAR(entry, "MACAddress");
            if (entry_mac && (std::string(entry_mac) == mac)) {
                sta_found = true;
            }
        }
        amxc_var_delete(&entries);
    }

    if (sta_found && mode == "WhiteList") {
        LOG(TRACE) << "sta allowed in WhiteList mode";
        return true;
    }
    if (!sta_found && mode == "BlackList") {
        LOG(TRACE) << "sta allowed in BlackList mode";
        return true;
    }

    // delete sta from the BlackList
    amxc_var_t args;
    amxc_var_t result;
    amxc_var_init(&args);
    amxc_var_init(&result);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&args, "mac", mac.c_str());
    bool ret = true;
    if (mode == "WhiteList") {
        ret = m_ambiorix_cl->call(mac_filter_path, "addEntry", &args, &result);
    } else if (mode == "BlackList") {
        ret = m_ambiorix_cl->call(mac_filter_path, "delEntry", &args, &result);
    }
    amxc_var_clean(&args);
    amxc_var_clean(&result);

    if (!ret) {
        LOG(ERROR) << "MACFiltering update entry failed!";
        return false;
    }
    LOG(TRACE) << "sta updated in accessList, sta allowed";
    return true;
}

bool ap_wlan_hal_whm::sta_deny(const std::string &mac, const std::string &bssid)
{
    auto vap_id = get_vap_id_with_mac(bssid);
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }

    std::string ifname          = m_radio_info.available_vaps[vap_id].bss;
    std::string mac_filter_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                  std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                                  "[Alias = " + ifname + "]" + AMX_CL_OBJ_DELIMITER +
                                  "MACFiltering.";

    amxc_var_t *mac_filter_obj = m_ambiorix_cl->get_object(mac_filter_path, 0);
    if (!mac_filter_obj) {
        LOG(ERROR) << "failed to get MACFiltering object";
        return false;
    }

    std::string mode = GET_CHAR(mac_filter_obj, "Mode");
    amxc_var_delete(&mac_filter_obj);

    // check if the sta is included in accesslist entries
    bool sta_found           = false;
    std::string entries_path = mac_filter_path + "Entry.";
    amxc_var_t *entries      = m_ambiorix_cl->get_object(entries_path, 2);
    if (entries) {
        amxc_var_for_each(entry, entries)
        {
            const char *entry_mac = GET_CHAR(entry, "MACAddress");
            if (entry_mac && (std::string(entry_mac) == mac)) {
                sta_found = true;
            }
        }
        amxc_var_delete(&entries);
    }

    if (sta_found && mode == "BlackList") {
        LOG(TRACE) << "sta denied in BlackList mode";
        return true;
    }
    if (!sta_found && mode == "WhiteList") {
        LOG(TRACE) << "sta denied in WhiteList mode";
        return true;
    }

    bool ret = true;
    amxc_var_t args;
    amxc_var_t result;
    amxc_var_init(&args);
    amxc_var_init(&result);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&args, "mac", mac.c_str());
    if (mode == "Off") {
        LOG(WARNING) << "change MACFiltering mode to BlackList";
        amxc_var_t new_obj;
        amxc_var_init(&new_obj);
        amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
        amxc_var_add_new_key_cstring_t(&new_obj, "Mode", "BlackList");
        ret = m_ambiorix_cl->update_object(mac_filter_path, &new_obj);
        amxc_var_clean(&new_obj);

        if (!ret) {
            LOG(ERROR) << "unable to change MACFiltering mode to BlackList!";
        } else {
            mode = "BlackList";
        }
    }
    if (!sta_found && mode == "BlackList") {
        ret = m_ambiorix_cl->call(mac_filter_path, "addEntry", &args, &result);
    } else if (sta_found && mode == "WhiteList") {
        ret = m_ambiorix_cl->call(mac_filter_path, "delEntry", &args, &result);
    }

    amxc_var_clean(&args);
    amxc_var_clean(&result);

    if (!ret) {
        LOG(ERROR) << "MACFiltering update entry failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_whm::sta_disassoc(int8_t vap_id, const std::string &mac, uint32_t reason)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::sta_deauth(int8_t vap_id, const std::string &mac, uint32_t reason)
{
    if (!check_vap_id(vap_id)) {
        LOG(ERROR) << "invalid vap_id " << vap_id;
        return false;
    }
    std::string ifname = m_radio_info.available_vaps[vap_id].bss;
    amxc_var_t args;
    amxc_var_t result;
    amxc_var_init(&args);
    amxc_var_init(&result);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&args, "macaddress", mac.c_str());
    amxc_var_add_new_key_uint32_t(&args, "reason", reason);
    std::string wifi_ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                               std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                               "[Alias = " + ifname + "]" + AMX_CL_OBJ_DELIMITER;
    bool ret = m_ambiorix_cl->call(wifi_ap_path, "kickStationReason", &args, &result);
    amxc_var_clean(&args);
    amxc_var_clean(&result);

    if (!ret) {
        LOG(ERROR) << "sta_deauth() failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_whm::sta_bss_steer(int8_t vap_id, const std::string &mac, const std::string &bssid,
                                    int oper_class, int chan, int disassoc_timer_btt,
                                    int valid_int_btt, int reason)
{
    if (!check_vap_id(vap_id)) {
        LOG(ERROR) << "invalid vap_id " << vap_id;
        return false;
    }
    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    amxc_var_t args;
    amxc_var_t result;
    amxc_var_init(&args);
    amxc_var_init(&result);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&args, "mac", mac.c_str());
    amxc_var_add_new_key_cstring_t(&args, "target", bssid.c_str());
    amxc_var_add_new_key_uint8_t(&args, "class", oper_class);
    amxc_var_add_new_key_uint8_t(&args, "channel", chan);
    amxc_var_add_new_key_uint8_t(&args, "validity", valid_int_btt);
    amxc_var_add_new_key_uint8_t(&args, "disassoc", disassoc_timer_btt);
    amxc_var_add_new_key_uint8_t(&args, "transitionReason", reason);
    std::string wifi_ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                               std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                               "[Alias = " + ifname + "]" + AMX_CL_OBJ_DELIMITER;
    bool ret = m_ambiorix_cl->call(wifi_ap_path, "sendBssTransferRequest", &args, &result);
    amxc_var_clean(&args);
    amxc_var_clean(&result);

    if (!ret) {
        LOG(ERROR) << "sta_bss_steer() failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_whm::update_vap_credentials(
    std::list<son::wireless_utils::sBssInfoConf> &bss_info_conf_list,
    const std::string &backhaul_wps_ssid, const std::string &backhaul_wps_passphrase)
{
    int vap_id = 0;

    // Clear all VAPs from the available container, since we preset it with configuration.
    m_radio_info.available_vaps.clear();

    for (auto bss_info_conf : bss_info_conf_list) {
        std::string ifname = get_iface_name();
        auto auth_type =
            son::wireless_utils::wsc_to_bwl_authentication(bss_info_conf.authentication_type);
        if (auth_type == "INVALID") {
            LOG(ERROR) << "Autoconfiguration: invalid auth_type "
                       << int(bss_info_conf.authentication_type);
            continue;
        }
        auto enc_type = son::wireless_utils::wsc_to_bwl_encryption(bss_info_conf.encryption_type);
        if (enc_type == "INVALID") {
            LOG(ERROR) << "Autoconfiguration: invalid enc_type "
                       << int(bss_info_conf.encryption_type);
            continue;
        }

        LOG(DEBUG) << "Autoconfiguration for ssid: " << bss_info_conf.ssid
                   << " auth_type: " << auth_type << " encr_type: " << enc_type
                   << " network_key: " << bss_info_conf.network_key
                   << " fronthaul: " << bss_info_conf.fronthaul
                   << " backhaul: " << bss_info_conf.backhaul;

        amxc_var_t *ap_obj = whm_get_wifi_ap_object(ifname);
        if (!ap_obj) {
            continue;
        }
        std::string ssid_ref_val   = GET_CHAR(ap_obj, "SSIDReference");
        std::string wifi_ssid_path = ssid_ref_val + AMX_CL_OBJ_DELIMITER;
        amxc_var_delete(&ap_obj);

        amxc_var_t new_obj;
        amxc_var_init(&new_obj);
        amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
        amxc_var_add_new_key_cstring_t(&new_obj, "SSID", bss_info_conf.ssid.c_str());
        bool ret = m_ambiorix_cl->update_object(wifi_ssid_path, &new_obj);
        amxc_var_clean(&new_obj);

        if (!ret) {
            LOG(ERROR) << "Failed to update SSID object";
            continue;
        }

        auto get_security_mode = [](WSC::eWscAuth authentication_type) {
            std::string sec_mode = "none";
            if (authentication_type == WSC::eWscAuth::WSC_AUTH_WPA2PSK) {
                sec_mode = "WPA2-Personal";
            }
            return sec_mode;
        };

        auto get_encryption_mode = [](WSC::eWscEncr encryption_type) {
            std::string encrypt_mode = "none";
            if (encryption_type == WSC::eWscEncr::WSC_ENCR_AES) {
                encrypt_mode = "AES";
            }
            return encrypt_mode;
        };

        std::string security_mode   = get_security_mode(bss_info_conf.authentication_type);
        std::string encryption_mode = get_encryption_mode(bss_info_conf.encryption_type);

        std::string wifi_ap_sec_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                       std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                                       "[Alias == '" + ifname + "']" + AMX_CL_OBJ_DELIMITER +
                                       "Security.";
        amxc_var_init(&new_obj);
        amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
        amxc_var_add_new_key_cstring_t(&new_obj, "ModeEnabled", security_mode.c_str());
        amxc_var_add_new_key_cstring_t(&new_obj, "EncryptionMode", encryption_mode.c_str());
        amxc_var_add_new_key_cstring_t(&new_obj, "KeyPassPhrase",
                                       bss_info_conf.network_key.c_str());
        ret = m_ambiorix_cl->update_object(wifi_ap_sec_path, &new_obj);
        amxc_var_clean(&new_obj);

        if (!ret) {
            LOG(ERROR) << "Failed to update Security object";
            continue;
        }

        m_radio_info.available_vaps[vap_id].fronthaul = bss_info_conf.fronthaul;
        m_radio_info.available_vaps[vap_id].backhaul  = bss_info_conf.backhaul;
        m_radio_info.available_vaps[vap_id++].ssid    = bss_info_conf.ssid;
    }

    return true;
}

bool ap_wlan_hal_whm::sta_unassoc_rssi_measurement(const std::string &mac, int chan, int bw,
                                                   int vht_center_frequency, int delay,
                                                   int window_size)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::sta_softblock_add(const std::string &vap_name, const std::string &client_mac,
                                        uint8_t reject_error_code, uint8_t probe_snr_threshold_hi,
                                        uint8_t probe_snr_threshold_lo,
                                        uint8_t authetication_snr_threshold_hi,
                                        uint8_t authetication_snr_threshold_lo)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::sta_softblock_remove(const std::string &vap_name,
                                           const std::string &client_mac)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::switch_channel(int chan, beerocks::eWiFiBandwidth bw,
                                     int vht_center_frequency, int csa_beacon_count)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::cancel_cac(int chan, beerocks::eWiFiBandwidth bw, int vht_center_frequency,
                                 int secondary_chan)
{
    return set_channel(chan, bw, vht_center_frequency);
}

bool ap_wlan_hal_whm::failsafe_channel_set(int chan, int bw, int vht_center_frequency)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::failsafe_channel_get(int &chan, int &bw)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::is_zwdfs_supported()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return false;
}

bool ap_wlan_hal_whm::set_zwdfs_antenna(bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::is_zwdfs_antenna_enabled()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return false;
}

bool ap_wlan_hal_whm::hybrid_mode_supported()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::restricted_channels_set(char *channel_list)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::restricted_channels_get(char *channel_list)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return false;
}

bool ap_wlan_hal_whm::read_acs_report()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_tx_power_limit(int tx_pow_limit)
{
    std::string wifi_radio_path;
    if (!whm_get_radio_path(get_iface_name(), wifi_radio_path)) {
        return false;
    }

    amxc_var_t new_obj;
    amxc_var_init(&new_obj);
    amxc_var_set_type(&new_obj, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_uint8_t(&new_obj, "TransmitPower", tx_pow_limit);
    bool ret = m_ambiorix_cl->update_object(wifi_radio_path, &new_obj);
    amxc_var_clean(&new_obj);

    if (!ret) {
        LOG(ERROR) << "unable to set tx power limit!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_whm::set_vap_enable(const std::string &iface_name, const bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::get_vap_enable(const std::string &iface_name, bool &enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::generate_connected_clients_events(
    bool &is_finished_all_clients, std::chrono::steady_clock::time_point max_iteration_timeout)
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::pre_generate_connected_clients_events()
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::start_wps_pbc()
{
    amxc_var_t args;
    amxc_var_t result;
    amxc_var_init(&args);
    amxc_var_init(&result);
    std::string wps_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                           std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER + "[Alias == '" +
                           get_iface_name() + "']" + AMX_CL_OBJ_DELIMITER + "WPS.";
    bool ret = m_ambiorix_cl->call(wps_path, "pushButton", &args, &result);
    amxc_var_clean(&args);
    amxc_var_clean(&result);

    if (!ret) {
        LOG(ERROR) << "start_wps_pbc() failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_whm::set_mbo_assoc_disallow(const std::string &bssid, bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_radio_mbo_assoc_disallow(bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_primary_vlan_id(uint16_t primary_vlan_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_cce_indication(uint16_t advertise_cce)
{
    LOG(DEBUG) << "ap_wlan_hal_whm: set_cce_indication, advertise_cce=" << advertise_cce;
    return true;
}

amxc_var_t *ap_wlan_hal_whm::get_last_assoc_frame(const std::string &sta_mac)
{
    amxc_var_t args;
    amxc_var_init(&args);
    amxc_var_t data;
    amxc_var_init(&data);
    amxc_var_t *frame = nullptr;

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&args, "mac", sta_mac.c_str());
    std::string ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                          std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                          whm_get_vap_instance_name(get_iface_name()) + AMX_CL_OBJ_DELIMITER;

    bool ret = m_ambiorix_cl->call(ap_path, "getLastAssocReq", &args, &data);

    if (ret) {
        frame = GETI_ARG(&data, 0);
        amxc_var_take_it(frame);
    } else {
        LOG(ERROR) << "getLastAssocReq() failed!";
    }

    amxc_var_clean(&args);
    amxc_var_clean(&data);

    return frame;
}

bool ap_wlan_hal_whm::process_whm_event(ap_wlan_hal::Event event, const amxc_var_t *data)
{
    switch (event) {

    case Event::AP_Enabled: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_ENABLED_NOTIFICATION));
        auto msg      = reinterpret_cast<sHOSTAP_ENABLED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        memset(msg_buff.get(), 0, sizeof(sHOSTAP_ENABLED_NOTIFICATION));

        const char *ap_obj_path = GET_CHAR(data, "path");

        amxc_var_t *ap_obj = m_ambiorix_cl->get_object(ap_obj_path, 0);
        if (!ap_obj) {
            LOG(ERROR) << "failed to get ap object";
            return true;
        }

        std::string interface = GET_CHAR(ap_obj, "Alias");
        amxc_var_delete(&ap_obj);
        auto vap_id    = get_vap_id_with_bss(interface);
        auto iface_ids = beerocks::utils::get_ids_from_iface_string(interface);
        if (vap_id < 0) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return false;
        }

        msg->vap_id = vap_id;

        if (iface_ids.vap_id == beerocks::IFACE_RADIO_ID) {
            // Ignore AP-ENABLED on radio
            return true;
        }

        event_queue_push(Event::AP_Enabled, msg_buff);
    } break;

    case Event::AP_Disabled: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_DISABLED_NOTIFICATION));
        auto msg      = reinterpret_cast<sHOSTAP_DISABLED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        memset(msg_buff.get(), 0, sizeof(sHOSTAP_DISABLED_NOTIFICATION));

        const char *ap_obj_path = GET_CHAR(data, "path");

        amxc_var_t *ap_obj = m_ambiorix_cl->get_object(ap_obj_path, 0);
        if (!ap_obj) {
            LOG(ERROR) << "failed to get ap object";
            return true;
        }

        std::string interface = GET_CHAR(ap_obj, "Alias");
        amxc_var_delete(&ap_obj);
        auto vap_id    = get_vap_id_with_bss(interface);
        auto iface_ids = beerocks::utils::get_ids_from_iface_string(interface);
        if (vap_id < 0) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return true;
        }

        msg->vap_id = vap_id;

        if (iface_ids.vap_id == beerocks::IFACE_RADIO_ID) {
            // Ignore AP-DISABLED on radio
            return true;
        }

        event_queue_push(Event::AP_Disabled, msg_buff); // send message to the AP manager

    } break;

    case Event::Interface_Disabled: {
        event_queue_push(event);
    } break;

    case Event::STA_Connected: {
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));

        const char *sta_obj_path = GET_CHAR(data, "object");
        if (!sta_obj_path) {
            return false;
        }
        amxc_var_t *sta_obj = m_ambiorix_cl->get_object(std::string(sta_obj_path), 0);
        if (!sta_obj) {
            LOG(ERROR) << "failed to get AssociatedDevice object " << sta_obj_path;
            return true;
        }

        std::string sta_mac = GET_CHAR(sta_obj, "MACAddress");
        amxc_var_delete(&sta_obj);
        if (sta_mac.empty()) {
            LOG(ERROR) << "failed to get MACAddress";
            return true;
        }

        msg->params.mac          = tlvf::mac_from_string(sta_mac);
        msg->params.capabilities = {};

        //init the freq band cap with the target radio freq band info
        msg->params.capabilities.band_5g_capable = m_radio_info.is_5ghz;
        msg->params.capabilities.band_2g_capable =
            (son::wireless_utils::which_freq(m_radio_info.channel) ==
             beerocks::eFreqType::FREQ_24G);

        auto assoc_frame_type = assoc_frame::AssocReqFrame::UNKNOWN;

        amxc_var_t *frame = get_last_assoc_frame(sta_mac);
        if (frame) {
            const char *frame_body = GET_CHAR(frame, "frame");
            const char *ap_bssid   = GET_CHAR(frame, "bssid");
            msg->params.bssid      = tlvf::mac_from_string(ap_bssid);
            auto vap_id            = get_vap_id_with_mac(ap_bssid);
            msg->params.vap_id     = vap_id;
            //convert the hex string to binary
            auto binary_str                      = get_binary_association_frame(frame_body);
            msg->params.association_frame_length = binary_str.length();
            // Add the latest association frame
            std::copy_n(&binary_str[0], binary_str.length(), msg->params.association_frame);
            assoc_frame_type      = assoc_frame::AssocReqFrame::ASSOCIATION_REQUEST;
            uint32_t request_type = GET_UINT32(frame, "request_type");
            if (request_type == 2) {
                assoc_frame_type = assoc_frame::AssocReqFrame::REASSOCIATION_REQUEST;
            }
            amxc_var_delete(&frame);
        } else {
            LOG(WARNING) << "STA connected without previously receiving a (re-)association frame!";
            msg->params.association_frame_length = 0;
        }

        auto assoc_frame = assoc_frame::AssocReqFrame::parse(
            msg->params.association_frame, msg->params.association_frame_length, assoc_frame_type);

        auto res = son::assoc_frame_utils::get_station_capabilities_from_assoc_frame(
            assoc_frame, msg->params.capabilities);
        if (!res) {
            LOG(WARNING) << "Failed to get station capabilities.";
        } else {
            LOG(INFO) << "print_station_capabilities!";
            son::wireless_utils::print_station_capabilities(msg->params.capabilities);
        }

        // Add the message to the queue
        event_queue_push(Event::STA_Connected, msg_buff);

    } break;

    case Event::STA_Disconnected: {
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION));

        const char *sta_obj_path = GET_CHAR(data, "object");
        if (!sta_obj_path) {
            return false;
        }
        amxc_var_t *sta_obj = m_ambiorix_cl->get_object(std::string(sta_obj_path), 0);
        if (!sta_obj) {
            LOG(ERROR) << "failed to get AssociatedDevice object";
            return true;
        }

        std::string sta_mac = GET_CHAR(sta_obj, "MACAddress");
        amxc_var_delete(&sta_obj);
        if (sta_mac.empty()) {
            LOG(ERROR) << "failed to get MACAddress";
            return true;
        }

        msg->params.mac = tlvf::mac_from_string(sta_mac);

        event_queue_push(Event::STA_Disconnected, msg_buff);
    } break;

    default:
        LOG(DEBUG) << "Unhandled event received";
        break;
    }

    return true;
}

bool ap_wlan_hal_whm::set(const std::string &param, const std::string &value, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

} // namespace whm

std::shared_ptr<ap_wlan_hal> ap_wlan_hal_create(std::string iface_name, bwl::hal_conf_t hal_conf,
                                                base_wlan_hal::hal_event_cb_t callback)
{
    return std::make_shared<whm::ap_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
