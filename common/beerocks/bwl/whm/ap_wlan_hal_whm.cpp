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

using namespace beerocks;
using namespace wbapi;

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
    subscribe_to_radio_events();
    subscribe_to_ap_events();
    subscribe_to_sta_events();
    subscribe_to_ap_bss_tm_events();
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

void ap_wlan_hal_whm::subscribe_to_ap_bss_tm_events()
{
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_BSS_TM_RESPONSE_EVT;
    event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        std::string ap_path;
        if (!event_data || (event_data.read_child(ap_path, "path") == false) || ap_path.empty()) {
            return;
        }
        ap_wlan_hal_whm *hal = (static_cast<ap_wlan_hal_whm *>(context));
        auto &vapsExtInfo    = hal->m_vapsExtInfo;
        auto vap_it          = std::find_if(vapsExtInfo.begin(), vapsExtInfo.end(),
                                   [&](const std::pair<std::string, VAPExtInfo> &element) {
                                       return element.second.path == ap_path;
                                   });
        if (vap_it == vapsExtInfo.end()) {
            LOG(DEBUG) << "vap_it not found";
            return;
        }
        LOG(DEBUG) << "event from iface " << vap_it->first;

        hal->process_ap_bss_event(vap_it->first, &event_data);
    };
    event_handler->context = this;

    std::string filter = "(path matches '" + wbapi_utils::search_path_ap() +
                         "[0-9]+.$')"
                         " && (notification == '" +
                         AMX_CL_BSS_TM_RESPONSE_EVT + "')";

    m_ambiorix_cl.subscribe_to_object_event(wbapi_utils::search_path_ap(), event_handler, filter);
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
    bool auto_channel_enable = false;
    m_ambiorix_cl.get_param(auto_channel_enable, m_radio_path, "AutoChannelEnable");
    if (auto_channel_enable) {
        LOG(ERROR) << "unable to set channel!, AutoChannelEnable option is enabled";
        return false;
    }

    AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
    new_obj.add_child("Channel", uint8_t(chan));
    bool ret = m_ambiorix_cl.update_object(m_radio_path, new_obj);

    if (chan == 0) {
        LOG(INFO) << "return true for channel:0";
        return true;
        // ap_manager sometimes writes 0 value as part of resetting the radio
        // it expects a return true in this case, so give it that
    }

    if (!ret) {
        LOG(ERROR) << "unable to set channel! ch: " << chan << " center chan : " << center_channel;
        return false;
    }

    return true;
}

bool ap_wlan_hal_whm::sta_allow(const sMacAddr &mac, const sMacAddr &bssid)
{
    auto vap_id = get_vap_id_with_mac(tlvf::mac_to_string(bssid));
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }

    std::string ifname          = m_radio_info.available_vaps[vap_id].bss;
    std::string mac_filter_path = wbapi_utils::search_path_mac_filtering(ifname);

    std::string mode;
    if (!m_ambiorix_cl.get_param(mode, mac_filter_path, "Mode")) {
        LOG(ERROR) << "failed to get MACFiltering object";
        return false;
    }

    if (mode.empty() || mode == "Off") {
        LOG(TRACE) << "MACFiltering mode is off, sta allowed";
        return true;
    }

    // check if the sta is included in accesslist entries
    std::string entry_path =
        wbapi_utils::search_path_mac_filtering_entry_by_mac(ifname, tlvf::mac_to_string(mac));
    bool sta_found = m_ambiorix_cl.resolve_path(entry_path, entry_path);

    if (sta_found && mode == "WhiteList") {
        LOG(TRACE) << "sta allowed in WhiteList mode";
        return true;
    }
    if (!sta_found && mode == "BlackList") {
        LOG(TRACE) << "sta allowed in BlackList mode";
        return true;
    }

    // delete sta from the BlackList
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child("mac", tlvf::mac_to_string(mac));
    bool ret = true;
    if (mode == "WhiteList") {
        ret = m_ambiorix_cl.call(mac_filter_path, "addEntry", args, result);
    } else if (mode == "BlackList") {
        ret = m_ambiorix_cl.call(mac_filter_path, "delEntry", args, result);
    }

    if (!ret) {
        LOG(ERROR) << "MACFiltering update entry failed!";
        return false;
    }
    LOG(TRACE) << "sta updated in accessList, sta allowed";
    return true;
}

bool ap_wlan_hal_whm::sta_deny(const sMacAddr &mac, const sMacAddr &bssid)
{
    auto vap_id = get_vap_id_with_mac(tlvf::mac_to_string(bssid));
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }

    std::string ifname          = m_radio_info.available_vaps[vap_id].bss;
    std::string mac_filter_path = wbapi_utils::search_path_mac_filtering(ifname);

    std::string mode;
    if (!m_ambiorix_cl.get_param(mode, mac_filter_path, "Mode")) {
        LOG(ERROR) << "failed to get MACFiltering object";
        return false;
    }

    if (mode.empty() || mode == "Off") {
        LOG(TRACE) << "MACFiltering mode is off, sta allowed";
        return true;
    }

    // check if the sta is included in accesslist entries
    std::string entry_path =
        wbapi_utils::search_path_mac_filtering_entry_by_mac(ifname, tlvf::mac_to_string(mac));
    bool sta_found = m_ambiorix_cl.resolve_path(entry_path, entry_path);

    if (sta_found && mode == "BlackList") {
        LOG(TRACE) << "sta denied in BlackList mode";
        return true;
    }
    if (!sta_found && mode == "WhiteList") {
        LOG(TRACE) << "sta denied in WhiteList mode";
        return true;
    }

    bool ret = true;
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child("mac", tlvf::mac_to_string(mac));
    if (mode == "Off") {
        LOG(WARNING) << "change MACFiltering mode to BlackList";
        AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
        new_obj.add_child<>("Mode", "BlackList");
        ret = m_ambiorix_cl.update_object(mac_filter_path, new_obj);

        if (!ret) {
            LOG(ERROR) << "unable to change MACFiltering mode to BlackList!";
        } else {
            mode = "BlackList";
        }
    }
    if (!sta_found && mode == "BlackList") {
        ret = m_ambiorix_cl.call(mac_filter_path, "addEntry", args, result);
    } else if (sta_found && mode == "WhiteList") {
        ret = m_ambiorix_cl.call(mac_filter_path, "delEntry", args, result);
    }

    if (!ret) {
        LOG(ERROR) << "MACFiltering update entry failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_whm::sta_acceptlist_modify(const sMacAddr &mac, const sMacAddr &bssid,
                                            bwl::sta_acl_action action)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_macacl_type(const eMacACLType &acl_type, const sMacAddr &bssid)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
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
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child("macaddress", mac);
    args.add_child("reason", reason);
    std::string wifi_ap_path = wbapi_utils::search_path_ap_by_iface(ifname);
    bool ret                 = m_ambiorix_cl.call(wifi_ap_path, "kickStationReason", args, result);

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

    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child("mac", mac);
    args.add_child("target", bssid);
    args.add_child("class", oper_class);
    args.add_child("channel", chan);
    args.add_child("validity", valid_int_btt);
    args.add_child("disassoc", disassoc_timer_btt);
    args.add_child("transitionReason", reason);
    auto wifi_ap_path = wbapi_utils::search_path_ap_by_iface(ifname);
    bool ret          = m_ambiorix_cl.call(wifi_ap_path, "sendBssTransferRequest", args, result);

    if (!ret) {
        LOG(ERROR) << "sta_bss_steer() failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_whm::update_vap_credentials(
    std::list<son::wireless_utils::sBssInfoConf> &bss_info_conf_list,
    const std::string &backhaul_wps_ssid, const std::string &backhaul_wps_passphrase,
    const std::string &bridge_ifname)
{
    LOG(DEBUG) << "updating vap credentials of radio " << get_iface_name();
    bool ret;

    for (auto bss_info_conf : bss_info_conf_list) {
        auto bssid = tlvf::mac_to_string(bss_info_conf.bssid);
        int vap_id = get_vap_id_with_mac(bssid);
        if (!check_vap_id(vap_id)) {
            LOG(ERROR) << "no matching vap_id for bssid " << bssid;
            continue;
        }
        auto &vap_info = m_radio_info.available_vaps[vap_id];
        auto &ifname   = vap_info.bss;
        auto vap_it    = m_vapsExtInfo.find(ifname);
        if (vap_it == m_vapsExtInfo.end()) {
            LOG(ERROR) << "fail to get ifname of " << bssid;
            continue;
        }
        std::string &wifi_vap_path  = vap_it->second.path;
        std::string &wifi_ssid_path = vap_it->second.ssid_path;
        bool &prev_teardown         = vap_it->second.teardown;

        LOG(DEBUG) << "updating AP " << wifi_vap_path << " SSID " << wifi_ssid_path << " ifname "
                   << ifname << " vap_id " << std::to_string(vap_id);

        AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
        if (bss_info_conf.teardown) {
            prev_teardown = true;
            LOG(INFO) << "BSS " << bss_info_conf.bssid << " flagged for tear down.";
            new_obj.add_child<bool>("Enable", false);
            ret = m_ambiorix_cl.update_object(wifi_vap_path, new_obj);
            if (!ret) {
                LOG(ERROR) << "Failed to disable vap " << ifname;
            }
            continue;
        } else {
            LOG(DEBUG) << "enable vap " << wifi_vap_path;
            new_obj.add_child("Enable", true);
            std::string multi_ap;
            if (bss_info_conf.fronthaul) {
                multi_ap += "FronthaulBSS,";
            }
            if (bss_info_conf.backhaul) {
                multi_ap += "BackhaulBSS";
            }
            LOG(DEBUG) << "set multiaptype " << multi_ap;
            new_obj.add_child("MultiAPType", multi_ap);
            ret = m_ambiorix_cl.update_object(wifi_vap_path, new_obj);
            if (!ret) {
                LOG(ERROR) << "Failed to enable vap " << wifi_vap_path
                           << " or to configure MultiAPType thereof " << multi_ap;
            }
        }

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

        new_obj.set_type(AMXC_VAR_ID_HTABLE);
        new_obj.add_child<>("SSID", bss_info_conf.ssid);
        ret = m_ambiorix_cl.update_object(wifi_ssid_path, new_obj);

        if (!ret) {
            LOG(ERROR) << "Failed to update SSID object";
            continue;
        }

        std::string security_mode =
            wbapi_utils::security_mode_to_string(bss_info_conf.authentication_type);
        std::string encryption_mode =
            wbapi_utils::encryption_type_to_string(bss_info_conf.encryption_type);

        std::string wifi_ap_sec_path = wifi_vap_path + "Security.";
        new_obj.set_type(AMXC_VAR_ID_HTABLE);
        new_obj.add_child<>("ModeEnabled", security_mode);
        if (security_mode == "None") {
            new_obj.add_child<>("EncryptionMode", "Default");
        } else {
            new_obj.add_child<>("EncryptionMode", encryption_mode);
            new_obj.add_child<>("KeyPassPhrase", bss_info_conf.network_key);
        }
        ret = m_ambiorix_cl.update_object(wifi_ap_sec_path, new_obj);

        if (!ret) {
            LOG(ERROR) << "Failed to update Security object " << wifi_ap_sec_path;
            continue;
        }

        if (prev_teardown) {
            prev_teardown = false;
            LOG(INFO) << "Re-enable BSS " << bss_info_conf.bssid << " after tear down.";
            new_obj.set_type(AMXC_VAR_ID_HTABLE);
            new_obj.add_child<bool>("Enable", true);
            ret = m_ambiorix_cl.update_object(wifi_vap_path, new_obj);
            if (!ret) {
                LOG(ERROR) << "Failed to enable vap " << ifname;
                continue;
            }
        }

        vap_info.bss       = ifname;
        vap_info.mac       = bssid;
        vap_info.fronthaul = bss_info_conf.fronthaul;
        vap_info.backhaul  = bss_info_conf.backhaul;
        if (vap_info.backhaul) {
            vap_info.ssid = backhaul_wps_ssid;
            vap_info.profile1_backhaul_sta_association_disallowed =
                bss_info_conf.profile1_backhaul_sta_association_disallowed;
            vap_info.profile2_backhaul_sta_association_disallowed =
                bss_info_conf.profile2_backhaul_sta_association_disallowed;
        } else {
            vap_info.ssid                                         = bss_info_conf.ssid;
            vap_info.profile1_backhaul_sta_association_disallowed = false;
            vap_info.profile2_backhaul_sta_association_disallowed = false;
        }

        // re-notify previously enabled vaps to unblock autoconf task
        auto status = m_ambiorix_cl.get_param(wifi_vap_path, "Status");
        if (status && !status->empty()) {
            process_ap_event(ifname, "Status", status.get());
        }
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
    LOG(TRACE) << " channel: " << chan << ", bw enum: " << bw
               << " bw mhz: " << wbapi_utils::bandwidth_to_string(bw)
               << ", vht_center_frequency: " << vht_center_frequency;

    AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
    bool amx_ret, status = true;

    if (bw == beerocks::eWiFiBandwidth::BANDWIDTH_40) {

        auto freq_type = son::wireless_utils::which_freq_type(vht_center_frequency);
        int freq       = son::wireless_utils::channel_to_freq(chan, freq_type);

        // Extension Channel
        if (freq < vht_center_frequency) {
            new_obj.add_child<>("ExtensionChannel", "AboveControlChannel");
        } else {
            new_obj.add_child<>("ExtensionChannel", "BelowControlChannel");
        }
    }
    // WiFi.Radio.2.OperatingChannelBandwidth
    new_obj.add_child("OperatingChannelBandwidth", wbapi_utils::bandwidth_to_string(bw));

    new_obj.add_child("Channel", chan);
    amx_ret = m_ambiorix_cl.update_object(m_radio_path, new_obj);
    if (!amx_ret) {
        LOG(ERROR) << "can't apply ExtensionCh, BW and Channel for " << m_radio_path;
        status = false;
    }

    return status;
}

bool ap_wlan_hal_whm::cancel_cac(int chan, beerocks::eWiFiBandwidth bw, int vht_center_frequency,
                                 int secondary_chan)
{
    return set_channel(chan, bw, vht_center_frequency);
}

bool ap_wlan_hal_whm::failsafe_channel_set(int chan, int bw, int vht_center_frequency)
{
    // when DFS_OFFLOAD- is not set(our case for now), DFS management will be handled by Hostapd.
    // Thus no need to implement this function.
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::failsafe_channel_get(int &chan, int &bw)
{
    // Failsafe will be handled by hostapd, thus no need to implement this function.
    // Morover, this function is not being called for now.
    LOG(TRACE) << __func__ << "- NOT IMPLEMENTED";
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
    // Hybrid mode is always supported to allow configuring fBss/bBss on profile 1
    return true;
}

bool ap_wlan_hal_whm::restricted_channels_set(char *channel_list)
{
    // We chose not to implement it because it is a custom feature and has no reference in the prplmesh Spec.
    return true;
}

bool ap_wlan_hal_whm::restricted_channels_get(char *channel_list)
{
    // We chose not to implement it because it is a custom feature and has no reference in the prplmesh Spec.
    return false;
}

bool ap_wlan_hal_whm::read_acs_report()
{
    // Whm (similar to nl80211) does not support any channel ranking thus no need to provide any acs_report.
    // Channel selection will be done at the controller level.
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

#define MAX_TX_POWER_ABSOLUTE_MW 100

bool ap_wlan_hal_whm::set_tx_power_limit(int tx_pow_limit)
{
    std::string power_list_str;
    m_ambiorix_cl.get_param<>(power_list_str, m_radio_path, "TransmitPowerSupported");

    std::stringstream ss(power_list_str);
    std::vector<int> power_list_vec;
    int new_value;

    while (ss.good()) {
        std::string substr;
        getline(ss, substr, ',');
        if (stoi(substr) > 0) { // skip special value of -1
            power_list_vec.push_back(stoi(substr));
        }
    }
    std::sort(power_list_vec.begin(), power_list_vec.end());

    //convert tx_pow_limit from dBm to mW
    std::map<int, double> dbm_to_mw_conversion_table = {
        {-7, 0.2000},   {-6, 0.2512},   {-5, 0.3162},   {-4, 0.3981},   {-3, 0.5012},
        {-2, 0.6310},   {-1, 0.7943},   {0, 1.0000},    {1, 1.2589},    {2, 1.5849},
        {3, 1.9953},    {4, 2.5119},    {5, 3.1628},    {6, 3.9811},    {7, 5.0119},
        {8, 6.3096},    {9, 7.9433},    {10, 10.000},   {11, 12.5893},  {12, 15.8489},
        {13, 19.9526},  {14, 25.1189},  {15, 31.6228},  {16, 39.8107},  {17, 50.1187},
        {18, 63.0957},  {19, 79.4328},  {20, 100.00},   {21, 125.8925}, {22, 158.4893},
        {23, 199.5262}, {24, 251.1886}, {25, 316.2278}, {26, 398.1072}, {27, 501.1872},
        {28, 630.9573}, {29, 794.3282}, {30, 1000.00},
    };
    /* human-readable conversion table  (from https://www.rapidtables.com/convert/power/dBm_to_mW.html)
{-7 ,  0.200},  {12 ,  15.8489},
{-6 ,  0.2512},  {13 ,  19.9526},
{-5 ,  0.3162},  {14 ,  25.1189},
{-4 ,  0.3981},  {15 ,  31.6228},
{-3 ,  0.5012},  {16 ,  39.8107},
{-2 ,  0.6310},  {17 ,  50.1187},
{-1 ,  0.7943},  {18 ,  63.0957},
{0  ,  1.0000},   {19 ,  79.4328},
{1  ,  1.2589},   {20 ,  100.00},
{2  ,  1.5849},   {21 ,  125.8925},
{3  ,  1.9953},   {22 ,  158.4893},
{4  ,  2.5119},   {23 ,  199.5262},
{5  ,  3.1628},   {24 ,  251.1886},
{6  ,  3.9811},   {25 ,  316.2278},
{7  ,  5.0119},   {26 ,  398.1072},
{8  ,  6.3096},   {27 ,  501.1872},
{9  ,  7.9433},   {28 ,  630.9573},
{10 ,	10.00},   {29 ,  794.3282},
{11 ,  12.5893},  {30 ,  1000.00},

notes on maintenance: adjust MAX_TX_POWER according to board; extend table if needed
ideally, expose the MAX_TX_POWER_ABSOLUTE_MW via bpl;
the code below will still work
*/
    auto pow_it = dbm_to_mw_conversion_table.find(tx_pow_limit);

    if (pow_it == dbm_to_mw_conversion_table.end()) {
        if (tx_pow_limit < dbm_to_mw_conversion_table.begin()->first) {
            //use smallest possible value
            new_value = *power_list_vec.begin();
        } else {
            //use biggest possible value
            new_value = *power_list_vec.rbegin();
        }
    } else {
        float denominator(MAX_TX_POWER_ABSOLUTE_MW), ratio, numerator;
        numerator           = pow_it->second;
        ratio               = numerator * 100 / denominator;
        int tx_pow_relative = floor(ratio);

        // power_list_vec is sorted; use reverse iterator until
        // the computed tx_pow_relative fits between between two values of "TransmitPowerSupported"
        // then use the small value of the two (with reverse iterator, it's the current one)
        std::vector<int>::reverse_iterator r_it;
        for (r_it = power_list_vec.rbegin(); &*(r_it.base() - 1) != &*(power_list_vec.begin());
             ++r_it) {
            // stop on the first element of the vector instead of the rend() iterator

            if (tx_pow_relative >= *r_it) {
                //computed value is smaller than previous, but bigger than current, use current value
                break;
            }
        }
        new_value = *r_it;
    }

    AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
    new_obj.add_child<>("TransmitPower", uint8_t(tx_pow_limit));
    bool ret = m_ambiorix_cl.update_object(m_radio_path, new_obj);

    if (!ret) {
        LOG(ERROR) << "unable to set tx power limit for " << m_radio_path;
        return false;
    } else {
        LOG(INFO) << "Absolute power " << tx_pow_limit << " dBm, relative power " << new_value;
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

    lock();
    // For the pwhm, we belive the time requirement will be maintained all time, thus we will ignore the max_iteration_timeout
    for (auto &vap : m_vapsExtInfo) {

        std::string vap_path                = vap.second.path;
        std::string associated_devices_path = vap_path + "AssociatedDevice.";

        auto associated_devices_pwhm =
            m_ambiorix_cl.get_object_multi<AmbiorixVariantMapSmartPtr>(associated_devices_path);

        if (associated_devices_pwhm == nullptr) {
            LOG(DEBUG) << "Failed reading: " << associated_devices_path;
            return true;
        }

        auto vap_id = get_vap_id_with_bss(vap.first);
        if (vap_id == beerocks::IFACE_ID_INVALID) {
            LOG(DEBUG) << "Invalid vap_id";
            continue;
        }
        //Lets iterate through all instances
        for (auto &associated_device_pwhm : *associated_devices_pwhm) {
            bool is_active;
            if (!associated_device_pwhm.second.read_child(is_active, "Active") || !is_active) {
                // we are only interested in connected stations
                continue;
            }

            std::string mac_addr;
            if (!associated_device_pwhm.second.read_child(mac_addr, "MACAddress")) {
                LOG(DEBUG) << "Failed reading MACAddress";
                continue;
            }

            auto msg_buff =
                ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));
            LOG_IF(msg_buff == nullptr, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));
            auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION *>(
                msg_buff.get());

            msg->params.vap_id = vap_id;
            msg->params.bssid  = tlvf::mac_from_string(m_radio_info.available_vaps[vap_id].mac);
            msg->params.mac    = tlvf::mac_from_string(mac_addr);

            msg->params.capabilities.band_5g_capable = m_radio_info.is_5ghz;
            msg->params.capabilities.band_2g_capable =
                (son::wireless_utils::which_freq_type(m_radio_info.vht_center_freq) ==
                 beerocks::eFreqType::FREQ_24G);
            msg->params.association_frame_length = 0;

            auto answer = get_last_assoc_frame(vap.first, mac_addr);
            if (!answer) {
                LOG(ERROR) << "fail to get last frame";
                continue;
            }
            std::string frame_body_str;
            if (!answer->read_child<>(frame_body_str, "frame") || frame_body_str.empty()) {
                LOG(WARNING) << "STA connected without previously receiving a "
                                "(re-)association frame!";
            } else {
                auto assoc_frame_type = assoc_frame::AssocReqFrame::UNKNOWN;
                auto management_frame = create_mgmt_frame_notification(frame_body_str.c_str());
                if (management_frame) {
                    auto &frame_body = management_frame->data;
                    // Add the latest association frame
                    std::copy(frame_body.begin(), frame_body.end(), msg->params.association_frame);
                    msg->params.association_frame_length = frame_body.size();
                    assoc_frame_type = assoc_frame::AssocReqFrame::ASSOCIATION_REQUEST;
                    if (management_frame->type == eManagementFrameType::REASSOCIATION_REQUEST) {
                        assoc_frame_type = assoc_frame::AssocReqFrame::REASSOCIATION_REQUEST;
                    }

                    auto assoc_frame = assoc_frame::AssocReqFrame::parse(
                        msg->params.association_frame, msg->params.association_frame_length,
                        assoc_frame_type);

                    auto res = son::assoc_frame_utils::get_station_capabilities_from_assoc_frame(
                        assoc_frame, msg->params.capabilities);
                    if (!res) {
                        LOG(ERROR) << "Failed to get station capabilities.";
                    };
                }
            }

            auto sta_it = m_stations.find(mac_addr);
            if (sta_it == m_stations.end()) {
                m_stations.insert(
                    std::make_pair(mac_addr, sStationInfo(associated_device_pwhm.first)));
            } else {
                sta_it->second.path = associated_device_pwhm.first; //enforce the path
            }

            event_queue_push(Event::STA_Connected, msg_buff);
        }
    }
    is_finished_all_clients = true;
    return true;
}

bool ap_wlan_hal_whm::pre_generate_connected_clients_events()
{

    // For the pwhm and the evolution of prplmesh, we dont see a need to implement this function, all will be done throughh the main
    // function generate_connected_clients_events
    return true;
}

bool ap_wlan_hal_whm::start_wps_pbc()
{
    AmbiorixVariant args, result;
    std::string main_vap_ifname = m_radio_info.available_vaps[0].bss;
    std::string wps_path        = wbapi_utils::search_path_ap_by_iface(main_vap_ifname) + "WPS.";
    bool ret                    = m_ambiorix_cl.call(wps_path, "InitiateWPSPBC", args, result);

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
    // Networking is responsible of handling vlanId, so pwhm does not interfere with vlans.
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_cce_indication(uint16_t advertise_cce)
{
    LOG(DEBUG) << "ap_wlan_hal_whm: set_cce_indication, advertise_cce=" << advertise_cce;
    return true;
}

AmbiorixVariantSmartPtr ap_wlan_hal_whm::get_last_assoc_frame(const std::string &vap_iface,
                                                              const std::string &sta_mac)
{
    AmbiorixVariant data;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child("mac", sta_mac);

    std::string ap_path{};
    bool ret =
        m_ambiorix_cl.resolve_path(wbapi_utils::search_path_ap_by_iface(vap_iface), ap_path);
    if (!ret) {
        LOG(ERROR) << "can't resolve " << wbapi_utils::search_path_ap_by_iface(vap_iface);
    } else {
        LOG(DEBUG) << "get assoc frame path " << ap_path << " for " << sta_mac;
    }

    ret = m_ambiorix_cl.call(ap_path, "getLastAssocReq", args, data);

    AmbiorixVariantSmartPtr result = data.find_child(0);
    if (!ret || !result) {
        LOG(ERROR) << "getLastAssocReq() failed!";
    } else {
        result->detach();
    }

    return result;
}

bool ap_wlan_hal_whm::process_radio_event(const std::string &interface, const std::string &key,
                                          const AmbiorixVariant *value)
{
    if (key == "Status") {
        std::string status = value->get<std::string>();
        if (status.empty()) {
            return true;
        }
        LOG(WARNING) << "radio " << interface << " status " << status;
    } else if (key == "AccessPointNumberOfEntries") {
        LOG(WARNING) << "request updating vaps list of radio " << interface;
        event_queue_push(Event::APS_update_list);
        return true;
    }
    return true;
}

bool ap_wlan_hal_whm::process_ap_event(const std::string &interface, const std::string &key,
                                       const AmbiorixVariant *value)
{
    auto vap_id = get_vap_id_with_bss(interface);
    if (vap_id == beerocks::IFACE_ID_INVALID) {
        return true;
    }
    if (key == "Status") {
        std::string status = value->get<std::string>();
        if (status.empty()) {
            return true;
        }
        LOG(WARNING) << "vap " << interface << " status " << status;
        if (status == "Enabled") {
            auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_ENABLED_NOTIFICATION));
            auto msg      = reinterpret_cast<sHOSTAP_ENABLED_NOTIFICATION *>(msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sHOSTAP_ENABLED_NOTIFICATION));
            msg->vap_id = vap_id;
            event_queue_push(Event::AP_Enabled, msg_buff);
        } else {
            refresh_vaps_info(vap_id);
            auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_DISABLED_NOTIFICATION));
            auto msg      = reinterpret_cast<sHOSTAP_DISABLED_NOTIFICATION *>(msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sHOSTAP_DISABLED_NOTIFICATION));
            msg->vap_id = vap_id;
            event_queue_push(Event::AP_Disabled, msg_buff);
        }
    }
    return true;
}

bool ap_wlan_hal_whm::process_sta_event(const std::string &interface, const std::string &sta_mac,
                                        const std::string &key, const AmbiorixVariant *value)
{
    auto vap_id = get_vap_id_with_bss(interface);
    if (key == "AuthenticationState") {
        bool connected = value->get<bool>();
        if (connected) {
            auto msg_buff =
                ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));
            auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION *>(
                msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";

            // Initialize the message
            memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));

            auto answer = get_last_assoc_frame(interface, sta_mac);
            if (!answer) {
                LOG(ERROR) << "fail to get last frame";
                return true;
            }

            msg->params.vap_id = vap_id;
            msg->params.bssid  = tlvf::mac_from_string(m_radio_info.available_vaps[vap_id].mac);
            LOG(WARNING) << "Connected station " << sta_mac << " over vap " << interface;

            msg->params.mac          = tlvf::mac_from_string(sta_mac);
            msg->params.capabilities = {};

            //init the freq band cap with the target radio freq band info
            msg->params.capabilities.band_5g_capable = m_radio_info.is_5ghz;
            msg->params.capabilities.band_2g_capable =
                (son::wireless_utils::which_freq_type(m_radio_info.vht_center_freq) ==
                 beerocks::eFreqType::FREQ_24G);
            msg->params.association_frame_length = 0;

            std::string frame_body_str;
            if (!answer->read_child<>(frame_body_str, "frame") || frame_body_str.empty()) {
                LOG(WARNING) << "STA connected without previously receiving a "
                                "(re-)association frame!";
            } else {
                auto assoc_frame_type = assoc_frame::AssocReqFrame::UNKNOWN;
                // Tunnel the Management request to the controller
                auto management_frame = create_mgmt_frame_notification(frame_body_str.c_str());
                if (management_frame) {
                    event_queue_push(Event::MGMT_Frame, management_frame);
                    msg->params.bssid = management_frame->bssid;
                    auto mac          = tlvf::mac_to_string(management_frame->bssid);
                    vap_id            = get_vap_id_with_mac(mac);
                    if (check_vap_id(vap_id)) {
                        msg->params.vap_id = vap_id;
                    }
                    auto &frame_body = management_frame->data;
                    // Add the latest association frame
                    std::copy(frame_body.begin(), frame_body.end(), msg->params.association_frame);
                    msg->params.association_frame_length = frame_body.size();
                    assoc_frame_type = assoc_frame::AssocReqFrame::ASSOCIATION_REQUEST;
                    if (management_frame->type == eManagementFrameType::REASSOCIATION_REQUEST) {
                        assoc_frame_type = assoc_frame::AssocReqFrame::REASSOCIATION_REQUEST;
                    }

                    auto assoc_frame = assoc_frame::AssocReqFrame::parse(
                        msg->params.association_frame, msg->params.association_frame_length,
                        assoc_frame_type);

                    auto res = son::assoc_frame_utils::get_station_capabilities_from_assoc_frame(
                        assoc_frame, msg->params.capabilities);
                    if (!res) {
                        LOG(ERROR) << "Failed to get station capabilities.";
                    } else {
                        son::wireless_utils::print_station_capabilities(msg->params.capabilities);
                    }
                }
            }

            // Add the message to the queue
            event_queue_push(Event::STA_Connected, msg_buff);

        } else {
            auto msg_buff =
                ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION));
            auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION *>(
                msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";

            // Initialize the message
            memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION));

            msg->params.mac    = tlvf::mac_from_string(sta_mac);
            msg->params.vap_id = vap_id;

            LOG(WARNING) << "disconnected station " << sta_mac << " from vap " << interface;

            event_queue_push(Event::STA_Disconnected, msg_buff);
        }
    }

    return true;
}

bool ap_wlan_hal_whm::process_ap_bss_event(const std::string &interface,
                                           const beerocks::wbapi::AmbiorixVariant *event_data)
{
    std::string name_notification;
    event_data->read_child(name_notification, "notification");
    if (name_notification == AMX_CL_BSS_TM_RESPONSE_EVT) {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE));
        auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE));

        // Client params
        std::string data;
        event_data->read_child(data, "PeerMacAddress");
        msg->params.mac = tlvf::mac_from_string(data);
        int32_t status_code(UINT32_MAX);
        event_data->read_child(status_code, "StatusCode");

        auto vap_id = get_vap_id_with_bss(interface);
        if (vap_id == beerocks::IFACE_ID_INVALID) {
            LOG(ERROR) << "Invalid vap_id";
            return false;
        }
        msg->params.source_bssid = tlvf::mac_from_string(m_radio_info.available_vaps[vap_id].mac);

        msg->params.status_code = status_code;
        if (msg->params.status_code == 0) {
            event_data->read_child(data, "TargetBssid");
            msg->params.target_bssid = tlvf::mac_from_string(data);
        } else {
            LOG(ERROR) << "BSS Transition Management Query for station " << msg->params.mac
                       << " has been rejected with Status code = " << msg->params.status_code;
        }

        LOG(DEBUG) << "BTM Response with mac= " << msg->params.mac
                   << " status_code= " << msg->params.status_code
                   << " source_bssid= " << msg->params.source_bssid
                   << " target_bssid= " << msg->params.target_bssid;

        // Add the message to the queue
        event_queue_push(Event::BSS_TM_Response, msg_buff);
    }
    return true;
}

bool ap_wlan_hal_whm::set(const std::string &param, const std::string &value, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

int ap_wlan_hal_whm::add_bss(std::string &ifname, son::wireless_utils::sBssInfoConf &bss_conf,
                             std::string &bridge, bool vbss)
{
    // Virtual bss will not be covered by the pwhm, for now!
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_whm::remove_bss(std::string &ifname)
{
    // Virtual bss will not be covered by the pwhm, for now!
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_whm::add_key(const std::string &ifname, const sKeyInfo &key_info)
{
    // Virtual bss will not be covered by the pwhm, for now!
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_whm::add_station(const std::string &ifname, const sMacAddr &mac,
                                  std::vector<uint8_t> &raw_assoc_req)
{
    // Virtual bss will not be covered by the pwhm, for now!
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_whm::get_key(const std::string &ifname, sKeyInfo &key_info)
{
    // Virtual bss will not be covered by the pwhm, for now!
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_whm::send_delba(const std::string &ifname, const sMacAddr &dst,
                                 const sMacAddr &src, const sMacAddr &bssid)
{
    // Virtual bss will not be covered by the pwhm, for now!
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

void ap_wlan_hal_whm::send_unassoc_sta_link_metric_query(
    std::shared_ptr<wfa_map::tlvUnassociatedStaLinkMetricsQuery> &query)
{
}

bool ap_wlan_hal_whm::prepare_unassoc_sta_link_metrics_response(
    std::shared_ptr<wfa_map::tlvUnassociatedStaLinkMetricsResponse> &response)
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_whm::set_beacon_da(const std::string &ifname, const sMacAddr &mac)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::update_beacon(const std::string &ifname)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool ap_wlan_hal_whm::set_no_deauth_unknown_sta(const std::string &ifname, bool value)
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
