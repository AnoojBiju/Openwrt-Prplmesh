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

static ap_wlan_hal::Event wpaCtrl_to_bwl_event(const std::string &opcode)
{
    if (opcode == "DFS-CAC-START") {
        return ap_wlan_hal::Event::DFS_CAC_Started;
    } else if (opcode == "DFS-CAC-COMPLETED") {
        return ap_wlan_hal::Event::DFS_CAC_Completed;
    } else if (opcode == "DFS-NOP-FINISHED") {
        return ap_wlan_hal::Event::DFS_NOP_Finished;
    } else if (opcode == "CTRL-EVENT-EAP-FAILURE") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Failure;
    } else if (opcode == "CTRL-EVENT-EAP-FAILURE2") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Failure2;
    } else if (opcode == "CTRL-EVENT-EAP-TIMEOUT-FAILURE") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Timeout_Failure;
    } else if (opcode == "CTRL-EVENT-EAP-TIMEOUT-FAILURE2") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Timeout_Failure2;
    } else if (opcode == "CTRL-EVENT-SAE-UNKNOWN-PASSWORD-IDENTIFIER") {
        return ap_wlan_hal::Event::WPA_Event_SAE_Unknown_Password_Identifier;
    } else if (opcode == "AP-STA-POSSIBLE-PSK-MISMATCH") {
        return ap_wlan_hal::Event::AP_Sta_Possible_Psk_Mismatch;
    }

    return ap_wlan_hal::Event::Invalid;
}

static uint8_t wpaCtrl_bw_to_beerocks_bw(const uint8_t width)
{
    std::map<uint8_t, beerocks::eWiFiBandwidth> bandwidths{
        {0 /*CHAN_WIDTH_20_NOHT*/, beerocks::BANDWIDTH_20},
        {1 /*CHAN_WIDTH_20     */, beerocks::BANDWIDTH_20},
        {2 /*CHAN_WIDTH_40     */, beerocks::BANDWIDTH_40},
        {3 /*CHAN_WIDTH_80     */, beerocks::BANDWIDTH_80},
        {4 /*CHAN_WIDTH_80P80  */, beerocks::BANDWIDTH_80_80},
        {5 /*CHAN_WIDTH_160    */, beerocks::BANDWIDTH_160},
    };

    auto it = bandwidths.find(width);
    if (it == bandwidths.end()) {
        LOG(ERROR) << "Invalid bandwidth value: " << width;
        return beerocks::BANDWIDTH_UNKNOWN;
    }

    return it->second;
}

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
    int amx_fd = m_ambiorix_cl.get_fd();
    LOG_IF((amx_fd == -1), FATAL) << "Failed to get amx  fd";
    int amxp_fd = m_ambiorix_cl.get_signal_fd();
    LOG_IF((amxp_fd == -1), FATAL) << "Failed to get amx signal fd";

    m_fds_ext_events = {amx_fd, amxp_fd};
    subscribe_to_radio_events();
    subscribe_to_radio_channel_change_events();
    subscribe_to_ap_events();
    subscribe_to_sta_events();
    subscribe_to_ap_bss_tm_events();
    subscribe_to_ap_mgmt_frame_events();
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
    auto event_handler        = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type = AMX_CL_BSS_TM_RESPONSE_EVT;

    event_handler->callback_fn = [this](AmbiorixVariant &event_data) -> void {
        std::string ap_path;
        if (!event_data.read_child(ap_path, "path") || ap_path.empty()) {
            return;
        }
        auto vap_it =
            std::find_if(m_vapsExtInfo.begin(), m_vapsExtInfo.end(),
                         [&](const auto &element) { return element.second.path == ap_path; });
        if (vap_it == m_vapsExtInfo.end()) {
            LOG(DEBUG) << "vap_it not found";
            return;
        }
        LOG(DEBUG) << "event from iface " << vap_it->first;

        process_ap_bss_event(vap_it->first, &event_data);
    };

    std::string filter = "(path matches '" + wbapi_utils::search_path_ap() +
                         "[0-9]+.$')"
                         " && (notification == '" +
                         AMX_CL_BSS_TM_RESPONSE_EVT + "')";

    m_ambiorix_cl.subscribe_to_object_event(wbapi_utils::search_path_ap(), event_handler, filter);
}

void ap_wlan_hal_whm::subscribe_to_ap_mgmt_frame_events()
{
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_MGMT_ACT_FRAME_EVT;
    event_handler->callback_fn = [this](AmbiorixVariant &event_data) -> void {
        std::string ap_path;
        if (!event_data.read_child(ap_path, "path") || ap_path.empty()) {
            return;
        }

        auto vap_it =
            std::find_if(m_vapsExtInfo.begin(), m_vapsExtInfo.end(),
                         [&](const auto &element) { return element.second.path == ap_path; });
        if (vap_it == m_vapsExtInfo.end()) {
            LOG(DEBUG) << "vap_it not found";
            return;
        }
        LOG(DEBUG) << "event from iface " << vap_it->first;

        process_ap_bss_event(vap_it->first, &event_data);
    };

    std::string filter = "(path matches '" + wbapi_utils::search_path_ap() +
                         "[0-9]+.$')"
                         " && (notification == '" +
                         AMX_CL_MGMT_ACT_FRAME_EVT + "')";

    m_ambiorix_cl.subscribe_to_object_event(wbapi_utils::search_path_ap(), event_handler, filter);
}

bool ap_wlan_hal_whm::enable()
{
    // API enable is not required with "PWHM",
    // it's usage is only during WPS (some propietary use-case) in non PWHM scenario.
    // WPS functionality in with PWHM scenario works as expected.
    // Conclusion: API usuage during WPS (propietary use-case), not needed with PWHM.
    // Hence no implementation is required.
    return true;
}

bool ap_wlan_hal_whm::disable()
{
    // API disable is not required with "PWHM",
    // it's usage is only during WPS (some propietary use-case) in non PWHM scenario.
    // WPS functionality in with PWHM scenario works as expected.
    // Conclusion: API usuage during WPS (propietary use-case), not needed with PWHM.
    // Hence no implementation is required.
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
        new_obj.add_child("Mode", "BlackList");
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
    int new_vap_index = m_radio_info.available_vaps.size();

    for (auto bss_info_conf : bss_info_conf_list) {
        std::string wifi_vap_path, wifi_ssid_path;
        std::string ifname = "new_interface";

        auto bssid = tlvf::mac_to_string(bss_info_conf.bssid);
        int vap_id = get_vap_id_with_mac(bssid);

        if (!check_vap_id(vap_id) || (bssid == beerocks::net::network_utils::WILD_MAC_STRING)) {
            LOG(DEBUG) << "create new vap for wildcard bssid";

            auto freq_name = wbapi_utils::band_short_name(m_radio_info.frequency_band);

            std::string new_vap_name = "vap" + freq_name + std::to_string(new_vap_index++);

            std::string radio_name;
            if (!m_ambiorix_cl.get_param(radio_name, m_radio_path, "Alias")) {
                LOG(ERROR) << "cannot read radio name for " << m_radio_path;
                continue;
            }

            LOG(INFO) << "calling addVAPIntf with radio name " << radio_name << " vap name "
                      << new_vap_name;

            AmbiorixVariant result;
            AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
            args.add_child("vap", new_vap_name);
            args.add_child("radio", radio_name);

            m_ambiorix_cl.call("Device.WiFi.", "addVAPIntf", args, result);

            // ex of call: Device.WiFi.addVAPIntf(vap="new5g10", radio="radio2")
            // use the parameter 'vap', "new5g10", as Alias to retrieve the new
            // SSID instance; from there, retrieve AccessPoint by SSIDReference;

            std::string search_path = wbapi_utils::search_path_ssid_by_alias(new_vap_name);
            if (!m_ambiorix_cl.resolve_path(search_path, wifi_ssid_path)) {
                LOG(ERROR) << "new SSID not found";
                continue;
            }

            search_path = wbapi_utils::search_path_ap_by_ssidRef(wifi_ssid_path);
            if (!m_ambiorix_cl.resolve_path(search_path, wifi_vap_path)) {
                LOG(ERROR) << "new AccessPoint not found";
                continue;
            }

            LOG(INFO) << "added new instances " << wifi_ssid_path << " " << wifi_vap_path;

            args.set_type(AMXC_VAR_ID_HTABLE);
            args.add_child("BridgeInterface", "br-lan");
            args.add_child("IEEE80211kEnabled", 1);
            args.add_child("WDSEnable", 1);
            if (!m_ambiorix_cl.update_object(wifi_vap_path, args)) {
                LOG(INFO) << "cannot set bridge, 11k and wds for " << wifi_vap_path;
                //continue;
                // no continue here since these parameters are supposed to be handled
                // by other EasyMesh messages : ex bridging - traffic separation policy;
                // or not handled by EasyMesh : ex WDSEnable;
            }
        } else {
            auto &vap_info = m_radio_info.available_vaps[vap_id];
            ifname         = vap_info.bss;
            auto vap_it    = m_vapsExtInfo.find(ifname);
            if (vap_it == m_vapsExtInfo.end()) {
                LOG(ERROR) << "fail to get ifname of " << bssid;
                continue;
            }
            wifi_vap_path  = vap_it->second.path;
            wifi_ssid_path = vap_it->second.ssid_path;

            LOG(DEBUG) << "updating AP " << wifi_vap_path << " SSID " << wifi_ssid_path
                       << " ifname " << ifname << " vap_id " << std::to_string(vap_id);
        }
        /* here we need to know the :
        * wifi_vap_path
        * wifi_ssid_path
        * */

        AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
        if (bss_info_conf.teardown) {
            auto &vap_info          = m_radio_info.available_vaps[vap_id];
            ifname                  = vap_info.bss;
            auto vap_it             = m_vapsExtInfo.find(ifname);
            vap_it->second.teardown = true;
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
        new_obj.add_child("SSID", bss_info_conf.ssid);
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
        new_obj.add_child("ModeEnabled", security_mode);
        if (security_mode == "None") {
            new_obj.add_child("EncryptionMode", "Default");
        } else {
            new_obj.add_child("EncryptionMode", encryption_mode);
            new_obj.add_child("KeyPassPhrase", bss_info_conf.network_key);
        }
        ret = m_ambiorix_cl.update_object(wifi_ap_sec_path, new_obj);

        if (!ret) {
            LOG(ERROR) << "Failed to update Security object " << wifi_ap_sec_path;
            continue;
        }
        if (ifname == "new_interface") {
            // skip update of vap_info, new instance in vap_info will be added asynchronously on a pwhm event
            continue;
        }

        auto &vap_info      = m_radio_info.available_vaps[vap_id];
        ifname              = vap_info.bss;
        auto vap_it         = m_vapsExtInfo.find(ifname);
        bool &prev_teardown = vap_it->second.teardown;

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

    if (m_unassociated_stations.empty()) {
        subscribe_to_rssi_eventing_events();
    }
    m_unassociated_stations.insert(mac);

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
    /*
* TODO: Below channel BW override is a temporary solution to overcome sniffer
* issues in WFA EasyMesh cert testing as mentioned in PPM-2638.
* Needs to be removed once sniffer issues resolved.
*/
    bool certification_mode = get_hal_conf().certification_mode;
    if (certification_mode) {
        LOG(INFO) << "In Certification mode, overriding bw to 20MHz";
        bw = BANDWIDTH_20;
    }

    AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);
    bool amx_ret, status = true;

    if (bw == beerocks::eWiFiBandwidth::BANDWIDTH_40) {

        auto freq_type = son::wireless_utils::which_freq_type(vht_center_frequency);
        int freq       = son::wireless_utils::channel_to_freq(chan, freq_type);

        // Extension Channel
        if (freq < vht_center_frequency) {
            new_obj.add_child("ExtensionChannel", "AboveControlChannel");
        } else {
            new_obj.add_child("ExtensionChannel", "BelowControlChannel");
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
    m_ambiorix_cl.get_param(power_list_str, m_radio_path, "TransmitPowerSupported");

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
    new_obj.add_child("TransmitPower", int8_t(new_value));
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
            if (!answer->read_child(frame_body_str, "frame") || frame_body_str.empty()) {
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

static bool set_mbo_assoc_disallow_vap(beerocks::wbapi::AmbiorixClient &ambiorix_cl,
                                       const std::string &vap_path, bool enable)
{
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);

    std::string reason = enable ? "Unspecified" : "Off";

    args.add_child("MBOAssocDisallowReason", reason);

    bool ret = ambiorix_cl.update_object(vap_path, args);

    if (!ret) {
        LOG(ERROR) << "vap " << vap_path << " set MBOEnable/MBOAssocDisallow:" << reason
                   << " failed";
    }
    return ret;
}

bool ap_wlan_hal_whm::set_mbo_assoc_disallow(const std::string &bssid, bool enable)
{
    int vap_id = get_vap_id_with_mac(bssid);
    if (!check_vap_id(vap_id)) {
        LOG(ERROR) << "no matching vap_id for bssid " << bssid;
        return false;
    }
    auto &vap_info = m_radio_info.available_vaps[vap_id];
    auto &ifname   = vap_info.bss;
    auto vap_it    = m_vapsExtInfo.find(ifname);
    if (vap_it == m_vapsExtInfo.end()) {
        LOG(ERROR) << "fail to get ifname of " << bssid;
        return false;
    }

    return set_mbo_assoc_disallow_vap(m_ambiorix_cl, vap_it->second.path, enable);
}

bool ap_wlan_hal_whm::set_radio_mbo_assoc_disallow(bool enable)
{
    bool ret = true;
    for (const auto &vap_it : m_vapsExtInfo) {
        if (!set_mbo_assoc_disallow_vap(m_ambiorix_cl, vap_it.second.path, enable)) {
            ret = false;
        }
    }
    return ret;
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
    bool ret = m_ambiorix_cl.resolve_path(wbapi_utils::search_path_ap_by_iface(vap_iface), ap_path);
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
    } else if (key == "Channel") {

        refresh_radio_info();
        // Event not processed by ap_manager.cpp (agent)
        event_queue_push(Event::CTRL_Channel_Switch);
        return true;
    } else if (key == "AccessPointNumberOfEntries") {
        LOG(WARNING) << "request updating vaps list of radio " << interface;
        event_queue_push(Event::APS_update_list);
        return true;
    }
    return true;
}

bool ap_wlan_hal_whm::process_radio_channel_change_event(const AmbiorixVariant *value)
{

    auto parameters = value->find_child("Updates");
    if (!parameters || parameters->empty()) {
        LOG(DEBUG) << "Received event without Updates parameter";
        return false;
    }
    std::string chan_change_reason;
    if (!parameters->read_child(chan_change_reason, "ChannelChangeReason")) {
        LOG(DEBUG) << "Received event without ChannelChangeReason parameter" << chan_change_reason;
        return false;
    }
    if (chan_change_reason != "MANUAL" && chan_change_reason != "AUTO") {
        LOG(DEBUG) << "chan_change_reason other than MANUAL or AUTO:" << chan_change_reason;
        return false;
    }
    event_queue_push(Event::CSA_Finished);
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
            if (!answer->read_child(frame_body_str, "frame") || frame_body_str.empty()) {
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
    if (event_data == nullptr) {
        LOG(WARNING) << "event_data null";
        return false;
    }
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
    } else if (name_notification == AMX_CL_MGMT_ACT_FRAME_EVT) {

        std::string frame_body_str;
        if (!event_data->read_child<>(frame_body_str, "frame") || frame_body_str.empty()) {
            LOG(WARNING) << "Unable to retrieve MGMT Frame from pwhm notification";
        }

        auto management_frame = create_mgmt_frame_notification(frame_body_str.c_str());
        if (management_frame) {
            event_queue_push(Event::MGMT_Frame, management_frame);
        } else {
            LOG(ERROR) << "creage_mgmt_frame_notification failed";
        }
    }
    return true;
}

bool ap_wlan_hal_whm::process_wpa_ctrl_event(const beerocks::wbapi::AmbiorixVariant &event_data)
{
    std::string event_str;
    if (!event_data.read_child<>(event_str, "eventData") || event_str.empty()) {
        LOG(WARNING) << "Unable to retrieve wpaCtrl event data from pwhm notification";
        return false;
    }
    LOG(DEBUG) << "wpaCtrl event: " << event_str;

    std::string interface;
    if (!event_data.read_child<>(interface, "ifName") || interface.empty()) {
        LOG(WARNING) << "Unable to retrieve ifName from pwhm notification";
        return false;
    }
    LOG(DEBUG) << "interface: " << interface;

    bwl::parsed_line_t parsed_obj;
    parse_event(event_str, parsed_obj);

    std::string opcode;
    if (!(parsed_obj.find(bwl::EVENT_KEYLESS_PARAM_OPCODE) != parsed_obj.end() &&
          !(opcode = parsed_obj[bwl::EVENT_KEYLESS_PARAM_OPCODE]).empty())) {
        return false;
    }

    auto event = wpaCtrl_to_bwl_event(opcode);

    switch (event) {

    case Event::DFS_CAC_Started: {
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION));
        auto msg = reinterpret_cast<sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION *>(
            msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION));

        // Channel
        msg->params.channel = beerocks::string_utils::stoi(parsed_obj["chan"]);

        // Secondary Channel
        std::string tmp_string = parsed_obj["sec_chan"];
        beerocks::string_utils::rtrim(tmp_string, ",");
        msg->params.secondary_channel = beerocks::string_utils::stoi(tmp_string);

        // Bandwidth
        tmp_string = parsed_obj["width"];
        beerocks::string_utils::rtrim(tmp_string, ",");
        msg->params.bandwidth = beerocks::eWiFiBandwidth(
            wpaCtrl_bw_to_beerocks_bw(beerocks::string_utils::stoi(tmp_string)));

        // CAC Duration
        tmp_string = parsed_obj["cac_time"];
        beerocks::string_utils::rtrim(tmp_string, "s");
        msg->params.cac_duration_sec = beerocks::string_utils::stoi(tmp_string);

        // Add the message to the queue
        event_queue_push(Event::DFS_CAC_Started, msg_buff);
        break;
    }
    case Event::DFS_CAC_Completed: {
        if (!get_radio_info().is_5ghz) {
            LOG(WARNING) << "interface: " << interface << " not 5GHz radio!";
            return true;
        }

        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION));
        auto msg = reinterpret_cast<sACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION *>(
            msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION));

        // CAC Status
        std::string success = parsed_obj["cac_status"];
        if (success.empty()) {
            // Some wpaCtrl_events still received with "success" parameter and we should support it as well
            success = parsed_obj["success"];
            if (success.empty()) {
                LOG(ERROR) << "Failed reading cac finished success parameter!";
                return false;
            }
        }
        msg->params.success = beerocks::string_utils::stoi(success);

        // Frequency
        msg->params.frequency = beerocks::string_utils::stoi(parsed_obj["freq"]);

        // Center frequency 1
        msg->params.center_frequency1 = beerocks::string_utils::stoi(parsed_obj["cf1"]);

        // Center frequency 2
        msg->params.center_frequency2 = beerocks::string_utils::stoi(parsed_obj["cf2"]);

        // Channel
        msg->params.channel = son::wireless_utils::freq_to_channel(msg->params.frequency);

        // Timeout
        std::string timeout = parsed_obj["timeout"];
        if (!timeout.empty()) {
            msg->params.timeout = beerocks::string_utils::stoi(timeout);
        }

        // Bandwidth
        msg->params.bandwidth =
            wpaCtrl_bw_to_beerocks_bw(beerocks::string_utils::stoi(parsed_obj["chan_width"]));

        // Add the message to the queue
        event_queue_push(Event::DFS_CAC_Completed, msg_buff);
        break;
    }
    case Event::DFS_NOP_Finished: {
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION));
        auto msg = reinterpret_cast<sACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION *>(
            msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0,
               sizeof(sACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION));

        // Frequency
        msg->params.frequency = beerocks::string_utils::stoi(parsed_obj["freq"]);

        // Channel
        msg->params.channel = son::wireless_utils::freq_to_channel(msg->params.frequency);

        // Bandwidth
        msg->params.bandwidth =
            wpaCtrl_bw_to_beerocks_bw(beerocks::string_utils::stoi(parsed_obj["chan_width"]));

        // Center frequency
        msg->params.vht_center_frequency = beerocks::string_utils::stoi(parsed_obj["cf1"]);

        // Add the message to the queue
        event_queue_push(Event::DFS_NOP_Finished, msg_buff);
        break;
    }
    case Event::WPA_Event_EAP_Failure:
    case Event::WPA_Event_EAP_Failure2:
    case Event::WPA_Event_EAP_Timeout_Failure:
    case Event::WPA_Event_EAP_Timeout_Failure2:
    case Event::WPA_Event_SAE_Unknown_Password_Identifier:
    case Event::AP_Sta_Possible_Psk_Mismatch: {
        /* example PSK Mismatch notification
            eobject = "WiFi.AccessPoint.[vap5g0priv].",
            eventData = "<3>AP-STA-POSSIBLE-PSK-MISMATCH 6c:f7:84:d8:32:af",
            ifName = "wlan2.1",
            notification = "wpaCtrlEvents",
            object = "WiFi.AccessPoint.vap5g0priv.",
            path = "WiFi.AccessPoint.1."
        */
        auto vap_id    = get_vap_id_with_bss(interface);
        auto iface_ids = beerocks::utils::get_ids_from_iface_string(interface);
        if ((vap_id < 0) && (iface_ids.vap_id != beerocks::IFACE_RADIO_ID)) {
            LOG(DEBUG) << "Unknown vap_id " << vap_id;
        }

        LOG(DEBUG) << "STA Connection Failure";
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sStaConnectionFail));
        auto msg      = reinterpret_cast<sStaConnectionFail *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sStaConnectionFail));

        // STA Mac Address
        msg->sta_mac = tlvf::mac_from_string(parsed_obj[bwl::EVENT_KEYLESS_PARAM_MAC]);
        LOG(DEBUG) << "STA connection failure: offending Sta MAC: " << msg->sta_mac;

        // BSSID
        msg->bssid = tlvf::mac_from_string(m_radio_info.available_vaps[vap_id].mac);
        LOG(DEBUG) << "STA connection failure: interface BSSID: " << msg->bssid;

        // Add the message to the queue
        event_queue_push(event, msg_buff);
        break;
    }
    // Unhandled events
    default:
        LOG(ERROR) << "Unhandled event received: " << int(event);
        break;
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

bool ap_wlan_hal_whm::configure_service_priority(const uint8_t *dscp)
{
    unsigned char i = 0, j = 0, k = 0;
    struct range_t {
        int start;
        int end;
        int pcp;
    } range[8] = {};
    struct map_t {
        int dscp;
        int pcp;
    } exception[64] = {};
    std::stringstream ss;

    for (i = 0; i < 8; i++) {
        range[i].start = -1;
        range[i].end   = -1;
        range[i].pcp   = i;
    }
    for (i = 0; i < 64; i++) {
        exception[i].dscp = -1;
        exception[i].pcp  = -1;
    }
    for (i = 0; i < 64; i++) {
        if ((i != 63) && dscp[i] == dscp[i + 1]) {
            for (j = i + 1; j < 64; j++) {
                if (j == 63 || dscp[j] != dscp[j + 1]) {
                    if ((j - i) >= (range[dscp[j]].end - range[dscp[j]].start)) {
                        range[dscp[j]].start = i;
                        range[dscp[j]].end   = j;
                        i                    = j;
                        break;
                    }
                } else {
                    continue;
                }
            }
        }
    }
    for (i = 0; i < 8; i++) {
        LOG(DEBUG) << "range[" << +i << "] : start = " << +range[i].start
                   << ", end = " << +range[i].end;
    }
    for (i = 0, j = 0; i < 64; i++) {
        for (k = 0; k < 8; k++) {
            if ((i >= range[k].start) && (i <= range[k].end)) {
                break;
            }
        }
        if (k == 8) {
            exception[j].pcp    = dscp[i];
            exception[j++].dscp = i;
        }
    }
    for (i = 0; i < 64; i++) {
        if (exception[i].dscp == 255) {
            break;
        }
    }
    for (i = 0; i < 21; i++) {
        if (exception[i].dscp == 255) {
            break;
        }
        ss << +exception[i].dscp << "," << +exception[i].pcp << ",";
    }
    for (i = 0; i < 8; i++) {
        ss << +range[i].start << "," << +range[i].end << ",";
    }
    ss.seekp(-1, std::ios_base::end);

    std::string qos_map = std::move(ss).str();
    LOG(DEBUG) << "Setting QOS_MAP_SET " << qos_map;

    auto search_path = wbapi_utils::search_path_ap_by_iface(get_iface_name());

    std::vector<std::string> paths;
    if (!m_ambiorix_cl.resolve_path_multi(search_path, paths)) {
        LOG(ERROR) << "Could not resolve " << search_path;
        return false;
    }

    for (const auto &path : paths) {
        AmbiorixVariant new_map(AMXC_VAR_ID_HTABLE);
        new_map.add_child("QoSMapSet", qos_map);

        if (!m_ambiorix_cl.update_object(path + "IEEE80211u.", new_map)) {
            LOG(ERROR) << "Could not set QoSMapSet for " << path;
            return false;
        }
    }

    return true;
}

bool ap_wlan_hal_whm::set_spatial_reuse_config(
    son::wireless_utils::sSpatialReuseParams &spatial_reuse_params)
{
    std::string path_to_80211ax = m_radio_path + "IEEE80211ax.";
    AmbiorixVariant new_obj(AMXC_VAR_ID_HTABLE);

    new_obj.add_child("BssColor", spatial_reuse_params.bss_color);
    new_obj.add_child("BssColorPartial", spatial_reuse_params.partial_bss_color);
    new_obj.add_child("HESIGASpatialReuseValue15Allowed",
                      spatial_reuse_params.hesiga_spatial_reuse_value15_allowed);
    new_obj.add_child("SRGInformationValid", spatial_reuse_params.srg_information_valid);
    new_obj.add_child("NonSRGOffsetValid", spatial_reuse_params.non_srg_offset_valid);
    new_obj.add_child("PSRDisallowed", spatial_reuse_params.psr_disallowed);

    if (spatial_reuse_params.non_srg_offset_valid) {
        new_obj.add_child("NonSRGOBSSPDMaxOffset", spatial_reuse_params.non_srg_obsspd_max_offset);
    }

    if (spatial_reuse_params.srg_information_valid) {
        new_obj.add_child("SRGOBSSPDMinOffset", spatial_reuse_params.srg_obsspd_min_offset);
        new_obj.add_child("SRGOBSSPDMaxOffset", spatial_reuse_params.srg_obsspd_max_offset);
        new_obj.add_child("SRGBSSColorBitmap",
                          get_bss_color_bitmap(spatial_reuse_params.srg_bss_color_bitmap));
        new_obj.add_child("SRGPartialBSSIDBitmap",
                          get_bss_color_bitmap(spatial_reuse_params.srg_partial_bssid_bitmap));
    }
    if (!m_ambiorix_cl.update_object(path_to_80211ax, new_obj)) {
        LOG(ERROR) << "Could not set spatial reuse parameters for " << path_to_80211ax;
        return false;
    }

    return true;
}

bool ap_wlan_hal_whm::get_spatial_reuse_config(
    son::wireless_utils::sSpatialReuseParams &spatial_reuse_params)
{
    std::string path_to_80211ax = m_radio_path + "IEEE80211ax.";
    std::string string_bss_color_bitmap;
    std::string string_partial_bssid_bitmap;

    LOG(WARNING) << "get_spatial_reuse_config. path_to_80211ax" << path_to_80211ax;
    m_ambiorix_cl.get_param<>(spatial_reuse_params.bss_color, path_to_80211ax, "BssColor");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.partial_bss_color, path_to_80211ax,
                              "BssColorPartial");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.hesiga_spatial_reuse_value15_allowed,
                              path_to_80211ax, "HESIGASpatialReuseValue15Allowed");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.srg_information_valid, path_to_80211ax,
                              "SRGInformationValid");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.non_srg_offset_valid, path_to_80211ax,
                              "NonSRGOffsetValid");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.psr_disallowed, path_to_80211ax,
                              "PSRDisallowed");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.non_srg_obsspd_max_offset, path_to_80211ax,
                              "NonSRGOBSSPDMaxOffset");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.srg_obsspd_min_offset, path_to_80211ax,
                              "SRGOBSSPDMinOffset");
    m_ambiorix_cl.get_param<>(spatial_reuse_params.srg_obsspd_max_offset, path_to_80211ax,
                              "SRGOBSSPDMaxOffset");
    m_ambiorix_cl.get_param<>(string_bss_color_bitmap, path_to_80211ax, "SRGBSSColorBitmap");
    m_ambiorix_cl.get_param<>(string_partial_bssid_bitmap, path_to_80211ax,
                              "SRGPartialBSSIDBitmap");
    spatial_reuse_params.srg_bss_color_bitmap = get_uint64_from_bss_string(string_bss_color_bitmap);
    spatial_reuse_params.srg_partial_bssid_bitmap =
        get_uint64_from_bss_string(string_partial_bssid_bitmap);

    LOG(INFO) << "Get spatial reuse parameters. bss_color: " << spatial_reuse_params.bss_color
              << " partial_bss_color: " << spatial_reuse_params.partial_bss_color
              << " string_bss_color_bitmap: " << string_bss_color_bitmap
              << " string_partial_bssid_bitmap: " << string_partial_bssid_bitmap;
    return true;
}

void ap_wlan_hal_whm::process_rssi_eventing_event(const std::string &interface,
                                                  beerocks::wbapi::AmbiorixVariant *updates)
{
    auto vap_id = get_vap_id_with_bss(interface);

    if (updates == nullptr || updates->empty()) {
        return;
    }
    auto updates_list = updates->read_children<AmbiorixVariantListSmartPtr>();
    if (!updates_list) {
        return;
    }

    // list of hash_tables
    for (auto &update : *updates_list) { //update is a map
        auto station_map = update.read_children<AmbiorixVariantMapSmartPtr>();
        if (!station_map) {
            continue;
        }

        auto real_map = *station_map;

        std::string mac_address = real_map["MACAddress"];

        if (m_unassociated_stations.find(mac_address) != m_unassociated_stations.end()) {

            auto msg_buff =
                ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE));
            auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE *>(
                msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";

            // Initialize the message
            memset(msg_buff.get(), 0,
                   sizeof(sACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE));

            msg->params.rx_rssi = real_map["SignalStrength"];

            msg->params.rx_snr     = beerocks::SNR_INVALID;
            msg->params.result.mac = tlvf::mac_from_string(mac_address);
            msg->params.vap_id     = vap_id;

            event_queue_push(Event::STA_Unassoc_RSSI, msg_buff);

            //Rssi consumed --> lets remove the unassociated station
            m_unassociated_stations.erase(mac_address);
        }
    }
    if (m_unassociated_stations.empty()) {
        m_ambiorix_cl.unsubscribe_from_object_event(m_rssi_event_handler);
    }
}

} // namespace whm

std::shared_ptr<ap_wlan_hal> ap_wlan_hal_create(std::string iface_name, bwl::hal_conf_t hal_conf,
                                                base_wlan_hal::hal_event_cb_t callback)
{
    return std::make_shared<whm::ap_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
