/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "base_wlan_hal_whm.h"

#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <bwl/nl80211_client_factory.h>

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <easylogging++.h>

using namespace beerocks;
using namespace wbapi;

namespace bwl {
namespace whm {

base_wlan_hal_whm::base_wlan_hal_whm(HALType type, const std::string &iface_name,
                                     hal_event_cb_t callback, const hal_conf_t &hal_conf)
    : base_wlan_hal(type, iface_name, IfaceType::Intel, callback, hal_conf),
      beerocks::beerocks_fsm<whm_fsm_state, whm_fsm_event>(whm_fsm_state::Delay),
      m_iso_nl80211_client(nl80211_client_factory::create_instance())
{
    m_ambiorix_cl = std::make_shared<beerocks::wbapi::AmbiorixClient>();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client instance!";

    LOG_IF(!m_ambiorix_cl->connect(), FATAL) << "Unable to connect to the ambiorix backend!";

    m_fds_ext_events = {};

    m_ambiorix_cl->resolve_path(wbapi_utils::search_path_radio_by_iface(iface_name), m_radio_path);

    // Initialize the FSM
    fsm_setup();
}

base_wlan_hal_whm::~base_wlan_hal_whm() { base_wlan_hal_whm::detach(); }

void base_wlan_hal_whm::subscribe_to_radio_events()
{
    // subscribe to the WiFi.Radio.iface_name.Status
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_OBJECT_CHANGED_EVT;
    event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        auto parameters        = event_data.find_child("parameters");
        if (!parameters || parameters->empty()) {
            return;
        }
        auto params_map = parameters->read_childs<AmbiorixVariantMapSmartPtr>();
        if (!params_map) {
            return;
        }
        for (auto &param_it : *params_map) {
            auto key   = param_it.first;
            auto value = param_it.second.find_child("to");
            if (key.empty() || !value || value->empty()) {
                continue;
            }
            hal->process_radio_event(hal->get_iface_name(), key, value.get());
        }
    };
    event_handler->context = this;

    std::string filter = "(path matches '" + m_radio_path +
                         "$')"
                         " && (notification == '" +
                         AMX_CL_OBJECT_CHANGED_EVT +
                         "')"
                         " && (contains('parameters.Status'))";

    m_ambiorix_cl->subscribe_to_object_event(m_radio_path, event_handler, filter);
}

void base_wlan_hal_whm::subscribe_to_ap_events()
{
    std::string wifi_ap_path   = wbapi_utils::search_path_ap();
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_OBJECT_CHANGED_EVT;
    event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        std::string ap_path;
        if (!event_data.read_child<>(ap_path, "path") || ap_path.empty()) {
            return;
        }
        auto &vapsExtInfo = hal->m_vapsExtInfo;
        auto vap_it       = std::find_if(vapsExtInfo.begin(), vapsExtInfo.end(),
                                   [&](const std::pair<std::string, VAPExtInfo> &element) {
                                       return element.second.path == ap_path;
                                   });
        if (vap_it == vapsExtInfo.end()) {
            return;
        }
        LOG(WARNING) << "event from iface " << vap_it->first;
        auto parameters = event_data.find_child("parameters");
        if (!parameters || parameters->empty()) {
            return;
        }
        auto params_map = parameters->read_childs<AmbiorixVariantMapSmartPtr>();
        if (!params_map) {
            return;
        }
        for (auto &param_it : *params_map) {
            auto key   = param_it.first;
            auto value = param_it.second.find_child("to");
            if (key.empty() || !value || value->empty()) {
                continue;
            }
            if (key == "Status") {
                auto status = value->get<std::string>();
                if (status == "Enabled" && !hal->has_enabled_vap()) {
                    hal->process_radio_event(hal->get_iface_name(), "AccessPointNumberOfEntries",
                                             AmbiorixVariant::copy(1).get());
                }
                hal->process_ap_event(vap_it->first, key, value.get());
                vap_it->second.status = status;
            } else {
                hal->process_ap_event(vap_it->first, key, value.get());
            }
        }
    };
    event_handler->context = this;

    std::string filter = "(path matches '" + wifi_ap_path +
                         "[0-9]+.$')"
                         " && (notification == '" +
                         AMX_CL_OBJECT_CHANGED_EVT +
                         "')"
                         " && (contains('parameters.Status'))";

    m_ambiorix_cl->subscribe_to_object_event(wifi_ap_path, event_handler, filter);
}

void base_wlan_hal_whm::subscribe_to_sta_events()
{
    std::string wifi_ad_path   = wbapi_utils::search_path_ap() + "[0-9]+.AssociatedDevice.";
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_OBJECT_CHANGED_EVT;
    event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        std::string sta_path;
        if (!event_data.read_child<>(sta_path, "path") || sta_path.empty()) {
            return;
        }
        std::string ap_path = wbapi_utils::get_path_ap_of_assocDev(sta_path);
        auto &vapsExtInfo   = hal->m_vapsExtInfo;
        auto vap_it         = std::find_if(vapsExtInfo.begin(), vapsExtInfo.end(),
                                   [&](const std::pair<std::string, VAPExtInfo> &element) {
                                       return element.second.path == ap_path;
                                   });
        if (vap_it == vapsExtInfo.end()) {
            return;
        }
        auto &stations = hal->m_stations;
        auto sta_it    = std::find_if(stations.begin(), stations.end(),
                                   [&](const std::pair<std::string, STAExtInfo> &element) {
                                       return element.second.path == sta_path;
                                   });
        std::string sta_mac;
        auto sta_mac_obj = event_data.find_child_deep("parameters.MACAddress.to");
        if (sta_mac_obj && !sta_mac_obj->empty()) {
            sta_mac = sta_mac_obj->get<std::string>();
        } else if (sta_it != stations.end()) {
            sta_mac = sta_it->first;
        } else if (!hal->m_ambiorix_cl->get_param<>(sta_mac, sta_path, "MACAddress")) {
            LOG(WARNING) << "unknown sta path " << sta_path;
            return;
        }
        if (sta_it != stations.end()) {
            sta_it->second.path = sta_path;
        } else if (!sta_mac.empty()) {
            STAExtInfo staInfo;
            staInfo.path = sta_path;
            sta_it       = stations.insert(std::make_pair(sta_mac, staInfo)).first;
        } else {
            LOG(WARNING) << "missing station mac";
            return;
        }
        auto parameters = event_data.find_child("parameters");
        if (!parameters || parameters->empty()) {
            return;
        }
        auto params_map = parameters->read_childs<AmbiorixVariantMapSmartPtr>();
        if (!params_map) {
            return;
        }
        for (auto &param_it : *params_map) {
            auto key   = param_it.first;
            auto value = param_it.second.find_child("to");
            if (key.empty() || key == "MACAddress" || !value || value->empty()) {
                continue;
            }
            hal->process_sta_event(vap_it->first, sta_mac, key, value.get());
        }
    };
    event_handler->context = this;

    std::string filter = "(path matches '" + wifi_ad_path +
                         "[0-9]+.$')"
                         " && (notification == '" +
                         AMX_CL_OBJECT_CHANGED_EVT +
                         "')"
                         " && ((contains('parameters.AuthenticationState'))"
                         " || (contains('parameters.MACAddress')))";

    m_ambiorix_cl->subscribe_to_object_event(wifi_ad_path, event_handler, filter);

    // station instances cleanup
    auto sta_del_event_handler         = std::make_shared<sAmbiorixEventHandler>();
    sta_del_event_handler->event_type  = AMX_CL_INSTANCE_REMOVED_EVT;
    sta_del_event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        std::string sta_templ_path;
        uint32_t sta_index;
        if (!event_data.read_child<>(sta_templ_path, "path") || sta_templ_path.empty() ||
            !event_data.read_child<>(sta_index, "index") || !sta_index) {
            return;
        }
        std::string sta_path = sta_templ_path + std::to_string(sta_index) + ".";
        LOG(DEBUG) << "Station instance " << sta_path << " deleted";
        auto &stations = hal->m_stations;
        auto sta_it    = std::find_if(stations.begin(), stations.end(),
                                   [&](const std::pair<std::string, STAExtInfo> &element) {
                                       return element.second.path == sta_path;
                                   });
        if (sta_it != stations.end()) {
            LOG(DEBUG) << "Clearing Station " << sta_it->first;
            stations.erase(sta_it);
        }
    };
    sta_del_event_handler->context = this;

    filter = "(path matches '" + wifi_ad_path +
             "$')"
             " && (notification == '" +
             AMX_CL_INSTANCE_REMOVED_EVT + "')";

    m_ambiorix_cl->subscribe_to_object_event(wbapi_utils::search_path_ap(), sta_del_event_handler,
                                             filter);
}

void base_wlan_hal_whm::subscribe_to_ep_events()
{
    // subscribe to the WiFi.EndPoint.iface_name.ConnectionStatus
    std::string wifi_ep_path = wbapi_utils::search_path_ep_profiles_by_iface(get_iface_name());
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_OBJECT_CHANGED_EVT;
    event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        auto parameters        = event_data.find_child("parameters");
        if (!parameters || parameters->empty()) {
            return;
        }
        auto params_map = parameters->read_childs<AmbiorixVariantMapSmartPtr>();
        if (!params_map) {
            return;
        }
        for (auto &param_it : *params_map) {
            auto key   = param_it.first;
            auto value = param_it.second.find_child("to");
            if (key.empty() || !value || value->empty()) {
                continue;
            }
            hal->process_ep_event(hal->get_iface_name(), key, value.get());
        }
    };
    event_handler->context = this;

    std::string filter = "(path matches '" + wifi_ep_path +
                         "$')"
                         " && (notification == '" +
                         AMX_CL_OBJECT_CHANGED_EVT +
                         "')"
                         " && (contains('parameters.Connectionstatus'))";

    m_ambiorix_cl->subscribe_to_object_event(m_radio_path, event_handler, filter);
}

void base_wlan_hal_whm::subscribe_to_ep_wps_events()
{
    // subscribe to the WiFi.EndPoint.iface_name.WPS.
    std::string wifi_ep_path = wbapi_utils::search_path_ep_profiles_by_iface(get_iface_name());
    std::string wifi_wps_path = wifi_ep_path + "WPS.";
    auto event_handler         = std::make_shared<sAmbiorixEventHandler>();
    event_handler->event_type  = AMX_CL_WPS_PAIRING_DONE;
    event_handler->callback_fn = [](AmbiorixVariant &event_data, void *context) -> void {
        if (!event_data) {
            return;
        }
        base_wlan_hal_whm *hal = (static_cast<base_wlan_hal_whm *>(context));
        hal->process_ep_wps_event(hal->get_iface_name(), event_data);
    };
    event_handler->context = this;
    std::string filter      = "path matches '" + wifi_wps_path + "'";
    m_ambiorix_cl->subscribe_to_object_event(m_radio_path, event_handler, filter);
}

bool base_wlan_hal_whm::process_radio_event(const std::string &interface, const std::string &key,
                                            const AmbiorixVariant *value)
{
    return true;
}

bool base_wlan_hal_whm::process_ap_event(const std::string &interface, const std::string &key,
                                         const AmbiorixVariant *value)
{
    return true;
}

bool base_wlan_hal_whm::process_sta_event(const std::string &interface, const std::string &sta_mac,
                                          const std::string &key, const AmbiorixVariant *value)
{
    return true;
}

bool base_wlan_hal_whm::process_ep_event(const std::string &interface, const std::string &key,
                                         const AmbiorixVariant *value)
{
    return true;
}

bool base_wlan_hal_whm::process_ep_wps_event(const std::string &interface, const AmbiorixVariant *data)
{
    return true;
}

bool base_wlan_hal_whm::fsm_setup() { return true; }

HALState base_wlan_hal_whm::attach(bool block)
{
    m_radio_info.radio_state = eRadioState::ENABLED;
    refresh_radio_info();
    return (m_hal_state = HALState::Operational);
}

bool base_wlan_hal_whm::detach() { return true; }

bool base_wlan_hal_whm::set(const std::string &param, const std::string &value, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool base_wlan_hal_whm::ping() { return true; }

bool base_wlan_hal_whm::refresh_radio_info()
{
    auto radio = m_ambiorix_cl->get_object(m_radio_path);
    if (!radio) {
        return false;
    }
    std::string sVal;
    if (radio->read_child<>(sVal, "OperatingFrequencyBand")) {
        m_radio_info.frequency_band = wbapi_utils::band_to_freq(sVal);
    }
    m_radio_info.is_5ghz = (m_radio_info.frequency_band == beerocks::eFreqType::FREQ_5G);
    radio->read_child<>(m_radio_info.wifi_ctrl_enabled, "Enable");
    if (radio->read_child<>(sVal, "MaxChannelBandwidth")) {
        m_radio_info.max_bandwidth = wbapi_utils::bandwith_from_string(sVal);
    }
    auto bandwidth = beerocks::utils::convert_bandwidth_to_enum(m_radio_info.bandwidth);
    if (radio->read_child<>(sVal, "CurrentOperatingChannelBandwidth")) {
        bandwidth              = wbapi_utils::bandwith_from_string(sVal);
        m_radio_info.bandwidth = beerocks::utils::convert_bandwidth_to_int(bandwidth);
    }
    radio->read_child<>(m_radio_info.channel, "Channel");
    m_radio_info.is_dfs_channel = son::wireless_utils::is_dfs_channel(m_radio_info.channel);

    // TODO: read radio capabilities and supported channel list (PPM-2120)
    if (radio->read_child<>(sVal, "PossibleChannels")) {
        auto channels_vec = beerocks::string_utils::str_split(sVal, ',');
        for (auto &chan_str : channels_vec) {
            uint32_t chanNum          = beerocks::string_utils::stoi(chan_str);
            auto &channel_info        = m_radio_info.channels_list[chanNum];
            channel_info.tx_power_dbm = m_radio_info.tx_power;

            //TODO: fetch DFS channel current CAC state
            channel_info.dfs_state = beerocks::eDfsState::DFS_STATE_MAX;

            //TODO: fetch Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths
            for (uint8_t bw = m_radio_info.max_bandwidth;
                 bw > beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN; bw--) {
                channel_info.bw_info_list[beerocks::eWiFiBandwidth(bw)] = 1;
            }
        }
    }
    if (radio->read_child<>(sVal, "ExtensionChannel")) {
        bool channel_ext_above = (sVal == "AboveControlChannel");
        if (!channel_ext_above && (sVal == "Auto") && (m_radio_info.bandwidth > 20)) {
            if (m_radio_info.frequency_band != beerocks::eFreqType::FREQ_24G) {
                channel_ext_above = ((m_radio_info.channel / 4) % 2);
            } else {
                channel_ext_above = (m_radio_info.channel < 7);
            }
        }
        m_radio_info.channel_ext_above = channel_ext_above;
    }
    m_radio_info.vht_center_freq = son::wireless_utils::channel_to_vht_center_freq(
        m_radio_info.channel, m_radio_info.frequency_band, bandwidth,
        m_radio_info.channel_ext_above);

    radio->read_child<>(m_radio_info.tx_power, "TransmitPower");
    if (radio->read_child<>(sVal, "Status")) {
        m_radio_info.radio_state = utils_wlan_hal_whm::radio_state_from_string(sVal);
        if (m_radio_info.radio_state == eRadioState::ENABLED) {
            m_radio_info.wifi_ctrl_enabled = 2; // Assume Operational
            m_radio_info.tx_enabled        = 1;
        }
    }
    m_ambiorix_cl->get_param<>(m_radio_info.ant_num, m_radio_path + "DriverStatus.", "NrTxAntenna");

    if (!m_radio_info.available_vaps.size()) {
        if (!refresh_vaps_info(beerocks::IFACE_RADIO_ID)) {
            return false;
        }
    }

    return true;
}

bool base_wlan_hal_whm::get_radio_vaps(AmbiorixVariantList &aps)
{
    aps.clear();
    auto result =
        m_ambiorix_cl->get_object_multi<AmbiorixVariantMapSmartPtr>(wbapi_utils::search_path_ap());
    if (!result) {
        return false;
    }
    std::string radio_path;
    for (auto &it : *result) {
        auto &ap = it.second;
        if ((ap.empty()) ||
            (!m_ambiorix_cl->resolve_path(wbapi_utils::get_path_radio_reference(ap), radio_path)) ||
            (radio_path != m_radio_path)) {
            continue;
        }
        aps.emplace_back(std::move(ap));
    }
    return true;
}

bool base_wlan_hal_whm::has_enabled_vap() const
{
    auto vap_it = std::find_if(m_vapsExtInfo.begin(), m_vapsExtInfo.end(),
                               [&](const std::pair<std::string, VAPExtInfo> &element) {
                                   return element.second.status == "Enabled";
                               });
    return (vap_it != m_vapsExtInfo.end());
}

bool base_wlan_hal_whm::check_enabled_vap(const std::string &bss) const
{
    auto vap_it = m_vapsExtInfo.find(bss);
    return (vap_it != m_vapsExtInfo.end() && vap_it->second.status == "Enabled");
}

bool base_wlan_hal_whm::refresh_vaps_info(int id)
{
    bool ret   = false;
    int vap_id = -1;

    AmbiorixVariantList curr_vaps;
    get_radio_vaps(curr_vaps);

    AmbiorixVariant empty_vap;
    bool detectNewVaps = false;
    std::vector<std::string> newEnabledVaps;
    bool wasActive   = has_enabled_vap();
    int nb_curr_vaps = curr_vaps.size();
    while (++vap_id < std::max(int(beerocks::IFACE_VAP_ID_MAX), nb_curr_vaps)) {
        if (id == beerocks::IFACE_RADIO_ID || id == vap_id) {
            if (vap_id >= nb_curr_vaps) {
                ret |= refresh_vap_info(vap_id, empty_vap);
            } else {
                auto &saved_vaps = m_radio_info.available_vaps;
                bool wasKnown    = (saved_vaps.find(vap_id) != saved_vaps.end());
                bool wasEnabled  = wasKnown && check_enabled_vap(saved_vaps[vap_id].bss);
                ret |= refresh_vap_info(vap_id, curr_vaps.at(vap_id));
                bool isKnown   = (saved_vaps.find(vap_id) != saved_vaps.end());
                bool isEnabled = isKnown && check_enabled_vap(saved_vaps[vap_id].bss);
                detectNewVaps |= ((isKnown != wasKnown) || (!wasActive && isEnabled));
                if (!wasEnabled && isEnabled) {
                    newEnabledVaps.push_back(saved_vaps[vap_id].bss);
                }
            }
        }
        if (id == vap_id) {
            break;
        }
    };

    if (detectNewVaps) {
        process_radio_event(get_iface_name(), "AccessPointNumberOfEntries",
                            AmbiorixVariant::copy(nb_curr_vaps).get());
    }
    if (!newEnabledVaps.empty()) {
        auto status = AmbiorixVariant::copy("Enabled");
        for (const auto &bss : newEnabledVaps) {
            process_ap_event(bss, "Status", status.get());
        }
    }
    return ret;
}

bool base_wlan_hal_whm::refresh_vap_info(int id, const AmbiorixVariant &ap_obj)
{
    VAPElement vap_element;
    VAPExtInfo vap_extInfo;

    auto wifi_ssid_path = wbapi_utils::get_path_ssid_reference(ap_obj);
    auto ifname         = wbapi_utils::get_ap_iface(ap_obj);
    if (!wifi_ssid_path.empty() && !ifname.empty() &&
        !wbapi_utils::get_path_radio_reference(ap_obj).empty()) {
        std::string mac;
        auto ssid_obj = m_ambiorix_cl->get_object(wifi_ssid_path);
        if (ssid_obj && ((mac = wbapi_utils::get_ssid_mac(*ssid_obj)) != "") &&
            (mac != beerocks::net::network_utils::ZERO_MAC_STRING)) {
            vap_element.bss = ifname;
            vap_element.mac = mac;
            ssid_obj->read_child<>(vap_element.ssid, "SSID");
            vap_element.fronthaul = false;
            vap_element.backhaul  = false;
            std::string multi_ap_type;
            if (ap_obj.read_child<>(multi_ap_type, "MultiAPType")) {
                if (multi_ap_type.find("FronthaulBSS") != std::string::npos) {
                    vap_element.fronthaul = true;
                }
                if (multi_ap_type.find("BackhaulBSS") != std::string::npos) {
                    vap_element.backhaul = true;
                }
            }
            m_ambiorix_cl->resolve_path(wbapi_utils::search_path_ap_by_iface(ifname),
                                        vap_extInfo.path);
            m_ambiorix_cl->resolve_path(wifi_ssid_path, vap_extInfo.ssid_path);
            vap_extInfo.status = wbapi_utils::get_ap_status(ap_obj);
        }
    }

    // VAP does not exists
    if (vap_element.mac.empty()) {
        if (m_radio_info.available_vaps.find(id) != m_radio_info.available_vaps.end()) {
            LOG(WARNING) << "Removed VAP " << m_radio_info.available_vaps[id].bss << " id (" << id
                         << ") ";
            m_vapsExtInfo.erase(m_radio_info.available_vaps[id].bss);
            m_radio_info.available_vaps.erase(id);
        }
        return true;
    }

    // Store the VAP element
    LOG(WARNING) << "Detected VAP id (" << id << ") - MAC: " << vap_element.mac
                 << ", SSID: " << vap_element.ssid << ", BSS: " << vap_element.bss;

    auto &mapped_vap_element = m_radio_info.available_vaps[id];
    auto &mapped_vap_extInfo = m_vapsExtInfo[vap_element.bss];
    if (mapped_vap_element.bss.empty()) {
        LOG(WARNING) << "BSS " << vap_element.bss << " is not preconfigured!"
                     << "Overriding VAP element.";

        mapped_vap_element = vap_element;
        mapped_vap_extInfo = vap_extInfo;
        return true;

    } else if (mapped_vap_element.bss != vap_element.bss) {
        LOG(ERROR) << "bss mismatch! vap_element.bss=" << vap_element.bss
                   << ", mapped_vap_element.bss=" << mapped_vap_element.bss;
        return false;
    } else if (mapped_vap_element.ssid != vap_element.ssid) {
        LOG(DEBUG) << "SSID changed from " << mapped_vap_element.ssid << ", to " << vap_element.ssid
                   << ". Overriding VAP element.";
        mapped_vap_element = vap_element;
        mapped_vap_extInfo = vap_extInfo;
        return true;
    }

    mapped_vap_element.mac    = vap_element.mac;
    mapped_vap_extInfo.status = vap_extInfo.status;

    return true;
}

bool base_wlan_hal_whm::process_ext_events(int fd)
{
    if (m_ambiorix_cl->get_fd() == fd) {
        m_ambiorix_cl->read();
    } else if (m_ambiorix_cl->get_signal_fd() == fd) {
        m_ambiorix_cl->read_signal();
    }
    return true;
}

int base_wlan_hal_whm::whm_get_vap_id(const std::string &iface)
{
    AmbiorixVariantList aps;
    if (get_radio_vaps(aps) && !aps.empty()) {
        int vap_id = beerocks::IFACE_VAP_ID_MIN;
        for (const auto &ap : aps) {
            if (wbapi_utils::get_ap_iface(ap) == iface) {
                return vap_id;
            }
            vap_id++;
        }
    }
    return int(beerocks::IFACE_ID_INVALID);
}

bool base_wlan_hal_whm::whm_get_radio_ref(const std::string &iface, std::string &ref)
{
    ref          = "";
    auto ap_path = wbapi_utils::search_path_ap_by_iface(iface);
    if (!m_ambiorix_cl->get_param<>(ref, ap_path, "RadioReference")) {
        LOG(ERROR) << "failed to get RadioReference of ap iface " << iface;
        return false;
    }
    if (ref.empty()) {
        LOG(ERROR) << "No radioReference for iface " << iface;
        return false;
    }
    return true;
}

bool base_wlan_hal_whm::whm_get_radio_path(const std::string &iface, std::string &path)
{
    return m_ambiorix_cl->resolve_path(wbapi_utils::search_path_radio_by_iface(iface), path);
}

std::string base_wlan_hal_whm::get_radio_mac()
{
    std::string mac("");
    auto wifi_radio_path = wbapi_utils::search_path_radio_by_iface(get_iface_name());
    m_ambiorix_cl->get_param<>(mac, wifi_radio_path, "BaseMACAddress");
    return mac;
}

bool base_wlan_hal_whm::get_channel_utilization(uint8_t &channel_utilization)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

} // namespace whm
} // namespace bwl
