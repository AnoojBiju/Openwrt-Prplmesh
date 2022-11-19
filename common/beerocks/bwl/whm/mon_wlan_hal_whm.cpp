/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "mon_wlan_hal_whm.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

#include <easylogging++.h>

#include <cmath>

using namespace beerocks;
using namespace wbapi;

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// WHM////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace bwl {
namespace whm {

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

mon_wlan_hal_whm::mon_wlan_hal_whm(const std::string &iface_name, hal_event_cb_t callback,
                                   const bwl::hal_conf_t &hal_conf)
    : base_wlan_hal(bwl::HALType::Monitor, iface_name, IfaceType::Intel, callback, hal_conf),
      base_wlan_hal_whm(bwl::HALType::Monitor, iface_name, callback, hal_conf)
{
    subscribe_to_ap_events();
    subscribe_to_sta_events();
}

mon_wlan_hal_whm::~mon_wlan_hal_whm() {}

bool mon_wlan_hal_whm::update_radio_stats(SRadioStats &radio_stats)
{
    std::string stats_path = m_radio_path + "Stats.";

    auto stats_obj = m_ambiorix_cl->get_object(stats_path);
    if (!stats_obj) {
        LOG(ERROR) << "failed to get radio Stats object " << stats_path;
        return true;
    }

    stats_obj->read_child<>(radio_stats.tx_bytes_cnt, "BytesSent");
    stats_obj->read_child<>(radio_stats.rx_bytes_cnt, "BytesReceived");
    stats_obj->read_child<>(radio_stats.tx_packets_cnt, "PacketsSent");
    stats_obj->read_child<>(radio_stats.rx_packets_cnt, "PacketsReceived");
    stats_obj->read_child<>(radio_stats.errors_sent, "ErrorsSent");
    stats_obj->read_child<>(radio_stats.errors_received, "ErrorsReceived");
    stats_obj->read_child<>(radio_stats.noise, "Noise");

    return true;
}

bool mon_wlan_hal_whm::update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats)
{
    std::string ssid_stats_path = wbapi_utils::search_path_ssid_by_iface(vap_iface_name) + "Stats.";

    auto ssid_stats_obj = m_ambiorix_cl->get_object(ssid_stats_path);
    if (!ssid_stats_obj) {
        LOG(ERROR) << "failed to get SSID Stats object, path:" << ssid_stats_path;
        return true;
    }

    ssid_stats_obj->read_child<>(vap_stats.tx_bytes_cnt, "BytesSent");
    ssid_stats_obj->read_child<>(vap_stats.rx_bytes_cnt, "BytesReceived");
    ssid_stats_obj->read_child<>(vap_stats.tx_packets_cnt, "PacketsSent");
    ssid_stats_obj->read_child<>(vap_stats.rx_packets_cnt, "PacketsReceived");
    ssid_stats_obj->read_child<>(vap_stats.errors_sent, "ErrorsSent");
    ssid_stats_obj->read_child<>(vap_stats.errors_received, "ErrorsReceived");
    ssid_stats_obj->read_child<>(vap_stats.retrans_count, "RetransCount");

    return true;
}

bool mon_wlan_hal_whm::update_stations_stats(const std::string &vap_iface_name,
                                             const std::string &sta_mac, SStaStats &sta_stats,
                                             bool is_read_unicast)
{
    auto sta_mac_address = tlvf::mac_from_string(sta_mac);
    nl80211_client::sta_info sta_info;
    if (!m_iso_nl80211_client->get_sta_info(vap_iface_name, sta_mac_address, sta_info)) {
        return true;
    }
    sta_stats.tx_bytes          = sta_info.tx_bytes;
    sta_stats.rx_bytes          = sta_info.rx_bytes;
    sta_stats.tx_packets        = sta_info.tx_packets;
    sta_stats.rx_packets        = sta_info.rx_packets;
    sta_stats.retrans_count     = sta_info.tx_retries;
    sta_stats.tx_phy_rate_100kb = sta_info.tx_bitrate_100kbps;
    sta_stats.rx_phy_rate_100kb = sta_info.rx_bitrate_100kbps;
    sta_stats.dl_bandwidth      = sta_info.dl_bandwidth;
    if (sta_info.signal_dbm != 0) {
        sta_stats.rx_rssi_watt = std::pow(10, (int8_t(sta_info.signal_dbm) / 10.0));
        sta_stats.rx_rssi_watt_samples_cnt++;
    }

    //complement missing info in sta_info struct
    std::string assoc_device_path =
        wbapi_utils::search_path_assocDev_by_mac(vap_iface_name, sta_mac);

    float s_float;
    if (m_ambiorix_cl->get_param<>(s_float, assoc_device_path, "SignalNoiseRatio")) {
        if (s_float >= beerocks::SNR_MIN) {
            sta_stats.rx_snr_watt = std::pow(10, s_float / float(10));
            sta_stats.rx_snr_watt_samples_cnt++;
        }
    }

    m_ambiorix_cl->get_param<>(sta_stats.tx_bytes_cnt, assoc_device_path, "TxBytes");
    m_ambiorix_cl->get_param<>(sta_stats.rx_bytes_cnt, assoc_device_path, "RxBytes");
    m_ambiorix_cl->get_param<>(sta_stats.rx_packets_cnt, assoc_device_path, "RxPacketCount");
    m_ambiorix_cl->get_param<>(sta_stats.tx_packets_cnt, assoc_device_path, "TxPacketCount");

    return true;
}

bool mon_wlan_hal_whm::update_station_qos_control_params(const std::string &vap_iface_name,
                                                         const std::string &sta_mac,
                                                         SStaQosCtrlParams &sta_qos_ctrl_params)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool mon_wlan_hal_whm::sta_channel_load_11k_request(const std::string &vap_iface_name,
                                                    const SStaChannelLoadRequest11k &req)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool mon_wlan_hal_whm::sta_beacon_11k_request(const std::string &vap_iface_name,
                                              const SBeaconRequest11k &req, int &dialog_token)
{
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child<>("mac", tlvf::mac_to_string(req.sta_mac.oct));
    args.add_child<>("bssid", tlvf::mac_to_string(req.bssid.oct));
    args.add_child<>("class", uint8_t(req.op_class));
    args.add_child<>("channel", uint8_t(req.channel));
    args.add_child<>("ssid", std::string((const char *)req.ssid));
    std::string wifi_ap_path = wbapi_utils::search_path_ap_by_iface(vap_iface_name);
    bool ret = m_ambiorix_cl->call(wifi_ap_path, "sendRemoteMeasumentRequest", args, result);

    if (!ret) {
        LOG(ERROR) << "sta_beacon_11k_request() failed!";
        return false;
    }
    return true;
}

bool mon_wlan_hal_whm::sta_link_measurements_11k_request(const std::string &vap_iface_name,
                                                         const std::string &sta_mac)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool mon_wlan_hal_whm::channel_scan_trigger(int dwell_time_msec,
                                            const std::vector<unsigned int> &channel_pool)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return false;
}

bool mon_wlan_hal_whm::channel_scan_dump_cached_results()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool mon_wlan_hal_whm::channel_scan_dump_results()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return false;
}

bool mon_wlan_hal_whm::generate_connected_clients_events(
    bool &is_finished_all_clients, std::chrono::steady_clock::time_point max_iteration_timeout)
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    is_finished_all_clients = true;
    return true;
}

bool mon_wlan_hal_whm::pre_generate_connected_clients_events()
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool mon_wlan_hal_whm::channel_scan_abort()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return false;
}

bool mon_wlan_hal_whm::process_ap_event(const std::string &interface, const std::string &key,
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
        LOG(WARNING) << "monitor: vap " << interface << " status " << status;
        if (status == "Enabled") {
            auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_ENABLED_NOTIFICATION));
            auto msg      = reinterpret_cast<sHOSTAP_ENABLED_NOTIFICATION *>(msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sHOSTAP_ENABLED_NOTIFICATION));
            msg->vap_id = vap_id;
            event_queue_push(Event::AP_Enabled, msg_buff);
        } else {
            auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_DISABLED_NOTIFICATION));
            auto msg      = reinterpret_cast<sHOSTAP_DISABLED_NOTIFICATION *>(msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sHOSTAP_DISABLED_NOTIFICATION));
            msg->vap_id = vap_id;
            event_queue_push(Event::AP_Disabled, msg_buff); // send message to the AP manager
        }
    }
    return true;
}

bool mon_wlan_hal_whm::process_sta_event(const std::string &interface, const std::string &sta_mac,
                                         const std::string &key, const AmbiorixVariant *value)
{
    auto vap_id = get_vap_id_with_bss(interface);
    if (vap_id == beerocks::IFACE_ID_INVALID) {
        return true;
    }
    if (key == "AuthenticationState") {
        bool connected = value->get<bool>();
        if (connected) {
            LOG(WARNING) << "monitor: Connected station " << sta_mac << " over vap " << interface;
            auto msg_buff =
                ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));
            auto msg =
                reinterpret_cast<sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));
            msg->vap_id = vap_id;
            msg->mac    = tlvf::mac_from_string(sta_mac);
            event_queue_push(Event::STA_Connected, msg_buff);
        } else {
            LOG(WARNING) << "monitor: disconnected station " << sta_mac << " from vap "
                         << interface;
            auto msg_buff =
                ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION));
            auto msg = reinterpret_cast<sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION *>(
                msg_buff.get());
            LOG_IF(!msg, FATAL) << "Memory allocation failed!";
            memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION));
            msg->mac = tlvf::mac_from_string(sta_mac);
            event_queue_push(Event::STA_Disconnected, msg_buff);
        }
    }
    return true;
}

bool mon_wlan_hal_whm::set(const std::string &param, const std::string &value, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

bool mon_wlan_hal_whm::set_estimated_service_parameters(uint8_t *esp_info_field)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

} // namespace whm

std::shared_ptr<mon_wlan_hal> mon_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback,
                                                  const bwl::hal_conf_t &hal_conf)
{
    return std::make_shared<whm::mon_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
