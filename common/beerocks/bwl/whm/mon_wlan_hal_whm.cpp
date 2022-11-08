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
    subscribe_to_sta_events(iface_name);
}

mon_wlan_hal_whm::~mon_wlan_hal_whm() {}

bool mon_wlan_hal_whm::update_radio_stats(SRadioStats &radio_stats)
{
    std::string stats_path = m_radio_path + "Stats.";

    amxc_var_t *stats_obj = m_ambiorix_cl->get_object(stats_path);
    if (!stats_obj) {
        LOG(ERROR) << "failed to get radio Stats object " << stats_path;
        return true;
    }

    radio_stats.tx_bytes_cnt    = amxc_var_dyncast(uint64_t, GET_ARG(stats_obj, "BytesSent"));
    radio_stats.rx_bytes_cnt    = amxc_var_dyncast(uint64_t, GET_ARG(stats_obj, "BytesReceived"));
    radio_stats.tx_packets_cnt  = GET_UINT32(stats_obj, "PacketsSent");
    radio_stats.rx_packets_cnt  = GET_UINT32(stats_obj, "PacketsReceived");
    radio_stats.errors_sent     = GET_UINT32(stats_obj, "ErrorsSent");
    radio_stats.errors_received = GET_UINT32(stats_obj, "ErrorsReceived");
    radio_stats.noise           = GET_INT32(stats_obj, "Noise");

    amxc_var_delete(&stats_obj);

    return true;
}

bool mon_wlan_hal_whm::update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats)
{
    std::string ssid_stats_path = search_path_ssid_by_iface(vap_iface_name) + "Stats.";

    amxc_var_t *ssid_stats_obj = m_ambiorix_cl->get_object(ssid_stats_path);
    if (!ssid_stats_obj) {
        LOG(ERROR) << "failed to get SSID Stats object, path:" << ssid_stats_path;
        return true;
    }

    vap_stats.tx_bytes_cnt   = amxc_var_dyncast(uint64_t, GET_ARG(ssid_stats_obj, "BytesSent"));
    vap_stats.rx_bytes_cnt   = amxc_var_dyncast(uint64_t, GET_ARG(ssid_stats_obj, "BytesReceived"));
    vap_stats.tx_packets_cnt = GET_UINT32(ssid_stats_obj, "PacketsSent");
    vap_stats.rx_packets_cnt = GET_UINT32(ssid_stats_obj, "PacketsReceived");
    vap_stats.errors_sent    = GET_UINT32(ssid_stats_obj, "ErrorsSent");
    vap_stats.errors_received = GET_UINT32(ssid_stats_obj, "ErrorsReceived");
    vap_stats.retrans_count   = GET_UINT32(ssid_stats_obj, "RetransCount");
    amxc_var_delete(&ssid_stats_obj);

    return true;
}

bool mon_wlan_hal_whm::update_stations_stats(const std::string &vap_iface_name,
                                             const std::string &sta_mac, SStaStats &sta_stats,
                                             bool is_read_unicast)
{
    std::string assoc_device_path = search_path_assocDev_by_mac(vap_iface_name, sta_mac);

    amxc_var_t *assoc_device_obj = m_ambiorix_cl->get_object(assoc_device_path);
    if (!assoc_device_obj) {
        LOG(ERROR) << "failed to get AssociatedDevice object " << assoc_device_path;
        return true;
    }

    int8_t signal          = int8_t(GET_INT32(assoc_device_obj, "SignalStrength"));
    sta_stats.rx_rssi_watt = std::pow(10, (signal / 10.0));
    sta_stats.rx_rssi_watt_samples_cnt++;

    float s_float = float(GET_UINT32(assoc_device_obj, "SignalNoiseRatio"));
    if (s_float >= beerocks::SNR_MIN) {
        sta_stats.rx_snr_watt = std::pow(10, s_float / float(10));
        sta_stats.rx_snr_watt_samples_cnt++;
    }

    sta_stats.tx_phy_rate_100kb = GET_UINT32(assoc_device_obj, "LastDataDownlinkRate") / 100;
    sta_stats.dl_bandwidth      = GET_UINT32(assoc_device_obj, "DownlinkBandwidth");
    sta_stats.rx_phy_rate_100kb = GET_UINT32(assoc_device_obj, "LastDataUplinkRate") / 100;
    sta_stats.tx_bytes_cnt      = amxc_var_dyncast(uint64_t, GET_ARG(assoc_device_obj, "RxBytes"));
    sta_stats.rx_bytes_cnt      = amxc_var_dyncast(uint64_t, GET_ARG(assoc_device_obj, "TxBytes"));
    sta_stats.tx_packets_cnt    = GET_UINT32(assoc_device_obj, "TxPacketCount");
    sta_stats.rx_packets_cnt    = GET_UINT32(assoc_device_obj, "RxPacketCount");
    sta_stats.retrans_count     = GET_UINT32(assoc_device_obj, "Retransmissions");
    amxc_var_delete(&assoc_device_obj);

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
    amxc_var_t args;
    amxc_var_t result;
    amxc_var_init(&args);
    amxc_var_init(&result);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key_cstring_t(&args, "mac", (tlvf::mac_to_string(req.sta_mac.oct)).c_str());
    amxc_var_add_new_key_cstring_t(&args, "bssid", (tlvf::mac_to_string(req.bssid.oct)).c_str());
    amxc_var_add_new_key_uint8_t(&args, "class", req.op_class);
    amxc_var_add_new_key_uint8_t(&args, "channel", req.channel);
    amxc_var_add_new_key_cstring_t(&args, "ssid", (const char *)req.ssid);
    std::string wifi_ap_path = search_path_ap_by_iface(vap_iface_name);
    bool ret = m_ambiorix_cl->call(wifi_ap_path, "sendRemoteMeasumentRequest", &args, &result);
    amxc_var_clean(&args);
    amxc_var_clean(&result);

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

bool mon_wlan_hal_whm::process_sta_event(const std::string &interface, const std::string &sta_mac,
                                         const amxc_var_t *data)
{
    bool active               = GETP_BOOL(data, "parameters.Active.to");
    mon_wlan_hal::Event event = mon_wlan_hal::Event::STA_Disconnected;
    if (active) {
        event = mon_wlan_hal::Event::STA_Connected;
    }
    process_whm_event(event, data);

    return true;
}

bool mon_wlan_hal_whm::process_whm_event(mon_wlan_hal::Event event, const amxc_var_t *data)
{
    switch (event) {

    case Event::STA_Connected: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));

        const char *sta_obj_path = GET_CHAR(data, "object");
        if (!sta_obj_path) {
            return false;
        }
        amxc_var_t *sta_obj = m_ambiorix_cl->get_object(std::string(sta_obj_path));
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
        //msg->vap_id = vap_id;
        msg->mac = tlvf::mac_from_string(sta_mac);

        // Add the message to the queue
        event_queue_push(Event::STA_Connected, msg_buff);
    } break;

    case Event::STA_Disconnected: {
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION));

        // Store the MAC address of the disconnected STA
        const char *sta_obj_path = GET_CHAR(data, "object");
        if (!sta_obj_path) {
            return false;
        }
        amxc_var_t *sta_obj = m_ambiorix_cl->get_object(std::string(sta_obj_path));
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
        msg->mac = tlvf::mac_from_string(sta_mac);

        // Add the message to the queue
        event_queue_push(Event::STA_Disconnected, msg_buff);
    } break;

    default:
        LOG(DEBUG) << "Unhandled event received";
        break;
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
