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

static mon_wlan_hal::Event whm_to_bwl_event(const std::string &opcode)
{
    if (opcode == "AP-STA-CONNECTED") {
        return mon_wlan_hal::Event::STA_Connected;
    } else if (opcode == "AP-STA-DISCONNECTED") {
        return mon_wlan_hal::Event::STA_Disconnected;
    }

    return mon_wlan_hal::Event::Invalid;
}

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

mon_wlan_hal_whm::mon_wlan_hal_whm(const std::string &iface_name, hal_event_cb_t callback,
                                   const bwl::hal_conf_t &hal_conf)
    : base_wlan_hal(bwl::HALType::Monitor, iface_name, IfaceType::Intel, callback, hal_conf),
      base_wlan_hal_whm(bwl::HALType::Monitor, iface_name, callback, hal_conf)
{
}

mon_wlan_hal_whm::~mon_wlan_hal_whm() {}

bool mon_wlan_hal_whm::update_radio_stats(SRadioStats &radio_stats)
{
    std::string wifi_radio_path;
    if (!whm_get_radio_ref(get_iface_name(), wifi_radio_path)) {
        return false;
    }

    std::string stats_path = wifi_radio_path + "Stats.";

    amxc_var_t *stats_obj = m_ambiorix_cl->get_object(stats_path, 0);
    if (!stats_obj) {
        LOG(ERROR) << "failed to get radio Stats object";
        return false;
    }

    radio_stats.tx_bytes_cnt    = GET_UINT32(stats_obj, "BytesSent");
    radio_stats.rx_bytes_cnt    = GET_UINT32(stats_obj, "BytesReceived");
    radio_stats.tx_packets_cnt  = GET_UINT32(stats_obj, "PacketsSent");
    radio_stats.rx_packets_cnt  = GET_UINT32(stats_obj, "PacketsReceived");
    radio_stats.errors_sent     = GET_UINT32(stats_obj, "ErrorsSent");
    radio_stats.errors_received = GET_UINT32(stats_obj, "ErrorsReceived");

    amxc_var_t *radio_obj = m_ambiorix_cl->get_object(wifi_radio_path, 0);
    if (!radio_obj) {
        LOG(ERROR) << "failed to get radio object";
        return false;
    }

    radio_stats.noise = GET_UINT32(radio_obj, "Noise");

    amxc_var_delete(&stats_obj);
    amxc_var_delete(&radio_obj);

    return true;
}

bool mon_wlan_hal_whm::update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats)
{
    std::string ssid_stats_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                  std::string(AMX_CL_SSID_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                                  vap_iface_name + AMX_CL_OBJ_DELIMITER + "Stats.";

    amxc_var_t *ssid_stats_obj = m_ambiorix_cl->get_object(ssid_stats_path, 0);
    if (!ssid_stats_obj) {
        LOG(ERROR) << "failed to get SSID Stats object, path:" << ssid_stats_path;
        return false;
    }

    vap_stats.tx_bytes_cnt    = GET_UINT32(ssid_stats_obj, "BytesSent");
    vap_stats.rx_bytes_cnt    = GET_UINT32(ssid_stats_obj, "BytesReceived");
    vap_stats.tx_packets_cnt  = GET_UINT32(ssid_stats_obj, "PacketsSent");
    vap_stats.rx_packets_cnt  = GET_UINT32(ssid_stats_obj, "PacketsReceived");
    vap_stats.errors_sent     = GET_UINT32(ssid_stats_obj, "ErrorsSent");
    vap_stats.errors_received = GET_UINT32(ssid_stats_obj, "ErrorsReceived");
    vap_stats.retrans_count   = GET_UINT32(ssid_stats_obj, "RetransCount");
    amxc_var_delete(&ssid_stats_obj);

    return true;
}

bool mon_wlan_hal_whm::update_stations_stats(const std::string &vap_iface_name,
                                             const std::string &sta_mac, SStaStats &sta_stats)
{
    std::string assoc_device_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                                    std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                                    "[Alias == '" + vap_iface_name + "']" + AMX_CL_OBJ_DELIMITER +
                                    "AssociatedDevice." + sta_mac;

    amxc_var_t *assoc_device_obj = m_ambiorix_cl->get_object(assoc_device_path, 0);
    if (!assoc_device_obj) {
        LOG(ERROR) << "failed to get AssociatedDevice object";
        return false;
    }

    sta_stats.rx_rssi_watt      = GET_UINT32(assoc_device_obj, "SignalStrength");
    sta_stats.rx_snr_watt       = GET_UINT32(assoc_device_obj, "SignalNoiseRatio");
    sta_stats.tx_phy_rate_100kb = GET_UINT32(assoc_device_obj, "LastDataDownlinkRate");
    sta_stats.dl_bandwidth      = GET_UINT32(assoc_device_obj, "DownlinkBandwidth");
    sta_stats.rx_phy_rate_100kb = GET_UINT32(assoc_device_obj, "LastDataUplinkRate");
    sta_stats.tx_bytes_cnt      = GET_UINT32(assoc_device_obj, "RxBytes");
    sta_stats.rx_bytes_cnt      = GET_UINT32(assoc_device_obj, "TxBytes");
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
    std::string wifi_ap_path = std::string(AMX_CL_WIFI_ROOT_NAME) + AMX_CL_OBJ_DELIMITER +
                               std::string(AMX_CL_AP_OBJ_NAME) + AMX_CL_OBJ_DELIMITER +
                               "[Alias == '" + vap_iface_name + "']" + AMX_CL_OBJ_DELIMITER;
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

bool mon_wlan_hal_whm::process_whm_event(std::string &opcode, const amxc_var_t *data)
{
    auto event = whm_to_bwl_event(opcode);
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

} // namespace whm

std::shared_ptr<mon_wlan_hal> mon_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback,
                                                  const bwl::hal_conf_t &hal_conf)
{
    return std::make_shared<whm::mon_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
