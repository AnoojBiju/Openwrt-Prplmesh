/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "mon_wlan_hal_whm.h"

#include <amxd/amxd_object.h>
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
                                             const std::string &sta_mac, SStaStats &sta_stats,
                                             bool is_read_unicast)
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

bool mon_wlan_hal_whm::process_whm_event(mon_wlan_hal::Event event, const amxc_var_t *data)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
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

/*  will get the unassociated stations stats from Ambirorix
*/
bool mon_wlan_hal_whm::sta_unassoc_rssi_measurement(std::unordered_map<std::string, uint> &new_list)
{
    /*
        Example of NonAssociatedDevice object:
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.AA:BB:CC:DD:EE:FF
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.AA:BB:CC:DD:EE:FF.MACAddress=AA:BB:CC:DD:EE:FF
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.AA:BB:CC:DD:EE:FF.SignalStrength=0
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.AA:BB:CC:DD:EE:FF.TimeStamp=0001-01-01T00:00:00Z
    */
    std::string create_nasta_device_string("createNonAssociatedDevice");
    std::string delete_non_associated_device("deleteNonAssociatedDevice");
    std::vector<sUnassociatedStationStats> stats;

    std::string wifi_radio_path;
    if (!whm_get_radio_path(get_iface_name(), wifi_radio_path)) {
        LOG(ERROR) << __func__ << " RADIO PATH not found!";
        return false;
    }

    std::unordered_map<std::string, uint32_t> amx_un_stations_to_be_removed;

    std::string non_associated_device_path = wifi_radio_path + "NaStaMonitor.NonAssociatedDevice.*";

    amxc_var_t *non_associated_device_amx_object =
        m_ambiorix_cl->get_object(non_associated_device_path, -1);

    //Lets iterate through all instances
    amxc_var_for_each(device, non_associated_device_amx_object)
    {
        const char *mac_address_amx = GET_CHAR(device, "MACAddress");
        auto signal_strength        = GET_UINT32(device, "SignalStrength");

        amxc_var_t *ts             = GET_ARG(device, "TimeStamp");
        const char *time_stamp_str = amxc_var_dyncast(cstring_t, ts);
        amxc_ts_t time;
        memset(&time, 0, sizeof(amxc_ts_t));
        amxc_ts_parse(&time, time_stamp_str, strlen(time_stamp_str));

        if (new_list.find(std::string(mac_address_amx)) != new_list.end()) {
            //NonAssociatedDevice exists -->get the result and update the channel
            sUnassociatedStationStats new_stat = {
                tlvf::mac_from_string(mac_address_amx),
                signal_strength,
                (uint32_t)time.sec,

            };
            stats.push_back(new_stat);
            LOG(DEBUG) << " read unassociated station stats for mac_address: " << mac_address_amx
                       << "SignalStrength: " << signal_strength
                       << "and TimeStamp(string): " << time_stamp_str
                       << " TimeStamp(seconds): " << (uint32_t)time.sec;
            new_list.erase(mac_address_amx); // consumed!
        } else {                             // -->controller is not interested on it any more
            const char *mac_address_amx = GET_CHAR(device, "MACAddress");
            uint32_t index              = GET_UINT32(device, "index");
            amx_un_stations_to_be_removed.insert(
                std::make_pair(std::string(mac_address_amx), index));
        }
    }

    std::string nasta_monitor_path = wifi_radio_path + "NaStaMonitor.";
    //Now add the newly added unassociated stations
    for (auto &new_station : new_list) {
        std::string mac_address(new_station.first);
        amxc_var_t args;
        amxc_var_init(&args);
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(cstring_t, &args, "MACAddress", mac_address.c_str());
        if (!m_ambiorix_cl->call(nasta_monitor_path, create_nasta_device_string.c_str(), &args,
                                 NULL)) {
            LOG(ERROR) << " remote function call " << create_nasta_device_string << " for object "
                       << nasta_monitor_path << " Failed!";
            amxc_var_clean(&args);
            continue;
        }
        amxc_var_clean(&args);

        LOG(TRACE) << "Non Associated Station with MACAddress: " << mac_address << "added to "
                   << non_associated_device_path;
    }

    // Now lets remove all stations the controller do not want them anymore
    for (auto &station_to_remove : amx_un_stations_to_be_removed) {
        LOG(DEBUG) << "removing unassociated station  with path: " << station_to_remove.first;
        amxc_var_t args;
        amxc_var_init(&args);
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(cstring_t, &args, "MACAddress", station_to_remove.first.c_str());

        if (!m_ambiorix_cl->call(nasta_monitor_path, delete_non_associated_device.c_str(), &args,
                                 NULL)) {
            LOG(ERROR) << " remote function call " << delete_non_associated_device << " for object "
                       << nasta_monitor_path << " Failed!";
            amxc_var_clean(&args);
            continue;
        } else {
            amxc_var_clean(&args);
            LOG(TRACE) << "Successfully removed unassociated station with mac: "
                       << station_to_remove.first;
        }
    }
    sUnassociatedStationsStats stats_out{stats};
    auto msg_buff = ALLOC_SMART_BUFFER(sizeof(stats_out));
    if (!msg_buff) {
        LOG(FATAL) << "Memory allocation failed for "
                      "sUnassociatedStationsStats!";
        return false;
    }
    auto msg = reinterpret_cast<sUnassociatedStationsStats *>(msg_buff.get());
    memset(msg_buff.get(), 0, sizeof(stats_out));
    std::copy(stats_out.un_stations_stats.begin(), stats_out.un_stations_stats.end(),
              back_inserter(msg->un_stations_stats));

    event_queue_push(Event::Unassociation_Stations_Stats,
                     msg_buff); // send message internally the monitor

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
