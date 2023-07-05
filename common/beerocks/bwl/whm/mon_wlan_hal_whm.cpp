/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "mon_wlan_hal_whm.h"
#include <bwl/mon_wlan_hal_types.h>

#include <amxd/amxd_object.h>
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
    subscribe_to_scan_complete_events();
    m_scan_active = false;
}

mon_wlan_hal_whm::~mon_wlan_hal_whm() {}

bool mon_wlan_hal_whm::update_radio_stats(SRadioStats &radio_stats)
{
    lock();

    std::string stats_path = m_radio_path + "Stats.";

    auto stats_obj = m_ambiorix_cl.get_object(stats_path);
    if (!stats_obj) {
        LOG(ERROR) << "failed to get radio Stats object " << stats_path;
        return true;
    }

    stats_obj->read_child(radio_stats.tx_bytes_cnt, "BytesSent");
    stats_obj->read_child(radio_stats.rx_bytes_cnt, "BytesReceived");
    stats_obj->read_child(radio_stats.tx_packets_cnt, "PacketsSent");
    stats_obj->read_child(radio_stats.rx_packets_cnt, "PacketsReceived");
    stats_obj->read_child(radio_stats.errors_sent, "ErrorsSent");
    stats_obj->read_child(radio_stats.errors_received, "ErrorsReceived");
    stats_obj->read_child(radio_stats.noise, "Noise");

    return true;
}

bool mon_wlan_hal_whm::update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats)
{
    lock();

    std::string ssid_stats_path = wbapi_utils::search_path_ssid_by_iface(vap_iface_name) + "Stats.";

    auto ssid_stats_obj = m_ambiorix_cl.get_object(ssid_stats_path);
    if (!ssid_stats_obj) {
        LOG(ERROR) << "failed to get SSID Stats object, path:" << ssid_stats_path;
        return true;
    }

    ssid_stats_obj->read_child(vap_stats.tx_bytes_cnt, "BytesSent");
    ssid_stats_obj->read_child(vap_stats.rx_bytes_cnt, "BytesReceived");
    ssid_stats_obj->read_child(vap_stats.tx_packets_cnt, "PacketsSent");
    ssid_stats_obj->read_child(vap_stats.rx_packets_cnt, "PacketsReceived");
    ssid_stats_obj->read_child(vap_stats.errors_sent, "ErrorsSent");
    ssid_stats_obj->read_child(vap_stats.errors_received, "ErrorsReceived");
    ssid_stats_obj->read_child(vap_stats.retrans_count, "RetransCount");

    return true;
}

bool mon_wlan_hal_whm::update_stations_stats(const std::string &vap_iface_name,
                                             const std::string &sta_mac, SStaStats &sta_stats,
                                             bool is_read_unicast)
{
    lock();
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
    if (m_ambiorix_cl.get_param(s_float, assoc_device_path, "SignalNoiseRatio")) {
        if (s_float >= beerocks::SNR_MIN) {
            sta_stats.rx_snr_watt = std::pow(10, s_float / float(10));
            sta_stats.rx_snr_watt_samples_cnt++;
        }
    }

    m_ambiorix_cl.get_param(sta_stats.tx_bytes_cnt, assoc_device_path, "TxBytes");
    m_ambiorix_cl.get_param(sta_stats.rx_bytes_cnt, assoc_device_path, "RxBytes");
    m_ambiorix_cl.get_param(sta_stats.rx_packets_cnt, assoc_device_path, "RxPacketCount");
    m_ambiorix_cl.get_param(sta_stats.tx_packets_cnt, assoc_device_path, "TxPacketCount");

    return true;
}

bool mon_wlan_hal_whm::update_station_qos_control_params(const std::string &vap_iface_name,
                                                         const std::string &sta_mac,
                                                         SStaQosCtrlParams &sta_qos_ctrl_params)
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
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
    lock();
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    args.add_child("mac", tlvf::mac_to_string(req.sta_mac.oct));
    args.add_child("bssid", tlvf::mac_to_string(req.bssid.oct));
    args.add_child("class", uint8_t(req.op_class));
    args.add_child("channel", uint8_t(req.channel));
    args.add_child("ssid", std::string((const char *)req.ssid));
    std::string wifi_ap_path = wbapi_utils::search_path_ap_by_iface(vap_iface_name);
    bool ret = m_ambiorix_cl.call(wifi_ap_path, "sendRemoteMeasumentRequest", args, result);

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
    lock();

    if (channel_pool.empty()) {
        LOG(INFO) << "channel_pool is empty!, scanning all channels";
    }

    std::string channels;
    if (!channel_pool.empty()) {
        for (auto &input_channel : channel_pool) {
            channels += std::to_string(input_channel);
            channels += ",";
        }
        channels.pop_back();
    }

    if (m_scan_active) {
        AmbiorixVariant result_abort;
        AmbiorixVariant args_abort(AMXC_VAR_ID_HTABLE);
        //scan is already active, as per spec, cancel the old one and start new one
        if (!m_ambiorix_cl.call(m_radio_path, "stopScan", args_abort, result_abort)) {
            LOG(INFO) << " remote function stopScan startScan Failed!";
            return false;
        } else {
            m_scan_active = false;
            event_queue_push(Event::Channel_Scan_Aborted);
        }
    }
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    if (!channels.empty()) {
        args.add_child<>("channels", channels);
    }
    if (!m_ambiorix_cl.call(m_radio_path, "startScan", args, result)) {
        LOG(ERROR) << " remote function call startScan Failed!";
        return false;
    }
    event_queue_push(Event::Channel_Scan_Triggered);
    m_scan_active = true;
    return true;
}

bool mon_wlan_hal_whm::channel_scan_dump_cached_results()
{
    lock();
    //read stats cached internally
    for (auto &map : m_scan_results) {
        auto results_notif = std::make_shared<sCHANNEL_SCAN_RESULTS_NOTIFICATION>();
        auto &results      = results_notif->channel_scan_results;

        string_utils::copy_string(results.ssid, map["SSID"].c_str(),
                                  beerocks::message::WIFI_SSID_MAX_LENGTH);

        results.bssid = tlvf::mac_from_string(map["BSSID"]);

        int32_t center_channel = std::stoi(map["CentreChannel"]);

        int32_t bandwidth                   = std::stoi(map["Bandwidth"]);
        results.operating_channel_bandwidth = utils_wlan_hal_whm::get_bandwidth_from_int(bandwidth);

        results.channel = std::stoul(map["Channel"]);

        WifiChannel wifi_channel(results.channel, center_channel,
                                 utils::convert_bandwidth_to_enum(bandwidth));
        results.operating_frequency_band =
            utils_wlan_hal_whm::eFreqType_to_eCh_scan_Op_Fr_Ba(wifi_channel.get_freq_type());

        results.signal_strength_dBm = std::stoi(map["RSSI"]);

        if (map.find("Noise") != map.end()) {
            results.noise_dBm = std::stoi(map["Noise"]);
        }

        if (map.find("SecurityModeEnabled") != map.end()) {
            std::string security_mode_enabled(map["SecurityModeEnabled"]);
            results.security_mode_enabled =
                utils_wlan_hal_whm::get_scan_security_modes_from_str(security_mode_enabled);
        }

        if (map.find("EncryptionMode") != map.end()) {
            std::string encryption_mode(map["EncryptionMode"]);
            results.encryption_mode =
                utils_wlan_hal_whm::get_scan_result_encryption_modes_from_str(encryption_mode);
        }

        if (map.find("OperatingStandards") != map.end()) {
            std::string supported_standards(map["OperatingStandards"]);
            results.supported_standards =
                utils_wlan_hal_whm::get_scan_result_operating_standards_from_str(
                    supported_standards);
        }

        LOG(DEBUG) << "Processing results for BSSID:" << results.bssid
                   << " on Channel: " << results.channel;
        event_queue_push(Event::Channel_Scan_Dump_Result, results_notif);
        event_queue_push(Event::Channel_Scan_New_Results_Ready, results_notif);
    }

    return true;
}

bool mon_wlan_hal_whm::channel_scan_dump_results()
{
    lock();
    //Lets update our internal results from the pwhm then dump them
    get_scan_results_from_pwhm();
    channel_scan_dump_cached_results(); //lets dump the results
    return true;
}

bool mon_wlan_hal_whm::generate_connected_clients_events(
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
                ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));
            LOG_IF(msg_buff == nullptr, FATAL) << "Memory allocation failed!";
            // Initialize the message
            memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));
            auto msg =
                reinterpret_cast<sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
            msg->vap_id = vap_id;
            msg->mac    = tlvf::mac_from_string(mac_addr);

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

bool mon_wlan_hal_whm::pre_generate_connected_clients_events()
{
    // For the pwhm and the evolution of prplmesh, we dont see a need to implement this function, all will be done throughh the main
    // function generate_connected_clients_events
    return true;
}

bool mon_wlan_hal_whm::channel_scan_abort()
{
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    if (!m_ambiorix_cl.call(m_radio_path, "stopScan", args, result)) {
        LOG(ERROR) << " remote function call stopScan Failed!";
        return false;
    }
    event_queue_push(Event::Channel_Scan_Aborted);
    return true;
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

bool mon_wlan_hal_whm::set_available_estimated_service_parameters(
    wfa_map::tlvApMetrics::sEstimatedService &estimated_service_parameters)
{
    estimated_service_parameters.include_ac_bk = 1;
    estimated_service_parameters.include_ac_be = 1;
    estimated_service_parameters.include_ac_vo = 1;
    estimated_service_parameters.include_ac_vi = 1;

    return true;
}

bool mon_wlan_hal_whm::set_estimated_service_parameters(uint8_t *esp_info_field)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    return true;
}

/*  will get the unassociated stations stats from Ambirorix
*/
bool mon_wlan_hal_whm::sta_unassoc_rssi_measurement(
    std::unordered_map<std::string, uint8_t> &new_list)
{
    /*
        Example of NonAssociatedDevice object:
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.{i}.
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.{i}.MACAddress=AA:BB:CC:DD:EE:FF
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.{i}.SignalStrength=0
        WiFi.Radio.wifi0.NaStaMonitor.NonAssociatedDevice.{i}.TimeStamp=0001-01-01T00:00:00Z
    */

    std::vector<sUnassociatedStationStats> stats;

    std::list<std::string> amx_un_stations_to_be_removed;

    std::string non_associated_device_path = m_radio_path + "NaStaMonitor.NonAssociatedDevice.";

    auto non_ass_devices =
        m_ambiorix_cl.get_object_multi<AmbiorixVariantMapSmartPtr>(non_associated_device_path);
    if (!non_ass_devices) {
        return false;
    }

    //Lets iterate through all instances
    for (auto &non_ass_device : *non_ass_devices) {
        uint8_t signal_strength(0);
        uint8_t channel(0);
        uint8_t operating_class(0);
        std::string time_stamp_str;
        std::string mac_address_amx;
        non_ass_device.second.read_child(mac_address_amx, "MACAddress");
        if (mac_address_amx.empty()) {
            continue;
        }
        non_ass_device.second.read_child(signal_strength, "SignalStrength");
        non_ass_device.second.read_child(channel, "Channel");
        non_ass_device.second.read_child(operating_class, "OperatingClass");
        non_ass_device.second.read_child(time_stamp_str, "TimeStamp");

        amxc_ts_t time;
        memset(&time, 0, sizeof(amxc_ts_t));
        amxc_ts_parse(&time, time_stamp_str.c_str(), time_stamp_str.size());

        if (new_list.find(mac_address_amx) != new_list.end()) {
            //NonAssociatedDevice exists -->get the result and update the data
            sUnassociatedStationStats new_stat = {
                tlvf::mac_from_string(mac_address_amx),
                signal_strength,
                channel,
                operating_class,
                (uint32_t)time.sec,
            };
            stats.push_back(new_stat);
            LOG(DEBUG) << " read unassociated station stats for mac_address: " << mac_address_amx
                       << " SignalStrength: " << signal_strength << " channel: " << channel
                       << " operating_class: " << operating_class
                       << " TimeStamp(string): " << time_stamp_str
                       << " and TimeStamp(seconds): " << (uint32_t)time.sec;
            new_list.erase(mac_address_amx); // consumed!
        } else { // -->controller is not interested on it any more--> remove it from the dm
            amx_un_stations_to_be_removed.push_back(mac_address_amx);
        }
    }

    std::string nasta_monitor_path = m_radio_path + "NaStaMonitor";
    //Now add the newly added unassociated stations
    for (auto &new_station : new_list) {
        std::string mac_address(new_station.first);

        AmbiorixVariant result;
        AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
        args.add_child("MACAddress", mac_address);
        if (!m_ambiorix_cl.call(nasta_monitor_path, "createNonAssociatedDevice", args, result)) {
            LOG(ERROR) << " remote function call createNonAssociatedDevice for object "
                       << nasta_monitor_path << " Failed!";
            continue;
        }

        LOG(TRACE) << "Non Associated Station with MACAddress: " << mac_address << "added to "
                   << non_associated_device_path;
    }

    // Now lets remove all stations the controller do not want them anymore
    for (auto &station_to_remove : amx_un_stations_to_be_removed) {
        AmbiorixVariant result;
        AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
        args.add_child("MACAddress", station_to_remove);
        if (!m_ambiorix_cl.call(nasta_monitor_path, "deleteNonAssociatedDevice", args, result)) {
            LOG(ERROR) << " remote function call deleteNonAssociatedDevice"
                       << " for object " << nasta_monitor_path
                       << " and  MACAddress: " << station_to_remove << " Failed!!";
            continue;
        } else {
            LOG(TRACE) << "Successfully removed unassociated station with mac: "
                       << station_to_remove
                       << " and path: " << nasta_monitor_path + station_to_remove;
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

bool mon_wlan_hal_whm::process_scan_complete_event(const std::string &result)
{
    if (result == "error") {
        LOG(DEBUG) << " received ScanComplete event with Error indication!";
        m_scan_active = false;
        event_queue_push(Event::Channel_Scan_Finished);
        return false;
    }
    if (result == "done" && m_scan_active) {
        m_scan_results.clear();
        event_queue_push(Event::Channel_Scan_Finished);
        m_scan_active = false;
        get_scan_results_from_pwhm();
    }
    return true;
}

bool mon_wlan_hal_whm::get_scan_results_from_pwhm()
{
    AmbiorixVariant result;
    AmbiorixVariant args(AMXC_VAR_ID_HTABLE);
    if (!m_ambiorix_cl.call(m_radio_path, "getScanResults", args, result)) {
        LOG(ERROR) << " remote function call getScanResults Failed!";
        return false;
    }
    AmbiorixVariantListSmartPtr scan_results_list =
        result.read_children<AmbiorixVariantListSmartPtr>();
    if (!scan_results_list) {
        LOG(ERROR) << "failed reading scan_results!";
        return false;
    }

    if (scan_results_list->empty()) {
        LOG(ERROR) << "scan_results are empty";
        return false;
    }

    m_scan_results.clear();

    auto results_as_wrapped_list = scan_results_list->front();

    auto ssid_results_as_list =
        results_as_wrapped_list.read_children<AmbiorixVariantListSmartPtr>();

    for (auto &ssid_results_map : *ssid_results_as_list) {
        auto data_map = ssid_results_map.read_children<AmbiorixVariantMapSmartPtr>();
        auto &map     = *data_map;

        std::unordered_map<std::string, std::string> map_cach_bssid;

        std::string bssid;
        if (map.find("BSSID") != map.end()) {
            map["BSSID"].get(bssid);
            map_cach_bssid["BSSID"] = bssid;
        } else {
            LOG(DEBUG) << "BSSID is missing,skipping";
            continue;
        }

        if (map.find("SSID") != map.end()) {
            std::string ssid;
            map["SSID"].get(ssid);
            map_cach_bssid["SSID"] = ssid;
        } else {
            LOG(DEBUG) << "SSID is missing,skipping";
            continue;
        }

        if (map.find("CentreChannel") != map.end()) {
            std::string center_channel;
            map["CentreChannel"].get(center_channel);
            map_cach_bssid["CentreChannel"] = center_channel;
        } else {
            LOG(DEBUG) << "CentreChannel is missing,skipping";
            continue;
        }

        std::string bandwidth;
        if (map.find("Bandwidth") != map.end()) {
            map["Bandwidth"].get(bandwidth);
            map_cach_bssid["Bandwidth"] = bandwidth;
        } else {
            LOG(DEBUG) << "Bandwidth is missing,skipping";
            continue;
        }
        if (map.find("Channel") != map.end()) {
            std::string channel;
            map["Channel"].get(channel);
            map_cach_bssid["Channel"] = channel;
        } else {
            LOG(DEBUG) << "Channel is missing,skipping";
            continue;
        }

        if (map.find("RSSI") != map.end()) {
            std::string rssi;
            map["RSSI"].get(rssi);
            map_cach_bssid["RSSI"] = rssi;
        } else {
            LOG(DEBUG) << "RSSI is missing,skipping";
            continue;
        }

        if (map.find("Noise") != map.end()) {
            std::string noise;
            map["Noise"].get(noise);
            map_cach_bssid["Noise"] = noise;
        }

        if (map.find("SecurityModeEnabled") != map.end()) {
            std::string security_mode_enabled;
            map["SecurityModeEnabled"].get(security_mode_enabled);
            map_cach_bssid["SecurityModeEnabled"] = security_mode_enabled;
        }

        if (map.find("EncryptionMode") != map.end()) {
            std::string encryption_mode;
            map["EncryptionMode"].get(encryption_mode);
            map_cach_bssid["EncryptionMode"] = encryption_mode;
        }

        if (map.find("OperatingStandards") != map.end()) {
            std::string operating_standards;
            map["OperatingStandards"].get(operating_standards);
            map_cach_bssid["OperatingStandards"] = operating_standards;
        }

        m_scan_results.push_back(map_cach_bssid);
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
