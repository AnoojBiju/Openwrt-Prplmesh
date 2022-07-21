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
}

mon_wlan_hal_whm::~mon_wlan_hal_whm() {}

bool mon_wlan_hal_whm::update_radio_stats(SRadioStats &radio_stats)
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    radio_stats = {};
    return true;
}

bool mon_wlan_hal_whm::update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats)
{
    //LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    vap_stats = {};
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

} // namespace whm

std::shared_ptr<mon_wlan_hal> mon_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback,
                                                  const bwl::hal_conf_t &hal_conf)
{
    return std::make_shared<whm::mon_wlan_hal_whm>(iface_name, callback, hal_conf);
}

} // namespace bwl
