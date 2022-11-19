/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "nl80211_client_whm.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

// Ambiorix
#include "ambiorix_connection_manager.h"
#include "wbapi_utils.h"

using namespace beerocks;
using namespace wbapi;

namespace bwl {

nl80211_client_whm::nl80211_client_whm() : m_connection(AmbiorixConnectionManager::get_connection())
{
}

bool nl80211_client_whm::get_interfaces(std::vector<std::string> &interfaces)
{
    interfaces.clear();
    if (!m_connection) {
        return false;
    }
    // pwhm dm path: WiFi.SSID.*.Name?
    auto ssids = m_connection->get_object(wbapi_utils::search_path_ssid_iface(), 0, false);
    if (!ssids) {
        return false;
    }
    auto ssids_map = ssids->read_childs<AmbiorixVariantMapSmartPtr>();
    if (!ssids_map) {
        return false;
    }
    for (auto const &it : *ssids_map) {
        auto &ssid  = it.second;
        auto ifname = wbapi_utils::get_ssid_iface(ssid);
        if (ifname.empty()) {
            continue;
        }
        interfaces.push_back(ifname);
    }
    return true;
}

bool nl80211_client_whm::get_interface_info(const std::string &interface_name,
                                            interface_info &interface_info)
{
    return false;
}

bool nl80211_client_whm::get_radio_info(const std::string &interface_name, radio_info &radio_info)
{
    return false;
}

bool nl80211_client_whm::get_sta_info(const std::string &interface_name,
                                      const sMacAddr &sta_mac_address, sta_info &sta_info)
{
    if (!m_connection) {
        return false;
    }
    std::string sta_mac_str = tlvf::mac_to_string(sta_mac_address);
    std::string assoc_device_path =
        wbapi_utils::search_path_assocDev_by_mac(interface_name, sta_mac_str);

    auto assoc_device_obj = m_connection->get_object(assoc_device_path, 0, true);
    if (!assoc_device_obj) {
        LOG(ERROR) << "failed to get AssociatedDevice object " << assoc_device_path;
        return false;
    }
    assoc_device_obj->read_child<>(sta_info.tx_bytes, "TxBytes");
    assoc_device_obj->read_child<>(sta_info.rx_bytes, "RxBytes");
    assoc_device_obj->read_child<>(sta_info.tx_packets, "TxPacketCount");
    assoc_device_obj->read_child<>(sta_info.rx_packets, "RxPacketCount");
    assoc_device_obj->read_child<>(sta_info.tx_retries, "Retransmissions");
    assoc_device_obj->read_child<>(sta_info.tx_failed, "TxErrors");
    assoc_device_obj->read_child<>(sta_info.signal_dbm, "SignalStrength");
    assoc_device_obj->read_child<>(sta_info.signal_avg_dbm, "AvgSignalStrength");
    uint32_t u32Val;
    if (assoc_device_obj->read_child<>(u32Val, "LastDataDownlinkRate")) {
        sta_info.rx_bitrate_100kbps = u32Val / 100;
    }
    if (assoc_device_obj->read_child<>(u32Val, "LastDataUplinkRate")) {
        sta_info.tx_bitrate_100kbps = u32Val / 100;
    }
    std::string sVal;
    assoc_device_obj->read_child<>(sVal, "DownlinkBandwidth");
    sta_info.dl_bandwidth = wbapi_utils::bandwith_from_string(sVal + "MHz");

    return true;
}

bool nl80211_client_whm::get_survey_info(const std::string &interface_name, SurveyInfo &survey_info)
{
    return false;
}

bool nl80211_client_whm::set_tx_power_limit(const std::string &interface_name, uint32_t limit)
{
    return false;
}

bool nl80211_client_whm::get_tx_power_dbm(const std::string &interface_name, uint32_t &power)
{
    return false;
}

bool nl80211_client_whm::channel_scan_abort(const std::string &interface_name) { return false; }

} // namespace bwl
