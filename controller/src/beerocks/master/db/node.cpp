/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "node.h"

#include <bcl/beerocks_utils.h>
#include <easylogging++.h>

using namespace beerocks;
using namespace son;

node::node(beerocks::eType type_, const std::string &mac_)
    : mac(mac_), capabilities(m_sta_24ghz_capabilities) // deafult value
{
    type = type_;
    if ((type == beerocks::TYPE_CLIENT) || (type == beerocks::TYPE_IRE_BACKHAUL)) {
        stats_info = std::make_shared<sta_stats_params>();
    }
    m_sta_5ghz_capabilities.valid  = false;
    m_sta_24ghz_capabilities.valid = false;
    client_initial_radio           = net::network_utils::ZERO_MAC;
}

namespace son {
std::ostream &operator<<(std::ostream &os, eTriStateBool value)
{
    if (value == eTriStateBool::FALSE) {
        os << "False";
    } else if (value == eTriStateBool::TRUE) {
        os << "True";
    } else {
        os << "Not-Configured";
    }
    return os;
}


std::ostream &operator<<(std::ostream &os, const node &n)
{
    n.print_node(os);
    return os;
}

void node::print_node(std::ostream &os) const
{
    std::chrono::steady_clock::time_point tCurrTime_steady = std::chrono::steady_clock::now();
    std::chrono::system_clock::time_point tCurrTime_system = std::chrono::system_clock::now();
    auto node_type                                         = get_type();

    os << std::endl;
    if ((node_type == beerocks::TYPE_IRE_BACKHAUL) || (node_type == beerocks::TYPE_CLIENT)) {
        os << " Type: " << ((node_type == beerocks::TYPE_IRE_BACKHAUL) ? "IRE" : "CLIENT")
           << std::endl
           << " State: " << state << std::endl
           << " Name: " << name << std::endl
           << " Mac: " << mac << std::endl
           << " Ipv4: " << ipv4 << std::endl
           << " Manufacturer: " << manufacturer << std::endl
           << " ParentMac: " << parent_mac << std::endl
           << " PreviousParentMac: " << previous_parent_mac << std::endl
           << " Channel: " << int(channel) << std::endl
           << " Bandwidth : " << int(bandwidth) << std::endl
           << " Radio Identifier: " << radio_identifier << std::endl
           << " StaCapabilities: " << std::endl
           << "   ht_mcs=" << int(capabilities.ht_mcs) << " ht_ss=" << int(capabilities.ht_ss)
           << "  ht_bw= " << int(capabilities.ht_bw) << std::endl
           << "   vht_mcs=" << int(capabilities.vht_mcs)
           << " vht_ss=" << int(capabilities.vht_ss) << "  vht_bw= " << int(capabilities.vht_bw)
           << std::endl
           << "   ant_num=" << int(capabilities.ant_num) << " wifi_standard="
           << (capabilities.wifi_standard == beerocks::STANDARD_AC
                   ? "ac"
                   : (capabilities.wifi_standard == beerocks::STANDARD_N ? "n" : "none ac/n"))
           << std::endl
           << " Hierarchy: " << int(hierarchy) << std::endl
           << " State: " << int(state) << std::endl
           << " Supports5ghz: " << bool(supports_5ghz) << std::endl
           << " Supports24ghz: " << bool(supports_24ghz) << std::endl
           << " Statistics:" << std::endl
           << "   LastUpdate: "
           << float((std::chrono::duration_cast<std::chrono::duration<double>>(
                         tCurrTime_steady - stats_info->timestamp))
                        .count())
           << "[sec]" << std::endl
           << "   StatsDelta: " << float(stats_info->stats_delta_ms) / 1000.0 << "[sec]"
           << std::endl
           << "   RSSI (RX): " << int(stats_info->rx_rssi) << " [dBm] " << std::endl
           << "   Packets (RX|TX): " << int(stats_info->rx_packets) << " | "
           << int(stats_info->tx_packets) << std::endl
           << "   Bytes (RX|TX): " << int(stats_info->rx_bytes) << " | "
           << int(stats_info->tx_bytes) << std::endl
           << "   PhyRate (RX|TX): " << int(stats_info->rx_phy_rate_100kb / 10.0) << " | "
           << int(stats_info->tx_phy_rate_100kb / 10.0) << " [Mbps]" << std::endl
           << "   Load (RX|TX): " << int(stats_info->rx_load_percent) << " | "
           << int(stats_info->tx_load_percent) << " [%]" << std::endl
           << "   RX Load: [";

        for (int i = 0; i < 10; ++i) {
            if (i < stats_info->rx_load_percent / 10) {
                os << "#";
            } else {
                os << " ";
            }
        }

        os << "] | TX Load: [";

        for (int i = 0; i < 10; ++i) {
            if (i < stats_info->tx_load_percent / 10) {
                os << "#";
            } else {
                os << " ";
            }
        }

        os << "]" << std::endl
           << "   LastSeen: "
           << float((std::chrono::duration_cast<std::chrono::duration<double>>(tCurrTime_steady -
                                                                               last_seen))
                        .count())
           << "[sec]" << std::endl
           << "   LastStateChange: "
           << float((std::chrono::duration_cast<std::chrono::duration<double>>(tCurrTime_steady -
                                                                               last_state_change))
                        .count())
           << "[sec]" << std::endl;

        if (node_type == beerocks::TYPE_IRE_BACKHAUL) {
            os << "   IfaceType: " << utils::get_iface_type_string(iface_type) << std::endl
               << "   IreHandoff: " << bool(ire_handoff) << std::endl;
        } else if (node_type == beerocks::TYPE_CLIENT) {
            os << "   Handoff: " << bool(handoff) << std::endl
               << "   Confined: " << bool(confined) << std::endl
               << "   Failed5ghzSteerAttemps: " << int(failed_5ghz_steer_attemps) << std::endl
               << "   Failed24ghzSteerAttemps: " << int(failed_24ghz_steer_attemps) << std::endl;
        }

        // persistent db
        if (node_type == beerocks::TYPE_CLIENT) {
            auto client_parameters_last_edit_minutes =
                std::chrono::duration_cast<std::chrono::minutes>(tCurrTime_system -
                                                                 client_parameters_last_edit)
                    .count();
            auto client_time_life_delay_minutes_count = client_time_life_delay_minutes.count();

            os << "Persistent configuration and data:" << std::endl
               << "   ClientParametersLastEdit: " << (client_parameters_last_edit_minutes / 60)
               << " hours, " << (client_parameters_last_edit_minutes % 60) << " minutes"
               << std::endl
               << "   ClientTimeLifeDelay: " << (client_time_life_delay_minutes_count / 60)
               << " hours, "
               << (client_time_life_delay_minutes_count % 60) << " minutes" << std::endl
               << "   ClientStayOnInitialRadio: " << client_stay_on_initial_radio << std::endl
               << "   ClientInitialRadio: " << client_initial_radio << std::endl
               << "   ClientSelectedBands: " << client_selected_bands << std::endl
               << "   ClientIsUnfriendly: " << client_is_unfriendly << std::endl;
        }

    }
}

void node_slave::print_node(std::ostream &os) const
{
    std::chrono::steady_clock::time_point tCurrTime_steady = std::chrono::steady_clock::now();

    os << std::endl
       << " Type: HOSTAP" << std::endl
       << " IfaceType: " << utils::get_iface_type_string(hostap->iface_type) << std::endl
       << " State: " << state << std::endl
       << " Active: " << bool(hostap->active) << std::endl
       << " Is backhual manager: " << hostap->is_backhaul_manager << std::endl
       << " Manufacturer: " << manufacturer << std::endl
       << " Channel: " << int(channel) << std::endl
       << " ChannelBandwidth: " << int(bandwidth) << std::endl
       << " ChannelExtAboveSecondary: " << bool(channel_ext_above_secondary) << std::endl
       << " cac_completed: " << bool(hostap->cac_completed) << std::endl
       << " on_fail_safe_channel: " << bool(hostap->on_fail_safe_channel) << std::endl
       << " on_sub_band_channel: " << bool(hostap->on_sub_band_channel) << std::endl
       << " on_dfs_reentry: " << bool(hostap->on_dfs_reentry) << std::endl
       << " ap_activity_mode: "
       << ((uint8_t(hostap->ap_activity_mode)) ? "AP_ACTIVE_MODE" : "AP_IDLE_MODE")
       << std::endl
       << " Radio Identifier: " << radio_identifier << std::endl
       << " SupportedChannels: " << std::endl;
    for (auto val : hostap->supported_channels) {
        if (val.channel > 0) {
            os << " ch=" << int(val.channel) << " | dfs=" << int(val.is_dfs_channel)
               << " | tx_pow=" << int(val.tx_pow) << " | noise=" << int(val.noise)
               << " [dbm] | bss_overlap=" << int(val.bss_overlap) << std::endl;
        }
    }
    os << " AntGain: " << int(hostap->ant_gain) << std::endl
       << " ConductedPower: " << int(hostap->tx_power) << std::endl
       << " AntNum: " << int(capabilities.ant_num) << std::endl
       << " Statistics:" << std::endl
       << "   LastUpdate: "
       << float((std::chrono::duration_cast<std::chrono::duration<double>>(
                     tCurrTime_steady - hostap->stats_info->timestamp))
                    .count())
       << "[sec]" << std::endl
       << "   StatsDelta: " << float(hostap->stats_info->stats_delta_ms) / 1000.0 << "[sec]"
       << std::endl
       << "   ActiveStaCount: " << int(hostap->stats_info->active_sta_count) << std::endl
       << "   Packets (RX|TX): " << int(hostap->stats_info->rx_packets) << " | "
       << int(hostap->stats_info->tx_packets) << std::endl
       << "   Bytes (RX|TX): " << int(hostap->stats_info->rx_bytes) << " | "
       << int(hostap->stats_info->tx_bytes) << std::endl
       << "   ChannelLoad: " << int(hostap->stats_info->channel_load_percent) << " [%]"
       << std::endl
       << "   TotalStaLoad (RX|TX): " << int(hostap->stats_info->total_client_rx_load_percent)
       << " | " << int(hostap->stats_info->total_client_tx_load_percent) << " [%] "
       << std::endl
       << "**radar statistics**" << std::endl;
    for_each(begin(hostap->Radar_stats), end(hostap->Radar_stats),
             [&](sWifiChannelRadarStats radar_stat) {
                 //for(auto radar_stat : hostap->Radar_stats) {
                 auto delta_radar =
                     std::chrono::duration_cast<std::chrono::seconds>(
                         radar_stat.csa_exit_timestamp - radar_stat.csa_enter_timestamp)
                         .count();
                 // if(delta// _radar)
                 os << "channel = " << int(radar_stat.channel)
                    << " bw = " << int(radar_stat.bandwidth)
                    << " time_in_channel = " << int(delta_radar) << std::endl;
                 //}
             });
    os << "   RX Load: [";

    for (int i = 0; i < 10; ++i) {
        if (i < hostap->stats_info->total_client_rx_load_percent / 10) {
            os << "#";
        } else {
            os << "_";
        }
    }

    os << "] | TX Load: [";

    for (int i = 0; i < 10; ++i) {
        if (i < hostap->stats_info->total_client_tx_load_percent / 10) {
            os << "#";
        } else {
            os << "_";
        }
    }

    os << "]";
}

std::ostream &operator<<(std::ostream &os, const node *n) { return (os << (const node &)(*n)); }

} // namespace son

bool node::get_beacon_measurement(const std::string &ap_mac_, int8_t &rcpi, uint8_t &rsni)
{
    auto it = beacon_measurements.find(ap_mac_);
    if (it == beacon_measurements.end()) {
        LOG(ERROR) << "ap_mac " << ap_mac_ << " does not exist!";
        rcpi = beerocks::RSSI_INVALID;
        rsni = 0;
        return false;
    }
    rcpi = it->second->rcpi;
    rsni = it->second->rsni;
    return true;
}

void node::set_beacon_measurement(const std::string &ap_mac_, int8_t rcpi, uint8_t rsni)
{
    auto it = beacon_measurements.find(ap_mac_);
    if (it == beacon_measurements.end()) {
        std::shared_ptr<beacon_measurement> m =
            std::make_shared<beacon_measurement>(ap_mac_, rcpi, rsni);
        beacon_measurements.insert(std::make_pair(ap_mac_, m));
    } else {
        it->second->rcpi      = rcpi;
        it->second->rsni      = rsni;
        it->second->timestamp = std::chrono::steady_clock::now();
    }
}

bool node::get_cross_rx_rssi(const std::string &ap_mac_, int8_t &rssi, int8_t &packets)
{
    auto it = cross_rx_rssi.find(ap_mac_);
    if (it == cross_rx_rssi.end()) {
        rssi    = beerocks::RSSI_INVALID;
        packets = -1;
        return false;
    }
    rssi    = it->second->rssi;
    packets = it->second->packets;
    return true;
}

void node::set_cross_rx_rssi(const std::string &ap_mac_, int8_t rssi, int8_t packets)
{
    auto it = cross_rx_rssi.find(ap_mac_);
    if (it == cross_rx_rssi.end()) {
        std::shared_ptr<rssi_measurement> m =
            std::make_shared<rssi_measurement>(ap_mac_, rssi, packets);
        cross_rx_rssi.insert(std::make_pair(ap_mac_, m));
    } else {
        it->second->rssi      = rssi;
        it->second->timestamp = std::chrono::steady_clock::now();
        it->second->packets   = packets;
    }
}

void node::clear_cross_rssi()
{
    cross_rx_rssi.clear();
    beacon_measurements.clear();
}

void node::clear_node_stats_info() { stats_info = std::make_shared<sta_stats_params>(); }

void node_slave::clear_hostap_stats_info()
{
    hostap->stats_info = std::make_shared<radio::ap_stats_params>();
}

beerocks::eType node::get_type() const { return type; }

bool node::set_type(beerocks::eType type_)
{
    //only allow TYPE_CLIENT to TYPE_IRE_BACKHAUL change
    if (type_ == type) {
        return true;
    } else if ((type == beerocks::TYPE_CLIENT) && (type_ == beerocks::TYPE_IRE_BACKHAUL)) {
        type = type_;
        return true;
    } else {
        LOG(ERROR) << "Not expected to happen: node = " << mac << ", old type = " << int(type)
                   << ", new type = " << int(type_);
    }
    return false;
}

bool node::link_metrics_data::add_transmitter_link_metric(
    std::shared_ptr<ieee1905_1::tlvTransmitterLinkMetric> tx_link_metric_data)
{
    //  interface_pair_info_length() returns the length in bytes (number of elements * sizeof(sInterfacePairInfo).
    size_t info_size = tx_link_metric_data->interface_pair_info_length() /
                       sizeof(ieee1905_1::tlvTransmitterLinkMetric::sInterfacePairInfo);

    for (size_t i = 0; i < info_size; i++) {
        auto info_tuple = tx_link_metric_data->interface_pair_info(i);

        if (!std::get<0>(info_tuple)) {
            LOG(ERROR) << "add_transmitter_link_metric getting operating class entry has failed!";
            return false;
        }
        auto &InterfacePairInfo = std::get<1>(info_tuple);
        transmitterLinkMetrics.push_back(InterfacePairInfo);

        LOG(DEBUG) << "adding tlvTransmitterLinkMetric data to list"
                   << " phy_rate = " << int(InterfacePairInfo.link_metric_info.phy_rate);
    }
    return true;
}

bool node::link_metrics_data::add_receiver_link_metric(
    std::shared_ptr<ieee1905_1::tlvReceiverLinkMetric> RxLinkMetricData)
{
    //  interface_pair_info_length() returns the length in bytes (number of elements * sizeof(sInterfacePairInfo).
    size_t info_size = RxLinkMetricData->interface_pair_info_length() /
                       sizeof(ieee1905_1::tlvReceiverLinkMetric::sInterfacePairInfo);

    for (size_t i = 0; i < info_size; i++) {
        auto info_tuple = RxLinkMetricData->interface_pair_info(i);

        if (!std::get<0>(info_tuple)) {
            LOG(ERROR) << "add_receiver_link_metric getting operating class entry has failed!";
            return false;
        }
        auto &InterfacePairInfo = std::get<1>(info_tuple);
        receiverLinkMetrics.push_back(InterfacePairInfo);

        LOG(DEBUG) << "adding tlvReceiverLinkMetric data to list"
                   << " rssi_db = " << int(InterfacePairInfo.link_metric_info.rssi_db);
    }
    return true;
}

bool node::ap_metrics_data::add_ap_metric_data(std::shared_ptr<wfa_map::tlvApMetrics> ApMetricData)
{
    bssid                               = ApMetricData->bssid();
    channel_utilization                 = ApMetricData->channel_utilization();
    number_of_stas_currently_associated = ApMetricData->number_of_stas_currently_associated();

    //copy all fields to database vector
    estimated_service_info_fields.clear();
    std::copy_n(ApMetricData->estimated_service_info_field(),
                ApMetricData->estimated_service_info_field_length(),
                std::back_inserter(estimated_service_info_fields));
    if (ApMetricData->estimated_service_parameters().include_ac_bk) {
        include_ac_bk = true;
    }
    if (ApMetricData->estimated_service_parameters().include_ac_vo) {
        include_ac_vo = true;
    }
    if (ApMetricData->estimated_service_parameters().include_ac_vi) {
        include_ac_vi = true;
    }
    return true;
}

std::vector<sMacAddr> node::get_unused_interfaces(const std::vector<sMacAddr> &new_interfaces)
{
    auto interfaces_mac_list = get_interfaces_mac();

    // Fastest way is checking that they are equal. If they are, nothing to be erased.
    if (interfaces_mac_list == new_interfaces)
        return {};

    // Loop through active interface and remove active ones to left only unused interfaces.
    for (auto &element : new_interfaces) {
        interfaces_mac_list.erase(
            std::remove(interfaces_mac_list.begin(), interfaces_mac_list.end(), element),
            interfaces_mac_list.end());
    }

    return interfaces_mac_list;
}

std::shared_ptr<prplmesh::controller::db::Interface> node::add_interface(const sMacAddr &mac)
{
    auto it =
        std::find_if(m_interfaces.begin(), m_interfaces.end(),
                     [mac](const std::shared_ptr<prplmesh::controller::db::Interface> &interface) {
                         return interface->m_mac == mac;
                     });
    if (it == m_interfaces.end()) {
        m_interfaces.emplace_back(
            std::make_shared<prplmesh::controller::db::Interface>(mac, *this));
        return m_interfaces.back();
    } else {
        return *it;
    }
}

std::shared_ptr<prplmesh::controller::db::Interface> node::get_interface(const sMacAddr &mac)
{
    auto it =
        std::find_if(m_interfaces.begin(), m_interfaces.end(),
                     [mac](const std::shared_ptr<prplmesh::controller::db::Interface> &interface) {
                         return interface->m_mac == mac;
                     });
    if (it == m_interfaces.end()) {
        return nullptr;
    } else {
        return *it;
    }
}

void node::remove_interface(const sMacAddr &mac)
{
    auto it =
        std::find_if(m_interfaces.begin(), m_interfaces.end(),
                     [mac](const std::shared_ptr<prplmesh::controller::db::Interface> &interface) {
                         return interface->m_mac == mac;
                     });
    if (it != m_interfaces.end()) {
        m_interfaces.erase(it);
    }
}

std::vector<sMacAddr> node::get_interfaces_mac()
{
    std::vector<sMacAddr> result{};

    for (const auto &interface : m_interfaces) {
        result.push_back(interface->m_mac);
    }

    return result;
}

std::shared_ptr<prplmesh::controller::db::Interface::sNeighbor>
node::add_neighbor(const sMacAddr &interface_mac, const sMacAddr &neighbor_mac, bool flag_ieee1905)
{
    auto interface = get_interface(interface_mac);
    if (!interface) {
        LOG(ERROR) << "Failed to get interface with mac:" << interface_mac;
        return nullptr;
    }

    return interface->m_neighbors.add(neighbor_mac, flag_ieee1905);
}

node_slave::node_slave(const std::string &mac): node(beerocks::eType::TYPE_SLAVE, mac) {
    hostap             = std::make_shared<radio>();
    hostap->stats_info = std::make_shared<radio::ap_stats_params>();
};

std::shared_ptr<node> son::create_node(beerocks::eType type_, const std::string &mac) {
    switch(type_) {
    case beerocks::eType::TYPE_GW:
        return std::make_shared<node_gw>(mac);
    case beerocks::eType::TYPE_IRE:
        return std::make_shared<node_ire>(mac);
    case beerocks::eType::TYPE_IRE_BACKHAUL:
        return std::make_shared<node_ire_backhaul>(mac);
    case beerocks::eType::TYPE_SLAVE:
        return std::make_shared<node_slave>(mac);
    case beerocks::eType::TYPE_CLIENT:
        return std::make_shared<node_client>(mac);
    case beerocks::eType::TYPE_ETH_SWITCH:
        return std::make_shared<node_eth_switch>(mac);
    case beerocks::eType::TYPE_ANY:
        return std::make_shared<node_any>(mac);
    default: {
        LOG(ERROR) << "Cannot create node of type " << static_cast<int>(type_);
        return nullptr;
    }
    }
}
