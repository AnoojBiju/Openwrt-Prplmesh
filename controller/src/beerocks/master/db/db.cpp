/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "db.h"

#include "../tasks/agent_monitoring_task.h"
#include <bcl/beerocks_utils.h>
#include <bcl/beerocks_wifi_channel.h>
#include <bcl/network/sockets.h>
#include <bcl/son/son_wireless_utils.h>
#include <beerocks/tlvf/beerocks_message.h>
#include <bpl/bpl_cfg.h>
#include <bpl/bpl_db.h>
#include <cmath>
#include <easylogging++.h>

#include <algorithm>

using namespace beerocks;
using namespace beerocks_message;
using namespace son;
using namespace net;

const std::string db::TIMESTAMP_STR            = "timestamp";
const std::string db::TIMELIFE_DELAY_STR       = "timelife_minutes";
const std::string db::INITIAL_RADIO_ENABLE_STR = "initial_radio_enable";
const std::string db::INITIAL_RADIO_STR        = "initial_radio";
const std::string db::SELECTED_BANDS_STR       = "selected_bands";
const std::string db::IS_UNFRIENDLY_STR        = "is_unfriendly";

constexpr std::chrono::minutes CHANNEL_PREFERENCE_EXPIRATION(5);

// static
std::string db::type_to_string(beerocks::eType type)
{
    switch (type) {
    case beerocks::eType::TYPE_GW:
        return "gateway";
    case beerocks::eType::TYPE_IRE:
        return "ire";
    case beerocks::eType::TYPE_IRE_BACKHAUL:
        return "ire_bh";
    case beerocks::eType::TYPE_SLAVE:
        return "slave";
    case beerocks::eType::TYPE_CLIENT:
        return "client";
    case beerocks::eType::TYPE_ETH_SWITCH:
        return "eth_switch";
    case beerocks::eType::TYPE_ANY:
        return "any";
    default:
        return {};
    }
}

std::string db::client_db_entry_from_mac(const sMacAddr &mac)
{
    std::string db_entry = tlvf::mac_to_string(mac);

    std::replace(db_entry.begin(), db_entry.end(), ':', '_');

    return db_entry;
}

sMacAddr db::client_db_entry_to_mac(std::string db_entry)
{
    std::replace(db_entry.begin(), db_entry.end(), '_', ':');

    if (!network_utils::is_valid_mac(db_entry)) {
        return network_utils::ZERO_MAC;
    }

    return tlvf::mac_from_string(db_entry);
}

std::string db::timestamp_to_string_seconds(const std::chrono::system_clock::time_point timestamp)
{
    return std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(timestamp.time_since_epoch()).count());
}

std::chrono::system_clock::time_point db::timestamp_from_seconds(int timestamp_sec)
{
    return std::chrono::system_clock::time_point(std::chrono::seconds(timestamp_sec));
}

std::pair<std::string, int> db::get_dm_index_from_path(const std::string &dm_path)
{
    std::pair<std::string, int> result = std::make_pair("", 0);

    if (dm_path.empty()) {
        LOG(ERROR) << "Empty data model path.";
        return result;
    }

    std::size_t found = dm_path.find_last_of(".");

    // Verifies errors as not finding dot and finding it as last member.
    if (found == std::string::npos || found >= dm_path.size()) {
        LOG(ERROR) << "Not suitable data model path: " << dm_path;
        return result;
    }
    result.first  = dm_path.substr(0, found);
    result.second = std::stoul(dm_path.substr(found + 1));
    return result;
}

// static - end

std::shared_ptr<Agent> db::get_agent_by_radio_uid(const sMacAddr &radio_uid)
{
    for (const auto &agent_map_element : m_agents) {
        const auto &agent = agent_map_element.second;
        if (agent->radios.find(radio_uid) != agent->radios.end()) {
            return agent;
        }
    }
    LOG(ERROR) << "No agent containing radio " << radio_uid << " found";
    return {};
}

std::shared_ptr<Agent> db::get_agent_by_parent(const sMacAddr &parent_mac)
{
    for (const auto &agent : m_agents) {
        if (agent.second->parent_mac == parent_mac) {
            return agent.second;
        }
    }

    return {};
}

std::shared_ptr<Agent> db::get_agent(const sMacAddr &al_mac)
{
    auto agent = m_agents.get(al_mac);
    if (!agent) {
        LOG(ERROR) << "Could not find Agent: " << al_mac << " in m_agents";
    }

    return agent;
}

bool db::set_sta_association_frame(const sMacAddr &sta_mac, std::vector<uint8_t> assoc_frame)
{
    auto sta = get_station(sta_mac);
    if (!sta) {
        LOG(ERROR) << "Station " << sta_mac << " is not known";
        return false;
    }
    sta->m_assoc_frame = assoc_frame;
    return true;
}

std::vector<uint8_t> db::get_association_frame_by_sta_mac(const sMacAddr &sta_mac)
{
    auto sta = get_station(sta_mac);
    if (!sta) {
        LOG(ERROR) << "Station " << sta_mac << " is not known";
        return {};
    }
    return sta->m_assoc_frame;
}

std::shared_ptr<Agent> db::get_agent_by_bssid(const sMacAddr &bssid)
{
    for (const auto &agent : m_agents) {
        for (const auto &radio : agent.second->radios) {
            auto bss = radio.second->bsses.get(bssid);
            if (bss) {
                return agent.second;
            }
        }
    }

    LOG(ERROR) << "No agent found containing bssid=" << bssid;
    return {};
}

std::shared_ptr<Agent::sRadio> db::get_radio(const sMacAddr &al_mac, const sMacAddr &radio_uid)
{
    auto agent = m_agents.get(al_mac);
    if (!agent) {
        LOG(ERROR) << "No agent found for al_mac " << al_mac;
        return {};
    }
    auto radio = agent->radios.get(radio_uid);
    return radio;
}

std::shared_ptr<Agent::sRadio> db::get_radio_by_bssid(const sMacAddr &bssid)
{
    for (const auto &agent : m_agents) {
        for (const auto &radio : agent.second->radios) {
            auto bss = radio.second->bsses.get(bssid);
            if (bss) {
                return radio.second;
            }
        }
    }

    LOG(ERROR) << "Radio with BSSID " << bssid << " not found";
    return {};
}

std::shared_ptr<Agent::sRadio> db::get_radio_by_backhaul_cap(const sMacAddr &bh_sta)
{
    if (bh_sta == beerocks::net::network_utils::ZERO_MAC) {
        LOG(INFO) << "Zero Backhaul Station Capability is requested";
        return {};
    }

    for (const auto &agent : m_agents) {
        for (const auto &radio : agent.second->radios) {

            if (radio.second->backhaul_station_mac == bh_sta) {
                return radio.second;
            }
        }
    }

    LOG(ERROR) << "Radio with Backhaul Station Capability " << bh_sta << " not found";
    return {};
}

void db::set_log_level_state(const beerocks::eLogLevel &log_level, const bool &new_state)
{
    logger.set_log_level_state(log_level, new_state);
}

// General set/get
bool db::has_station(const sMacAddr &mac) { return (get_station(mac) != nullptr); }

std::string db::get_sta_data_model_path(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return {};
    }
    return pSta->dm_path;
}

std::shared_ptr<Agent> db::add_gateway(const sMacAddr &mac)
{
    auto agent = m_agents.add(mac);

    agent->is_gateway = true;

    auto data_model_path = dm_add_device_element(mac);
    if (data_model_path.empty()) {
        LOG(ERROR) << "Failed to add device element for the gateway, mac: " << mac;
        return agent;
    }

    agent->dm_path = data_model_path;

    if (!dm_set_device_multi_ap_capabilities(tlvf::mac_to_string(mac))) {
        LOG(ERROR) << "Failed to set multi ap capabilities";
    }

    if (!dm_update_collection_intervals(config.link_metrics_request_interval_seconds)) {
        LOG(ERROR) << "Failed to set collection intervals";
    }

    if (!dm_set_agent_oui(agent)) {
        LOG(ERROR) << "Failed to set Manufacturer OUI";
    }

    return agent;
}

std::shared_ptr<Agent> db::add_agent(const sMacAddr &mac, const sMacAddr &parent_mac)
{
    if (mac == network_utils::ZERO_MAC) {
        LOG(ERROR) << "mac supplied for add_agent is zero_mac";
        return {};
    }
    auto agent = m_agents.add(mac);
    if (!agent) {
        LOG(ERROR) << "Failed to add Agent " << mac;
        return agent;
    }

    agent->parent_mac = parent_mac;

    auto data_model_path = dm_add_device_element(mac);
    if (data_model_path.empty()) {
        LOG(ERROR) << "Failed to add device element for the ire, mac: " << mac;
        return agent;
    }

    agent->dm_path = data_model_path;

    if (!dm_set_device_multi_ap_capabilities(tlvf::mac_to_string(mac))) {
        LOG(ERROR) << "Failed to set multi ap capabilities";
    }

    if (!dm_update_collection_intervals(config.link_metrics_request_interval_seconds)) {
        LOG(ERROR) << "Failed to set collection intervals";
    }

    if (!dm_set_agent_oui(agent)) {
        LOG(ERROR) << "Failed to set Manufacturer OUI";
    }

    m_ambiorix_datamodel->set(agent->dm_path + ".MultiAPDevice", "EasyMeshAgentOperationMode",
                              std::string{"RUNNING"});

    return agent;
}

std::shared_ptr<Station> db::add_backhaul_station(const sMacAddr &mac, const sMacAddr &parent_mac)
{
    auto station = m_stations.add(mac);
    if (!station) {
        return {};
    }
    station->set_bSta(true);

    // Save stations's parent
    std::shared_ptr<Agent::sRadio::sBss> parent_bss = get_bss(parent_mac);
    if (parent_bss) {
        set_station_bss(station, parent_bss);
    } else {
        std::shared_ptr<Agent::sEthSwitch> parent_switch = get_eth_switch(parent_mac);
        if (parent_switch) {
            station->set_eth_switch(parent_switch);
        }
    }

    // TODO: Add instance for Radio.BackhaulSta element from the Data Elements
    return station;
}

bool db::add_eth_switch(const sMacAddr &mac, const sMacAddr &parent_mac)
{
    std::shared_ptr<Agent> agent = get_agent(parent_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to find Agent " << parent_mac;
        return false;
    }
    agent->eth_switches.add(mac);
    LOG(ERROR) << "TMP add eth switch " << mac << " with parent " << parent_mac;

    // TODO: Add node to the controller data model via m_ambiorix_datamodel for Wired BH agent
    return true;
}

bool db::dm_add_radio_element(Agent::sRadio &radio, Agent &agent)
{

    // Empty path for parent object refers to disabled NBAPI. Return true silently.
    if (agent.dm_path.empty()) {
        return true;
    }

    // Radio path is empty, so this is newly introduced object, add to datamodel.
    if (radio.dm_path.empty()) {

        const std::string path_to_radio = agent.dm_path + ".Radio";

        radio.dm_path = m_ambiorix_datamodel->add_instance(path_to_radio);
        if (radio.dm_path.empty()) {
            LOG(ERROR) << "Failed to add radio instance " << path_to_radio
                       << ". ruid: " << radio.radio_uid;
            return false;
        }
    }

    return m_ambiorix_datamodel->set(radio.dm_path, "ID", radio.radio_uid);
}

bool db::dm_set_multi_ap_sta_noise_param(Station &station, const uint8_t rcpi, const uint8_t rsni)
{
    auto bss = station.get_bss();

    if (!bss) {
        LOG(INFO) << "BSS of the Station is empty mac: " << station.mac;
        return false;
    }

    if (station.dm_path.empty()) {
        return true;
    }

    uint32_t anpi = rcpi / (1 + std::pow(10, (rsni / 20.0) - 1));

    if (!bss->radio.stats_info) {
        LOG(ERROR) << "Failed to get stats of hosting radio " << bss->radio.radio_uid;
        return false;
    }

    return m_ambiorix_datamodel->set(station.dm_path + ".MultiAPSTA", "Noise",
                                     anpi + bss->radio.stats_info->noise);
}

bool db::dm_add_sta_beacon_measurement(const beerocks_message::sBeaconResponse11k &beacon)
{
    auto sta = get_station(beacon.sta_mac);

    if (!sta) {
        LOG(ERROR) << "Failed to get station with mac: " << beacon.sta_mac;
        return false;
    }
    if (sta->dm_path.empty()) {
        return true;
    }

    if (m_dialog_tokens[beacon.sta_mac] != beacon.dialog_token) {
        m_ambiorix_datamodel->remove_all_instances(sta->dm_path + ".MeasurementReport");
    }
    m_dialog_tokens[beacon.sta_mac] = beacon.dialog_token;

    std::string measurement_inst =
        m_ambiorix_datamodel->add_instance(sta->dm_path + ".MeasurementReport");

    if (measurement_inst.empty()) {
        LOG(ERROR) << "Failed to add: " << sta->dm_path << ".MeasurementReport";
        return false;
    }
    bool ret_val = true;

    ret_val &= dm_set_multi_ap_sta_noise_param(*sta, beacon.rcpi, beacon.rsni);

    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "BSSID", beacon.bssid);
    ret_val &=
        m_ambiorix_datamodel->set(measurement_inst, "MeasurementToken", beacon.measurement_token);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "RCPI", beacon.rcpi);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "RSNI", beacon.rsni);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "Channel", beacon.channel);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "OpClass", beacon.op_class);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "DialogToken", beacon.dialog_token);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "RepMode", beacon.rep_mode);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "PhyType", beacon.phy_type);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "AntId", beacon.ant_id);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "Duration", beacon.duration);
    ret_val &= m_ambiorix_datamodel->set(measurement_inst, "StartTime", beacon.start_time);
    return ret_val;
}

bool db::add_radio(const sMacAddr &mac, const sMacAddr &parent_mac)
{
    auto agent = m_agents.get(parent_mac);
    if (!agent) {
        LOG(ERROR) << "While adding radio " << mac << " parent agent " << parent_mac
                   << " not found.";
        return false;
    }

    auto radio = agent->radios.add(mac);

    return dm_add_radio_element(*radio, *agent);
}

std::shared_ptr<Station> db::add_station(const sMacAddr &al_mac, const sMacAddr &mac,
                                         const sMacAddr &parent_mac)
{
    if (mac == network_utils::ZERO_MAC) {
        LOG(ERROR) << "mac supplied for add_station is zero_mac";
        return {};
    }
    auto station = m_stations.add(mac);
    auto bss     = get_bss(parent_mac, al_mac);
    LOG(DEBUG) << "Adding Station node "
               << " for AL-MAC " << al_mac << " station mac " << mac
               << " parent mac: " << parent_mac;

    if (!bss) {
        LOG(ERROR) << "Failed to get sBss: " << parent_mac;
    } else {
        LOG(DEBUG) << "Setting the BSS of station " << mac << " to " << bss->dm_path;
        set_station_bss(station, bss);
    }

    if (parent_mac == network_utils::ZERO_MAC && config.persistent_db) {
        LOG(DEBUG) << "Skip data model insertion for not-yet-connected persistent clients";
        return station;
    }
    station->parent_mac = tlvf::mac_to_string(parent_mac);

    // Add STA to the controller data model via m_ambiorix_datamodel
    // for connected station (WiFi client)
    if (!dm_add_sta_element(al_mac, parent_mac, *station)) {
        LOG(ERROR) << "Failed to add station datamodel, mac: " << station->mac;
    }

    return station;
}

void db::set_station_bss(std::shared_ptr<Station> station, std::shared_ptr<Agent::sRadio::sBss> bss)
{
    if (!station || !bss) {
        LOG(ERROR) << "Invalid station or bss";
        return;
    }
    std::shared_ptr<Agent::sRadio::sBss> old_parent = station->get_bss();
    if (old_parent) {
        old_parent->connected_stations.erase(station->mac);
    }
    station->set_bss(bss);
    bss->connected_stations.add(station);
}

bool db::remove_sta(const sMacAddr &mac)
{
    m_stations.erase(mac);
    return true;
}

bool db::set_agent_ipv4(const std::string &al_mac, const std::string &ipv4)
{
    std::shared_ptr<Agent> agent = get_agent(tlvf::mac_from_string(al_mac));
    if (!agent) {
        return false;
    }
    agent->ipv4 = ipv4;
    return true;
}

bool db::set_sta_ipv4(const std::string &mac, const std::string &ipv4)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    pSta->ipv4 = ipv4;
    return true;
}

std::string db::get_sta_ipv4(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return std::string();
    }
    return pSta->ipv4;
}

bool db::set_agent_manufacturer(prplmesh::controller::db::Agent &agent,
                                const std::string &manufacturer)
{
    agent.device_info.manufacturer = manufacturer;
    return true;
}

int db::get_radio_operating_class(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << "radio " << mac << " does not exist!";
        return 0;
    }
    return radio->operating_class;
}

bool db::set_sta_vap_id(const std::string &mac, int8_t vap_id)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    pSta->vap_id = vap_id;
    return true;
}

int8_t db::get_sta_vap_id(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        return beerocks::IFACE_ID_INVALID;
    }
    return pSta->vap_id;
}

bool db::set_global_restricted_channels(const uint8_t *restricted_channels)
{
    if (!restricted_channels) {
        return false;
    }
    global_restricted_channels.clear();
    std::copy(restricted_channels, restricted_channels + message::RESTRICTED_CHANNEL_LENGTH,
              std::back_inserter(global_restricted_channels));
    return true;
}

std::vector<uint8_t> db::get_global_restricted_channels() { return global_restricted_channels; }

bool db::set_radio_conf_restricted_channels(const sMacAddr &ruid,
                                            const uint8_t *restricted_channels)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(ruid);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << ruid << " does not exist!";
        return false;
    } else if (!restricted_channels) {
        LOG(WARNING) << __FUNCTION__ << "radio " << ruid << " restricted_channels not valid";
        return false;
    }
    radio->conf_restricted_channels.clear();
    std::copy(restricted_channels, restricted_channels + message::RESTRICTED_CHANNEL_LENGTH,
              std::back_inserter(radio->conf_restricted_channels));
    for (auto elm : radio->conf_restricted_channels) {
        LOG(WARNING) << __FUNCTION__ << " elm = " << int(elm);
    }
    return true;
}

std::vector<uint8_t> db::get_radio_conf_restricted_channels(const sMacAddr &ruid)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(ruid);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << ruid << " does not exist!";
        return std::vector<uint8_t>();
    }
    return radio->conf_restricted_channels;
}

bool db::set_radio_channel_scan_capabilites(
    Agent::sRadio &radio, wfa_map::cRadiosWithScanCapabilities &radio_capabilities)
{
    radio.scan_capabilities.on_boot_only          = radio_capabilities.capabilities().on_boot_only;
    radio.scan_capabilities.scan_impact           = radio_capabilities.capabilities().scan_impact;
    radio.scan_capabilities.minimum_scan_interval = radio_capabilities.minimum_scan_interval();

    std::stringstream ss;
    ss << "on_boot_only=" << std::hex << int(radio.scan_capabilities.on_boot_only) << std::endl
       << "scan_impact=" << std::oct << int(radio.scan_capabilities.scan_impact) << std::endl
       << "minimum_scan_interval=" << int(radio.scan_capabilities.minimum_scan_interval)
       << std::endl;

    auto operating_classes_list_length = radio_capabilities.operating_classes_list_length();

    for (uint8_t oc_idx = 0; oc_idx < operating_classes_list_length; oc_idx++) {
        auto operating_class_tuple = radio_capabilities.operating_classes_list(oc_idx);
        if (!std::get<0>(operating_class_tuple)) {
            LOG(ERROR) << "getting operating class entry has failed!";
            return false;
        }

        auto &operating_class_struct = std::get<1>(operating_class_tuple);
        auto operating_class         = operating_class_struct.operating_class();
        const auto &op_class_chan_set =
            wireless_utils::operating_class_to_channel_set(operating_class);
        ss << "operating class=" << int(operating_class);

        auto channel_list_length = operating_class_struct.channel_list_length();

        ss << ", channel_list={";
        if (channel_list_length == 0) {
            ss << "}";
        }

        auto &operating_classes = radio.scan_capabilities.operating_classes;
        operating_classes.clear();
        for (int ch_idx = 0; ch_idx < channel_list_length; ch_idx++) {
            auto channel = operating_class_struct.channel_list(ch_idx);
            if (!channel) {
                LOG(ERROR) << "getting channel entry has failed!";
                return false;
            }

            // Check if channel is valid for operating class
            if (op_class_chan_set.find(*channel) == op_class_chan_set.end()) {
                LOG(ERROR) << "Channel " << int(*channel) << " invalid for operating class "
                           << int(operating_class);
                return false;
            }

            ss << int(*channel);

            // add comma if not last channel in the list, else close list by add curl brackets
            ss << (((ch_idx + 1) != channel_list_length) ? "," : "}");

            operating_classes[operating_class].push_back(*channel);
        }
    }
    ss << std::endl;
    LOG(DEBUG) << ss.str();
    return true;
}

bool db::set_sta_beacon_measurement_support_level(
    const std::string &mac, beerocks::eBeaconMeasurementSupportLevel support_beacon_measurement)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        return false;
    }
    if (!pSta->supports_beacon_measurement) { // sticky
        pSta->supports_beacon_measurement = support_beacon_measurement;
    }
    return true;
}

beerocks::eBeaconMeasurementSupportLevel
db::get_sta_beacon_measurement_support_level(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        return beerocks::BEACON_MEAS_UNSUPPORTED;
    }
    return pSta->supports_beacon_measurement;
}

bool db::set_agent_name(const std::string &al_mac, const std::string &name)
{
    std::shared_ptr<Agent> agent = get_agent(tlvf::mac_from_string(al_mac));
    if (!agent) {
        return false;
    }
    agent->name = name;
    return true;
}

bool db::set_sta_name(const std::string &mac, const std::string &name)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - sta " << mac << " does not exist!";
        return false;
    }
    pSta->name = name;
    return true;
}

bool db::set_eth_switch_name(const sMacAddr &mac, const std::string &name)
{
    std::shared_ptr<Agent::sEthSwitch> eth_switch = get_eth_switch(mac);
    if (!eth_switch) {
        LOG(WARNING) << __FUNCTION__ << " - eth_switch " << mac << " does not exist!";
        return false;
    }
    eth_switch->name = name;
    return true;
}

bool db::set_agent_state(const std::string &al_mac, beerocks::eNodeState state)
{
    std::shared_ptr<Agent> agent = get_agent(tlvf::mac_from_string(al_mac));
    if (!agent) {
        LOG(WARNING) << __FUNCTION__ << " - agent " << al_mac << " does not exist!";
        return false;
    }
    agent->state             = state;
    agent->last_state_change = std::chrono::steady_clock::now();
    return true;
}

bool db::set_radio_state(const std::string &ruid, beerocks::eNodeState state)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(ruid));
    if (!radio) {
        LOG(ERROR) << __FUNCTION__ << " - radio " << ruid << "does not exist!";
        return false;
    }
    radio->state             = state;
    radio->last_state_change = std::chrono::steady_clock::now();
    return true;
}

bool db::set_eth_switch_state(const std::string &mac, beerocks::eNodeState state)
{
    std::shared_ptr<Agent::sEthSwitch> eth_switch = get_eth_switch(tlvf::mac_from_string(mac));
    if (!eth_switch) {
        LOG(ERROR) << __FUNCTION__ << " - eth_switch " << mac << "does not exist!";
        return false;
    }
    eth_switch->state = state;
    return true;
}

beerocks::eNodeState db::get_agent_state(const sMacAddr &mac)
{
    std::shared_ptr<Agent> agent = get_agent(mac);
    if (!agent) {
        LOG(WARNING) << __FUNCTION__ << " - agent " << mac << " does not exist!";
        return beerocks::STATE_MAX;
    }
    return agent->state;
}

beerocks::eNodeState db::get_radio_state(const sMacAddr &ruid)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(ruid);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << ruid << " does not exist!";
        return beerocks::STATE_MAX;
    }
    return radio->state;
}

bool db::set_sta_state(const std::string &mac, beerocks::eNodeState state)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    pSta->state = state;
    return true;
}

beerocks::eNodeState db::get_sta_state(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return beerocks::STATE_MAX;
    }
    return pSta->state;
}

bool db::set_sta_handoff_flag(Station &station, bool handoff)
{
    std::shared_ptr<Station> pSta = get_station(station.mac);
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << station.mac << " does not exist!";
        return false;
    }
    pSta->m_handoff = handoff;
    return true;
}

bool db::get_sta_handoff_flag(const Station &station)
{
    std::shared_ptr<Station> pSta = get_station(station.mac);
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << station.mac << " does not exist!";
        return false;
    }
    return pSta->m_handoff;
}

bool db::update_radio_last_seen(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }
    radio->last_seen = std::chrono::steady_clock::now();
    return true;
}

bool db::update_sta_last_seen(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    pSta->last_seen = std::chrono::steady_clock::now();
    return true;
}

std::chrono::steady_clock::time_point db::get_radio_last_seen(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return std::chrono::steady_clock::now();
    }

    return radio->last_seen;
}

std::chrono::steady_clock::time_point db::get_sta_last_seen(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return std::chrono::steady_clock::time_point::min();
    }
    return pSta->last_seen;
}

std::unordered_map<sMacAddr, std::unordered_map<sMacAddr, son::db::link_metrics_data>> &
db::get_link_metric_data_map()
{
    return m_link_metric_data;
}

std::unordered_map<sMacAddr, son::db::ap_metrics_data> &db::get_ap_metric_data_map()
{
    return m_ap_metric_data;
}

std::unordered_map<std::string, son::db::sUnAssocStaInfo> &db::get_unassoc_sta_map()
{
    return m_unassoc_sta_map;
}

bool db::set_radio_active(const sMacAddr &mac, const bool active)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << "radio " << mac << " not found";
        return false;
    }

    LOG(DEBUG) << "Setting radio '" << mac << "' as " << (active ? "active" : "inactive");
    radio->active = active;

    // Enabled variable is a part of Radio data element and
    // need to get path like Device.WiFi.DataElements.Device.{i}.Radio.{i}. for setting Enabled variable
    auto radio_enable_path = radio->dm_path;

    if (radio_enable_path.empty()) {
        return true;
    }

    if (!m_ambiorix_datamodel->set(radio_enable_path, "Enabled", active)) {
        LOG(ERROR) << "Failed to set " << radio_enable_path << "Enabled: " << active;
        return false;
    }

    return true;
}

bool db::is_radio_active(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }
    return radio->active;
}

bool db::is_ap_out_of_band(const std::string &mac, const std::string &sta_mac)
{
    auto sta_wifi_channel = get_sta_wifi_channel(sta_mac);
    if (sta_wifi_channel.is_empty()) {
        LOG(ERROR) << "empty wifi channel of " << sta_mac << " in DB";
        return false;
    }
    bool client_on_5ghz = (sta_wifi_channel.get_freq_type() == eFreqType::FREQ_5G);

    auto wifi_channel = get_radio_wifi_channel(tlvf::mac_from_string(mac));
    if (wifi_channel.is_empty()) {
        LOG(ERROR) << "empty wifi channel of " << mac << " in DB";
        return false;
    }

    if (((wifi_channel.get_freq_type() == eFreqType::FREQ_24G) && client_on_5ghz) ||
        ((wifi_channel.get_freq_type() == eFreqType::FREQ_5G) && (!client_on_5ghz))) {
        return true;
    }
    return false;
}

bool db::is_sta_wireless(const std::string &mac)
{
    std::shared_ptr<Station> station = get_station(tlvf::mac_from_string(mac));
    if (!station) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    return utils::is_device_wireless(station->iface_type);
}

std::string db::obj_to_string(const sMacAddr &mac)
{
    std::ostringstream os;
    std::shared_ptr<Agent> agent = get_agent(mac);
    if (agent) {
        os << agent;
    } else {
        std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
        if (radio) {
            os << radio;
        } else {
            std::shared_ptr<Agent::sRadio::sBss> bss = get_bss(mac);
            if (bss) {
                os << bss;
            } else {
                std::shared_ptr<Station> station = get_station(mac);
                if (station) {
                    os << station;
                } else {
                    os << "";
                }
            }
        }
    }
    return os.str();
}
//
// DB node functions (get only)
//
std::set<std::string> db::get_stations()
{
    std::set<std::string> ret;

    for (const auto &station : m_stations) {
        ret.insert(tlvf::mac_to_string(station.first));
    }
    return ret;
}

std::set<std::string> db::get_active_radios()
{
    std::set<std::string> ret;
    for (const auto &agent : m_agents) {
        for (const auto &radio : agent.second->radios) {
            if (get_radio_state(radio.first) == beerocks::STATE_CONNECTED &&
                is_radio_active(radio.first)) {
                ret.insert(tlvf::mac_to_string(radio.first));
            }
        }
    }
    return ret;
}

std::vector<std::shared_ptr<Agent>> db::get_all_connected_agents()
{
    std::vector<std::shared_ptr<Agent>> ret;

    for (const auto &agent_map_element : m_agents) {
        auto &agent = agent_map_element.second;
        if (agent->state == beerocks::STATE_CONNECTED) {
            ret.push_back(agent);
        }
    }
    return ret;
}

std::set<std::string> db::get_backhauls_from_hierarchy(int hierarchy)
{
    std::set<std::string> result;

    if (hierarchy < 0 || hierarchy >= HIERARCHY_MAX) {
        LOG(ERROR) << "invalid hierarchy";
        return result;
    }

    for (const auto &agent : m_agents) {
        if (get_agent_hierarchy(agent.first) == hierarchy) {
            result.insert(tlvf::mac_to_string(agent.second->parent_mac));
        }
    }

    return result;
}

std::shared_ptr<Agent> db::get_gw()
{
    for (const auto &agent : m_agents) {
        if (agent.second->is_gateway) {
            return agent.second;
        }
    }

    LOG(ERROR) << "Gateway not found";
    return {};
}

std::unordered_set<sMacAddr> db::get_agent_children(const sMacAddr &al_mac)
{
    // iterate recursively over agents checking their parent
    std::unordered_set<sMacAddr> children;
    for (const auto &agent : m_agents) {
        std::shared_ptr<Agent> parent_agent = agent.second->backhaul.parent_agent.lock();
        if (parent_agent && parent_agent->al_mac == al_mac) {
            children.insert(agent.first);
            std::unordered_set<sMacAddr> children_set = get_agent_children(agent.first);
            children.insert(children_set.begin(), children_set.end());
        }
    }

    return children;
}

// returns vap mac to which the client is connected
std::string db::get_sta_parent(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << "station " << mac << "does not exist!";
        return std::string();
    }
    return pSta->parent_mac;
}

sMacAddr db::get_radio_parent_agent(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent> agent = get_agent_by_radio_uid(radio_mac);
    if (!agent) {
        LOG(ERROR) << "No Agent found hosting radio " << radio_mac;
        return network_utils::ZERO_MAC;
    }

    return agent->al_mac;
}

sMacAddr db::get_bss_parent_agent(const sMacAddr &bssid)
{
    std::shared_ptr<Agent::sRadio::sBss> bss = get_bss(bssid);
    if (!bss) {
        LOG(ERROR) << "No BSS found with BSSID " << bssid;
        return network_utils::ZERO_MAC;
    }

    return get_radio_parent_agent(bss->radio.radio_uid);
}

sMacAddr db::get_agent_parent(const sMacAddr &al_mac)
{
    std::shared_ptr<Agent> agent = get_agent(al_mac);
    if (!agent) {
        LOG(ERROR) << "No Agent found with ALID " << al_mac;
        return network_utils::ZERO_MAC;
    }

    return agent->parent_mac;
}

sMacAddr db::get_eth_switch_parent_agent(const sMacAddr &mac)
{
    for (const auto &agent : m_agents) {
        if (agent.second->eth_switches.get(mac)) {
            return agent.first;
        }
    }

    return network_utils::ZERO_MAC;
}

std::set<std::string> db::get_radio_siblings(const sMacAddr &ruid)
{
    std::set<std::string> siblings;
    std::shared_ptr<Agent> parent_agent = get_agent_by_radio_uid(ruid);
    if (!parent_agent) {
        LOG(ERROR) << "No parent agent found for RUID " << ruid;
        return siblings;
    }

    for (const auto &radio : parent_agent->radios) {
        if (radio.first == ruid) {
            continue;
        }
        siblings.insert(tlvf::mac_to_string(radio.first));
    }

    return siblings;
}

std::set<std::string> db::get_stations_on_radio(const sMacAddr &ruid, int state)
{
    std::set<std::string> stations_mac;
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(ruid);
    if (!radio) {
        LOG(ERROR) << "No radio found with RUID " << ruid;
        return stations_mac;
    }
    for (const auto &bss : radio->bsses) {
        for (const auto &station : bss.second->connected_stations) {
            if (state != STATE_CONNECTED || station.second->state == STATE_CONNECTED) {
                stations_mac.insert(tlvf::mac_to_string(station.first));
            }
        }
    }
    return stations_mac;
}

std::list<sMacAddr> db::get_1905_1_neighbors(const sMacAddr &al_mac)
{
    std::list<sMacAddr> neighbors_al_macs;

    // According to IEEE 1905.1 a neighbor is defined as a first circle only, so we need to filter
    // out the childrens from second circle and above.
    for (const auto &agent : m_agents) {
        if (get_agent_parent(agent.first) == al_mac) {
            neighbors_al_macs.push_back(agent.first);
        }
    }

    // Add the parent bridge as well to the neighbors list
    auto parent_bridge = get_agent_parent(al_mac);
    if (parent_bridge != network_utils::ZERO_MAC) {
        neighbors_al_macs.push_back(parent_bridge);
    }

    return neighbors_al_macs;
}

//
// Capabilities
//

bool db::set_ap_vht_capabilities(wfa_map::tlvApVhtCapabilities &vht_caps_tlv)
{
    auto radio = get_radio_by_uid(vht_caps_tlv.radio_uid());
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with mac: " << vht_caps_tlv.radio_uid();
        return false;
    }

    auto path_to_obj = radio->dm_path;
    if (path_to_obj.empty()) {
        return true;
    }

    path_to_obj += ".Capabilities.";
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "VHTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object" << path_to_obj << "VHTCapabilities";
        return false;
    }

    bool ret_val = true;
    path_to_obj += "VHTCapabilities.";

    auto flags1 = vht_caps_tlv.flags1();
    auto flags2 = vht_caps_tlv.flags2();

    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "MCSNSSTxSet", vht_caps_tlv.supported_vht_tx_mcs());
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "MCSNSSRxSet", vht_caps_tlv.supported_vht_rx_mcs());

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams",
                                         flags1.max_num_of_supported_tx_spatial_streams + 1);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams",
                                         flags1.max_num_of_supported_rx_spatial_streams + 1);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "VHTShortGI80",
                                         static_cast<bool>(flags1.short_gi_support_80mhz));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "VHTShortGI160",
                                  static_cast<bool>(flags1.short_gi_support_160mhz_and_80_80mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "VHT8080",
                                         static_cast<bool>(flags2.vht_support_80_80mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "VHT160",
                                         static_cast<bool>(flags2.vht_support_160mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformer",
                                         static_cast<bool>(flags2.su_beamformer_capable));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUBeamformer",
                                         static_cast<bool>(flags2.mu_beamformer_capable));

    return ret_val;
}

bool db::dm_add_ap_operating_classes(const std::string &radio_mac, uint8_t max_tx_power,
                                     uint8_t op_class,
                                     const std::vector<uint8_t> &non_operable_channels)
{
    auto radio        = get_radio_by_uid(tlvf::mac_from_string(radio_mac));
    bool return_value = true;

    if (!radio) {
        LOG(ERROR) << "Failed to get radio with mac: " << radio_mac;
        return false;
    }

    std::string path_to_obj = radio->dm_path;
    if (path_to_obj.empty()) {
        return true;
    }

    path_to_obj += ".Capabilities.OperatingClasses";
    std::string path_to_obj_instance = m_ambiorix_datamodel->add_instance(path_to_obj);
    if (path_to_obj_instance.empty()) {
        LOG(ERROR) << "Failed to add object: " << path_to_obj;
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_obj_instance, "MaxTxPower", max_tx_power)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << " MaxTxPower: " << max_tx_power;
        return_value = false;
    }

    if (!m_ambiorix_datamodel->set(path_to_obj_instance, "Class", op_class)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << " Class: " << op_class;
        return_value = false;
    }

    path_to_obj = path_to_obj_instance + ".NonOperable";
    for (auto non_op_channel : non_operable_channels) {
        auto path_to_non_operable_instance = m_ambiorix_datamodel->add_instance(path_to_obj);
        if (path_to_non_operable_instance.empty()) {
            LOG(ERROR) << "Failed to add object: " << path_to_obj;
            return_value = false;
            continue;
        }
        if (!m_ambiorix_datamodel->set(path_to_non_operable_instance, "NonOpChannelNumber",
                                       non_op_channel)) {
            LOG(ERROR) << "Failed to set " << path_to_non_operable_instance
                       << "NonOpChannelNumber: " << non_op_channel;
            return_value = false;
        }
    }

    return return_value;
}

bool db::set_ap_he_capabilities(wfa_map::tlvApHeCapabilities &he_caps_tlv)
{
    auto radio = get_radio_by_uid(he_caps_tlv.radio_uid());

    if (!radio) {
        LOG(ERROR) << "Fail get radio, mac:" << he_caps_tlv.radio_uid();
        return false;
    }

    auto path_to_obj = radio->dm_path;
    if (path_to_obj.empty()) {
        return true;
    }

    path_to_obj += ".Capabilities.";
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "WiFi6Capabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_obj << "WiFi6Capabilities";
        return false;
    }

    bool ret_val = true;
    path_to_obj += "WiFi6Capabilities.";

    auto flags1 = he_caps_tlv.flags1();
    auto flags2 = he_caps_tlv.flags2();

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams",
                                         flags1.max_num_of_supported_tx_spatial_streams + 1);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams",
                                         flags1.max_num_of_supported_rx_spatial_streams + 1);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE8080",
                                         static_cast<bool>(flags1.he_support_80_80mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE160",
                                         static_cast<bool>(flags1.he_support_160mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformer",
                                         static_cast<bool>(flags2.su_beamformer_capable));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUBeamformer",
                                         static_cast<bool>(flags2.mu_beamformer_capable));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "ULMUMIMO",
                                         static_cast<bool>(flags2.ul_mu_mimo_capable));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "ULOFDMA",
                                         static_cast<bool>(flags2.ul_ofdm_capable));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "DLOFDMA",
                                         static_cast<bool>(flags2.dl_ofdm_capable));

    uint8_t supported_he_mcs_length = he_caps_tlv.supported_he_mcs_length();
    path_to_obj += "MCSNSS";
    for (int i = 0; i < supported_he_mcs_length; i++) {
        auto path_to_obj_instance = m_ambiorix_datamodel->add_instance(path_to_obj);
        if (path_to_obj_instance.empty()) {
            LOG(ERROR) << "Failed to add " << path_to_obj;
            ret_val = false;
            continue;
        }
        ret_val &= m_ambiorix_datamodel->set(path_to_obj_instance + '.', "MCSNSSSet",
                                             *he_caps_tlv.supported_he_mcs(i));
    }

    return ret_val;
}

bool db::set_software_version(std::shared_ptr<Agent> agent, const std::string &sw_version)
{
    if (!agent) {
        LOG(ERROR) << "Invalid agent pointer provided";
        return false;
    }

    if (agent->dm_path.empty()) {
        return true;
    }

    if (!m_ambiorix_datamodel->set(agent->dm_path, "SoftwareVersion", sw_version)) {
        LOG(ERROR) << "Failed to set " << agent->dm_path << ".SoftwareVersion: " << sw_version;
        return false;
    }

    return true;
}

const beerocks::message::sRadioCapabilities *
db::get_sta_current_capabilities(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        return nullptr;
    }
    return (pSta->capabilities);
}

bool db::dm_set_sta_he_capabilities(const std::string &path_to_sta,
                                    const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_sta, "WiFi6Capabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_sta << "WiFi6Capabilities";
        return false;
    }

    bool ret_val            = true;
    std::string path_to_obj = path_to_sta + "WiFi6Capabilities.";

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams", sta_cap.he_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams", sta_cap.he_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE8080",
                                         static_cast<bool>(sta_cap.he_bw == BANDWIDTH_80_80));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE160",
                                         static_cast<bool>(sta_cap.he_bw == BANDWIDTH_160));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformer",
                                         static_cast<bool>(sta_cap.he_su_beamformer));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformee",
                                         static_cast<bool>(sta_cap.he_su_beamformee));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUBeamformer",
                                         static_cast<bool>(sta_cap.he_mu_beamformer));
    ret_val &= m_ambiorix_datamodel->set(
        path_to_obj, "Beamformee80orLess",
        static_cast<bool>(sta_cap.he_su_beamformee ? sta_cap.he_beamformee_sts_less_80mhz : false));
    ret_val &= m_ambiorix_datamodel->set(
        path_to_obj, "BeamformeeAbove80",
        static_cast<bool>(sta_cap.he_su_beamformee && (sta_cap.he_bw > BANDWIDTH_80)
                              ? sta_cap.he_beamformee_sts_great_80mhz
                              : false));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "ULMUMIMO", static_cast<bool>(sta_cap.ul_mu_mimo));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "ULOFDMA", static_cast<bool>(sta_cap.ul_ofdma));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "DLOFDMA", static_cast<bool>(sta_cap.dl_ofdma));
    // TODO: find the values for the unfilled parameters, PPM-2112
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxDLMUMIMO", sta_cap.dl_mu_mimo_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxULMUMIMO", sta_cap.ul_mu_mimo_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxDLOFDMA", sta_cap.dl_ofdma_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxULOFDMA", sta_cap.ul_ofdma_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "RTS", static_cast<bool>(false));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MURTS", static_cast<bool>(sta_cap.ul_ofdma));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MultiBSSID", static_cast<bool>(false));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUEDCA", static_cast<bool>(false));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "TWTRequestor",
                                         static_cast<bool>(sta_cap.twt_requester));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "TWTResponder",
                                         static_cast<bool>(sta_cap.twt_responder));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SpatialReuse", static_cast<bool>(false));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "AnticipatedChannelUsage", static_cast<bool>(false));

    return ret_val;
}

bool db::set_ap_wifi6_capabilities(wfa_map::tlvApWifi6Capabilities &wifi6_caps_tlv)
{
    auto radio = get_radio_by_uid(wifi6_caps_tlv.radio_uid());
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with RUID: " << wifi6_caps_tlv.radio_uid();
        return false;
    }

    if (radio->dm_path.empty()) {
        return true;
    }

    auto path_to_obj = radio->dm_path + ".Capabilities.";
    bool ret_val     = true;

    for (auto iter1 = 0; iter1 < wifi6_caps_tlv.number_of_roles(); iter1++) {
        auto role_tuple = wifi6_caps_tlv.role(iter1);
        if (!std::get<0>(role_tuple)) {
            LOG(ERROR) << "role entry has failed!";
            return false;
        }

        auto &role  = std::get<1>(role_tuple);
        auto flags1 = role.flags1();
        auto flags2 = role.flags2();
        auto flags3 = role.flags3();
        auto flags4 = role.flags4();

        // First bit represents agent role, second bit is reserved according to R3.
        uint8_t agent_role_first_bit = flags1.agent_role & 0x01;

        if (agent_role_first_bit == 0x0) {
            if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "WiFi6APRole")) {
                LOG(ERROR) << "Failed to add sub-object " << path_to_obj << "WiFi6APRole";
                return false;
            }
            path_to_obj += "WiFi6APRole.";
        } else {
            if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "WiFi6bSTARole")) {
                LOG(ERROR) << "Failed to add sub-object " << path_to_obj << "WiFi6bSTARole";
                return false;
            }
            path_to_obj += "WiFi6bSTARole.";
        }

        //TODO: Need to set the value for MCS_NSS and OFDMA (PPM-2288)
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "AgentRole", flags1.agent_role);
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE160",
                                             static_cast<bool>(flags1.he_support_160mhz));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE8080",
                                             static_cast<bool>(flags1.he_support_80_80mhz));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MCSNSSLength", flags1.mcs_nss_length);
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformer",
                                             static_cast<bool>(flags2.su_beamformer));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformee",
                                             static_cast<bool>(flags2.su_beamformee));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUBeamformer",
                                             static_cast<bool>(flags2.mu_Beamformer_status));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "BeamformeeStsLess80",
                                             static_cast<bool>(flags2.beamformee_sts_less_80mhz));
        ret_val &=
            m_ambiorix_datamodel->set(path_to_obj, "BeamformeeStsGreater80",
                                      static_cast<bool>(flags2.beamformee_sts_greater_80mhz));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "ULMUMIMO",
                                             static_cast<bool>(flags2.ul_mu_mimo));
        ret_val &=
            m_ambiorix_datamodel->set(path_to_obj, "ULOFDMA", static_cast<bool>(flags2.ul_ofdma));
        ret_val &=
            m_ambiorix_datamodel->set(path_to_obj, "DLOFDMA", static_cast<bool>(flags2.dl_ofdma));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfUsersSupportedTX",
                                             flags3.max_dl_mu_mimo_tx);
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfUsersSupportedRX",
                                             flags3.max_ul_mu_mimo_rx);
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "RTS", static_cast<bool>(flags4.rts));
        ret_val &=
            m_ambiorix_datamodel->set(path_to_obj, "MURTS", static_cast<bool>(flags4.mu_rts));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MULTIBSSID",
                                             static_cast<bool>(flags4.multi_bssid));
        ret_val &=
            m_ambiorix_datamodel->set(path_to_obj, "MUEDCA", static_cast<bool>(flags4.mu_edca));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "TwtRequester",
                                             static_cast<bool>(flags4.twt_requester));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "TwtResponder",
                                             static_cast<bool>(flags4.twt_responder));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SpatialReuse",
                                             static_cast<bool>(flags4.spatial_reuse));
        ret_val &= m_ambiorix_datamodel->set(path_to_obj, "AnticipatedChannelUsage",
                                             static_cast<bool>(flags4.anticipated_channel_usage));
    }
    return ret_val;
}

bool db::dm_set_sta_ht_capabilities(const std::string &path_to_sta,
                                    const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_sta, "HTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_sta << "HTCapabilities";
        return false;
    }

    bool ret_val            = true;
    std::string path_to_obj = path_to_sta + "HTCapabilities.";

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HTShortGI20",
                                         static_cast<bool>(sta_cap.ht_low_bw_short_gi));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HTShortGI40",
                                         static_cast<bool>(sta_cap.ht_high_bw_short_gi));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "HT40", (sta_cap.ht_bw == beerocks::BANDWIDTH_40));
    // TODO: find value for tx_spatial_streams PPM-792.
    // Parse the (Re)Association Request frame.
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams", sta_cap.ht_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams", sta_cap.ht_ss);

    return ret_val;
}

bool db::dm_set_sta_vht_capabilities(const std::string &path_to_sta,
                                     const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_sta, "VHTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_sta << "VHTCapabilities";
        return false;
    }

    bool ret_val            = true;
    std::string path_to_obj = path_to_sta + "VHTCapabilities.";

    auto vht_mcs_set = son::wireless_utils::get_vht_mcs_set(sta_cap.vht_mcs, sta_cap.vht_ss);

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MCSNSSTxSet", vht_mcs_set);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MCSNSSRxSet", vht_mcs_set);
    // TODO: find value for tx_spatial_streams PPM-792.
    // Parse the (Re)Association Request frame.
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams", sta_cap.vht_ss);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams", sta_cap.vht_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "VHTShortGI80",
                                         static_cast<bool>(sta_cap.vht_low_bw_short_gi));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "VHTShortGI160",
                                         static_cast<bool>(sta_cap.vht_high_bw_short_gi));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "VHT8080", (BANDWIDTH_80_80 <= sta_cap.vht_bw));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "VHT160", (BANDWIDTH_160 <= sta_cap.vht_bw));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformer",
                                         static_cast<bool>(sta_cap.vht_su_beamformer));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUBeamformer",
                                         static_cast<bool>(sta_cap.vht_mu_beamformer));

    return ret_val;
}

bool db::dm_add_assoc_event_sta_caps(const std::string &assoc_event_path,
                                     const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (assoc_event_path.empty()) {
        return true;
    }

    std::string path_to_event = assoc_event_path + '.';

    // Remove previous entry
    m_ambiorix_datamodel->remove_optional_subobject(path_to_event, "HTCapabilities");
    m_ambiorix_datamodel->remove_optional_subobject(path_to_event, "VHTCapabilities");
    m_ambiorix_datamodel->remove_optional_subobject(path_to_event, "WiFi6Capabilities");

    if (sta_cap.ht_bw != beerocks::BANDWIDTH_UNKNOWN) {
        dm_set_assoc_event_sta_ht_cap(path_to_event, sta_cap);
    }
    if (sta_cap.vht_bw != beerocks::BANDWIDTH_UNKNOWN) {
        dm_set_assoc_event_sta_vht_cap(path_to_event, sta_cap);
    }
    if (sta_cap.he_bw != beerocks::BANDWIDTH_UNKNOWN) {
        dm_set_assoc_event_sta_he_cap(path_to_event, sta_cap);
    }
    return true;
}

bool db::dm_set_assoc_event_sta_ht_cap(const std::string &path_to_event,
                                       const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_event, "HTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_event << "HTCapabilities";
        return false;
    }

    bool ret_val               = true;
    std::string path_to_ht_cap = path_to_event + "HTCapabilities.";

    ret_val &=
        m_ambiorix_datamodel->set(path_to_ht_cap, "MaxNumberOfTxSpatialStreams", sta_cap.ht_ss);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_ht_cap, "MaxNumberOfRxSpatialStreams", sta_cap.ht_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "HTShortGI20",
                                         static_cast<bool>(sta_cap.ht_low_bw_short_gi));
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "HTShortGI40",
                                         static_cast<bool>(sta_cap.ht_high_bw_short_gi));
    // Set to 1 if both 20 MHz and 40 MHz operation is supported
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "HT40",
                                         (sta_cap.ht_bw == beerocks::BANDWIDTH_40));

    return ret_val;
}

bool db::dm_set_assoc_event_sta_vht_cap(const std::string &path_to_event,
                                        const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_event, "VHTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_event << "VHTCapabilities";
        return false;
    }

    bool ret_val               = true;
    std::string path_to_ht_cap = path_to_event + "VHTCapabilities.";

    auto vht_mcs_set = son::wireless_utils::get_vht_mcs_set(sta_cap.vht_mcs, sta_cap.vht_ss);

    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "MCSNSSTxSet", vht_mcs_set);
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "MCSNSSRxSet", vht_mcs_set);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_ht_cap, "MaxNumberOfTxSpatialStreams", sta_cap.vht_ss);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_ht_cap, "MaxNumberOfRxSpatialStreams", sta_cap.vht_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "VHTShortGI80",
                                         static_cast<bool>(sta_cap.vht_low_bw_short_gi));
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "VHTShortGI160",
                                         static_cast<bool>(sta_cap.vht_high_bw_short_gi));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_ht_cap, "VHT8080", (BANDWIDTH_80_80 <= sta_cap.vht_bw));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_ht_cap, "VHT160", (BANDWIDTH_160 <= sta_cap.vht_bw));
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "SUBeamformer",
                                         static_cast<bool>(sta_cap.vht_su_beamformer));
    ret_val &= m_ambiorix_datamodel->set(path_to_ht_cap, "MUBeamformer",
                                         static_cast<bool>(sta_cap.vht_mu_beamformer));

    return ret_val;
}

bool db::dm_set_assoc_event_sta_he_cap(const std::string &path_to_event,
                                       const beerocks::message::sRadioCapabilities &sta_cap)
{
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_event, "WiFi6Capabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_event << "WiFi6Capabilities";
        return false;
    }

    bool ret_val            = true;
    std::string path_to_obj = path_to_event + "WiFi6Capabilities.";

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams", sta_cap.he_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams", sta_cap.he_ss);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE8080",
                                         static_cast<bool>(sta_cap.he_bw == BANDWIDTH_80_80));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HE160",
                                         static_cast<bool>(sta_cap.he_bw == BANDWIDTH_160));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformer",
                                         static_cast<bool>(sta_cap.he_su_beamformer));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SUBeamformee",
                                         static_cast<bool>(sta_cap.he_su_beamformee));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUBeamformer",
                                         static_cast<bool>(sta_cap.he_mu_beamformer));
    ret_val &= m_ambiorix_datamodel->set(
        path_to_obj, "Beamformee80orLess",
        static_cast<bool>(sta_cap.he_su_beamformee ? sta_cap.he_beamformee_sts_less_80mhz : false));
    ret_val &= m_ambiorix_datamodel->set(
        path_to_obj, "BeamformeeAbove80",
        static_cast<bool>(sta_cap.he_su_beamformee && (sta_cap.he_bw > BANDWIDTH_80)
                              ? sta_cap.he_beamformee_sts_great_80mhz
                              : false));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "ULMUMIMO", static_cast<bool>(sta_cap.ul_mu_mimo));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "ULOFDMA", static_cast<bool>(sta_cap.ul_ofdma));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "DLOFDMA", static_cast<bool>(sta_cap.dl_ofdma));
    // TODO: find the values for the unfilled parameters, PPM-2112
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxDLMUMIMO", sta_cap.dl_mu_mimo_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxULMUMIMO", sta_cap.ul_mu_mimo_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxDLOFDMA", sta_cap.dl_ofdma_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxULOFDMA", sta_cap.ul_ofdma_max_users);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "RTS", static_cast<bool>(false));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MURTS", static_cast<bool>(sta_cap.ul_ofdma));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MultiBSSID", static_cast<bool>(false));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MUEDCA", static_cast<bool>(false));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "TWTRequestor",
                                         static_cast<bool>(sta_cap.twt_requester));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "TWTResponder",
                                         static_cast<bool>(sta_cap.twt_responder));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "SpatialReuse", static_cast<bool>(false));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "AnticipatedChannelUsage", static_cast<bool>(false));

    return ret_val;
}

bool db::set_sta_capabilities(const std::string &client_mac,
                              const beerocks::message::sRadioCapabilities &sta_cap)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(client_mac));
    if (!pSta) {
        LOG(ERROR) << "station " << client_mac << " not found";
        return false;
    }

    auto parent_radio = get_sta_parent_radio(client_mac);

    if (parent_radio.empty()) {
        LOG(ERROR) << "parent radio node found for client " << client_mac;
        return false;
    }

    if (is_radio_5ghz(tlvf::mac_from_string(parent_radio))) {
        pSta->m_sta_5ghz_capabilities       = sta_cap;
        pSta->m_sta_5ghz_capabilities.valid = true;
        pSta->capabilities                  = &pSta->m_sta_5ghz_capabilities;
    } else if (is_radio_6ghz(tlvf::mac_from_string(parent_radio))) {
        pSta->m_sta_6ghz_capabilities       = sta_cap;
        pSta->m_sta_6ghz_capabilities.valid = true;
        pSta->capabilities                  = &pSta->m_sta_6ghz_capabilities;
    } else {
        pSta->m_sta_24ghz_capabilities       = sta_cap;
        pSta->m_sta_24ghz_capabilities.valid = true;
        pSta->capabilities                   = &pSta->m_sta_24ghz_capabilities;
    }

    // Prepare path to the STA
    // Example: Device.WiFi.DataElements.Network.Device.1.Radio.1.BSS.1.STA.1
    std::string path_to_sta = pSta->dm_path;

    if (path_to_sta.empty()) {
        return true;
    }

    path_to_sta += '.';
    // Remove previous capabilities objects, if they exist
    m_ambiorix_datamodel->remove_optional_subobject(path_to_sta, "HTCapabilities");
    m_ambiorix_datamodel->remove_optional_subobject(path_to_sta, "VHTCapabilities");
    m_ambiorix_datamodel->remove_optional_subobject(path_to_sta, "WiFi6Capabilities");

    if (sta_cap.ht_bw != beerocks::BANDWIDTH_UNKNOWN &&
        !dm_set_sta_ht_capabilities(path_to_sta, sta_cap)) {
        LOG(ERROR) << "Failed to set station HT Capabilities";
        return false;
    }
    if (sta_cap.vht_bw != beerocks::BANDWIDTH_UNKNOWN &&
        !dm_set_sta_vht_capabilities(path_to_sta, sta_cap)) {
        LOG(ERROR) << "Failed to set station VHT Capabilities";
        return false;
    }
    if ((sta_cap.wifi_standard & beerocks::STANDARD_AX) &&
        !dm_set_sta_he_capabilities(path_to_sta, sta_cap)) {
        LOG(ERROR) << "Failed to set station HE Capabilities";
        return false;
    }

    return true;
}

bool db::set_client_capabilities(const sMacAddr &sta_mac, const std::string &frame, db &database)
{
    auto station = database.get_station(sta_mac);
    if (!station) {
        LOG(ERROR) << "station " << sta_mac << " not found";
        return false;
    }

    if (station->dm_path.empty()) {
        return true;
    }

    if (station->assoc_event_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "ClientCapabilities", frame);
    ret_val &= m_ambiorix_datamodel->set(station->assoc_event_path, "ClientCapabilities", frame);

    return ret_val;
}

const beerocks::message::sRadioCapabilities *db::get_sta_capabilities(const std::string &client_mac,
                                                                      beerocks::eFreqType freq_type)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(client_mac));

    if (!pSta) {
        LOG(ERROR) << "Station not found ";
        return nullptr;
    }

    if ((freq_type != eFreqType::FREQ_24G) && (freq_type != eFreqType::FREQ_5G) &&
        (freq_type != eFreqType::FREQ_6G)) {
        LOG(ERROR) << "freq type must be 2.4GHz, 5GHz, or 6GHz";
        return nullptr;
    }

    if ((freq_type == eFreqType::FREQ_24G) && (pSta->m_sta_24ghz_capabilities.valid == true)) {
        return &pSta->m_sta_24ghz_capabilities;
    }

    if ((freq_type == eFreqType::FREQ_5G) && (pSta->m_sta_5ghz_capabilities.valid == true)) {
        return &pSta->m_sta_24ghz_capabilities;
    }

    if ((freq_type == eFreqType::FREQ_6G) && (pSta->m_sta_6ghz_capabilities.valid == true)) {
        return &pSta->m_sta_24ghz_capabilities;
    }

    LOG(ERROR) << "Failed to find valid sta capabilities for freq type "
               << beerocks::utils::convert_frequency_type_to_string(freq_type);
    return nullptr;
}

bool db::set_radio_ant_num(const sMacAddr &mac, const beerocks::eWiFiAntNum ant_num)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }
    radio->ant_num = ant_num;
    return true;
}

beerocks::eWiFiAntNum db::get_radio_ant_num(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return beerocks::ANT_NONE;
    }
    return radio->ant_num;
}

bool db::set_radio_ant_gain(const sMacAddr &radio_mac, const int ant_gain)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << radio_mac << " does not exist!";
        return false;
    }
    radio->ant_gain = ant_gain;
    return true;
}

int db::get_radio_ant_gain(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << radio_mac << " does not exist!";
        return -1;
    }
    return radio->ant_gain;
}

bool db::set_radio_tx_power(const sMacAddr &radio_mac, const int tx_power)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << radio_mac << " does not exist!";
        return false;
    }
    radio->tx_power = tx_power;
    return true;
}

int db::get_radio_tx_power(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << radio_mac << " does not exist!";
        return -1;
    }
    return radio->tx_power;
}

bool db::set_radio_supported_channels(const sMacAddr &mac, beerocks::WifiChannel *channels,
                                      const int length)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }
    std::vector<beerocks::WifiChannel> supported_channels_(channels, channels + length);
    radio->supported_channels = supported_channels_;

    if (radio->supported_channels.size() == 0) {
        LOG(ERROR) << "No supported channels";
        return false;
    }

    switch (radio->supported_channels[0].get_freq_type()) {
    case eFreqType::FREQ_24G:
        radio->supports_24ghz = true;
        break;
    case eFreqType::FREQ_5G:
        radio->supports_5ghz = true;
        break;
    case eFreqType::FREQ_6G:
        radio->supports_6ghz = true;
        break;
    default:
        LOG(ERROR) << "unknown frequency! channel: "
                   << int(radio->supported_channels[0].get_channel());
        return false;
    }

    return true;
}

std::vector<beerocks::WifiChannel> db::get_radio_supported_channels(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return std::vector<beerocks::WifiChannel>();
    }
    return radio->supported_channels;
}

std::string db::get_hostap_supported_channels_string(const sMacAddr &radio_mac)
{
    std::ostringstream os;
    auto supported_channels = get_radio_supported_channels(radio_mac);
    for (const auto &val : supported_channels) {
        if (val.get_channel() > 0) {
            os << " ch = " << int(val.get_channel()) << " | dfs = " << int(val.is_dfs_channel())
               << " | bw = " << beerocks::utils::convert_bandwidth_to_int(val.get_bandwidth())
               << " | tx_pow = " << int(val.get_tx_power()) << std::endl;
        }
    }

    return os.str();
}

/**
* @brief Returns bss_color_bitmap string from uint64 value
*/
std::string db::get_bss_color_bitmap_string(uint64_t decimal_value)
{
    std::string resultStr;
    bool first = true;

    for (int i = 0; i < 64; ++i) {
        if ((decimal_value >> i) & 1) {
            if (!first) {
                resultStr += ',';
            }
            resultStr += std::to_string(i);
            first = false;
        }
    }
    return resultStr;
}

/**
 * @brief Add supported operating class to the database.
 * Currently this function is a wrapper which converts the operating
 * class to a set of supported channels and updates the list of currently
 * supported channels.
 *
 * @param mac radio mac
 * @param operating class operating class to add
 * @tx_power transmit power
 * @non_operable_channels list of statically non-operable channels
 * @return true on success
 * @return false on failure
 */
bool db::add_hostap_supported_operating_class(const sMacAddr &radio_mac, uint8_t operating_class,
                                              uint8_t tx_power,
                                              const std::vector<uint8_t> &non_operable_channels)
{
    auto supported_channels = get_radio_supported_channels(radio_mac);
    auto channel_set        = wireless_utils::operating_class_to_channel_set(operating_class);
    auto op_class_bw        = wireless_utils::operating_class_to_bandwidth(operating_class);
    auto freq_type          = wireless_utils::which_freq_op_cls(operating_class);

    // Update current channels
    for (auto c : channel_set) {
        auto channel =
            std::find_if(supported_channels.begin(), supported_channels.end(),
                         [&c, &op_class_bw](const beerocks::WifiChannel &ch) {
                             return ch.get_channel() == c && ch.get_bandwidth() == op_class_bw;
                         });
        if (channel != supported_channels.end()) {
            channel->set_tx_power(tx_power);
            channel->set_bandwidth(op_class_bw);

        } else {
            if (son::wireless_utils::is_operating_class_using_central_channel(operating_class)) {
                // These classes contains only centre channels
                beerocks::WifiChannel ch(c, wireless_utils::channel_to_freq(c, freq_type),
                                         op_class_bw);
                ch.set_tx_power(tx_power);
                supported_channels.push_back(ch);
            } else {
                beerocks::WifiChannel ch(c, freq_type, op_class_bw);
                ch.set_tx_power(tx_power);
                supported_channels.push_back(ch);
            }
        }
    }

    // Delete non-operable channels
    for (auto c : non_operable_channels) {
        auto channel = std::find_if(supported_channels.begin(), supported_channels.end(),
                                    [&c, op_class_bw, freq_type](const beerocks::WifiChannel &ch) {
                                        return ((ch.get_channel() == c) &&
                                                (ch.get_bandwidth() == op_class_bw) &&
                                                ch.get_freq_type() == freq_type);
                                    });
        if (channel != supported_channels.end()) {
            supported_channels.erase(channel);
        }
    }

    // Set values for Device.WiFi.DataElements.Network.Device.Radio.Capabilities.OperatingClasses
    dm_add_ap_operating_classes(tlvf::mac_to_string(radio_mac), tx_power, operating_class,
                                non_operable_channels);

    set_radio_supported_channels(radio_mac, &supported_channels[0], supported_channels.size());
    // dump new supported channels state
    // LOG(DEBUG) << "New supported channels for hostap" << radio_mac << " operating class "
    //            << int(operating_class) << std::endl
    //            << get_hostap_supported_channels_string(radio_mac);

    return true;
}

std::set<uint8_t> db::get_supported_channels_in_operating_class(const sMacAddr &radio_mac,
                                                                uint8_t operating_class)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << radio_mac << " does not exist!";
        return std::set<uint8_t>();
    }
    std::set<uint8_t> channels_in_operating_class;
    auto supported_channels = get_radio_supported_channels(radio_mac);
    auto channel_set        = wireless_utils::operating_class_to_channel_set(operating_class);
    auto op_class_bw        = wireless_utils::operating_class_to_bandwidth(operating_class);

    for (const auto &c : channel_set) {
        auto channel =
            std::find_if(supported_channels.begin(), supported_channels.end(),
                         [&c, &op_class_bw](const beerocks::WifiChannel &ch) {
                             return ch.get_channel() == c && ch.get_bandwidth() == op_class_bw;
                         });
        if (channel != supported_channels.end()) {
            channels_in_operating_class.insert(c);
        }
    }

    return channels_in_operating_class;
}

bool db::set_radio_band_capability(const sMacAddr &mac,
                                   const beerocks::eRadioBandCapability capability)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }
    radio->capability = capability;
    return true;
}

beerocks::eRadioBandCapability db::get_radio_band_capability(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return beerocks::SUBBAND_CAPABILITY_UNKNOWN;
    }
    return radio->capability;
}

bool db::capability_check(const std::string &mac, int channel)
{
    auto band       = wireless_utils::which_subband(channel);
    auto capability = get_radio_band_capability(tlvf::mac_from_string(mac));
    if (band == beerocks::SUBBAND_UNKNOWN || capability == beerocks::SUBBAND_CAPABILITY_UNKNOWN) {
        LOG(ERROR) << "band or capability unknown!!";
        return false;
    } else if (int(band) == int(capability) || capability == beerocks::BOTH_SUBBAND) {
        return true;
    }
    return false;
}

bool db::get_sta_6ghz_support(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    return pSta->supports_6ghz;
}

bool db::get_sta_5ghz_support(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    return pSta->supports_5ghz;
}

bool db::get_sta_24ghz_support(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    return pSta->supports_24ghz;
}

bool db::get_radio_5ghz_support(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        return false;
    }

    return radio->supports_5ghz;
}

bool db::is_radio_24ghz(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "radio " << radio_mac << " does not exist! return false as default";
        return false;
    }

    return (radio->wifi_channel.get_freq_type() == eFreqType::FREQ_24G);
}

bool db::is_radio_5ghz(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "radio " << radio_mac << " does not exist! return false as default";
        return false;
    }

    return (radio->wifi_channel.get_freq_type() == eFreqType::FREQ_5G);
}

bool db::is_radio_6ghz(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "radio " << radio_mac << " does not exist! return false as default";
        return false;
    }

    return (radio->wifi_channel.get_freq_type() == eFreqType::FREQ_6G);
}

beerocks::eFreqType db::get_radio_freq_type(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "radio " << radio_mac << " does not exist!";
        return eFreqType::FREQ_UNKNOWN;
    }
    return radio->band;
}

bool db::is_sta_6ghz(const sMacAddr &sta_mac)
{
    std::shared_ptr<Station> pSta = get_station(sta_mac);
    if (!pSta) {
        LOG(ERROR) << "Station " << sta_mac << " does not exist! return false as default";
        return false;
    }

    return (pSta->wifi_channel.get_freq_type() == eFreqType::FREQ_6G);
}

bool db::is_sta_5ghz(const sMacAddr &sta_mac)
{
    std::shared_ptr<Station> pSta = get_station(sta_mac);
    if (!pSta) {
        LOG(ERROR) << "Station " << sta_mac << " does not exist! return false as default";
        return false;
    }

    return (pSta->wifi_channel.get_freq_type() == eFreqType::FREQ_5G);
}

bool db::is_sta_24ghz(const sMacAddr &sta_mac)
{
    std::shared_ptr<Station> pSta = get_station(sta_mac);
    if (!pSta) {
        LOG(ERROR) << "Station " << sta_mac << " does not exist! return false as default";
        return false;
    }

    return (pSta->wifi_channel.get_freq_type() == eFreqType::FREQ_24G);
}

bool db::update_sta_failed_6ghz_steer_attempt(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(ERROR) << "Station not found " << mac;
        return false;
    }

    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }

    if (++pSta->steer_attempts->failed_6ghz_steer_attempts >=
        config.roaming_6ghz_failed_attemps_threshold) {
        radio->supports_6ghz = false;
    }
    return true;
}

bool db::update_sta_failed_5ghz_steer_attempt(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(ERROR) << "Station not found " << mac;
        return false;
    }

    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }

    if (++pSta->steer_attempts->failed_5ghz_steer_attempts >=
        config.roaming_5ghz_failed_attemps_threshold) {
        radio->supports_5ghz = false;
    }
    return true;
}

bool db::update_sta_failed_24ghz_steer_attempt(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(ERROR) << "Station not found " << mac;
        return false;
    }

    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }

    if (++pSta->steer_attempts->failed_24ghz_steer_attempts >=
        config.roaming_24ghz_failed_attemps_threshold) {
        radio->supports_24ghz = false;
    }
    return true;
}

bool db::can_start_client_steering(const std::string &sta_mac, const std::string &target_bssid)
{

    auto station = get_station(tlvf::mac_from_string(sta_mac));
    if (!station) {
        LOG(ERROR) << "Failed to get station with mac: " << sta_mac;
        return false;
    }

    auto target_bss   = get_bss(tlvf::mac_from_string(target_bssid));
    auto original_bss = station->get_bss();

    if (!target_bss) {
        LOG(ERROR) << "Failed to get Target BSS with BSSID: " << target_bssid;
        return false;
    }

    if (!original_bss) {
        LOG(ERROR) << "Failed to get Origin BSS for station: " << sta_mac;
        return false;
    }

    if (tlvf::mac_to_string(original_bss->bssid) == target_bssid) {
        LOG(ERROR) << "target BSSID is identical to current BSSID";
        return false;
    }

    //TODO: Refactor BSS object to cover radio band support (PPM-1057)
    bool hostap_is_5ghz = is_radio_5ghz(target_bss->radio.radio_uid);

    //TODO: Refactor Station object to cover band support (PPM-1057)
    if ((hostap_is_5ghz && !get_sta_5ghz_support(sta_mac))) {
        LOG(DEBUG) << "Sta " << sta_mac << " can't steer to hostap " << target_bssid << std::endl
                   << "  hostap_is_5ghz = " << hostap_is_5ghz << std::endl
                   << "  sta_is_5ghz = " << is_sta_5ghz(tlvf::mac_from_string(sta_mac))
                   << std::endl;
        return false;
    }
    if (!hostap_is_5ghz && !get_sta_24ghz_support(sta_mac)) {
        LOG(DEBUG) << "Sta " << sta_mac << " can't steer to hostap " << target_bssid << std::endl
                   << "  node_5ghz_support = " << get_sta_5ghz_support(sta_mac) << std::endl
                   << "  node_24ghz_support = " << get_sta_24ghz_support(sta_mac) << std::endl;
        return false;
    }
    return true;
}

void db::update_node_11v_responsiveness(Station &station, bool success)
{
    if (success) {
        LOG(DEBUG) << "updating station " << station.mac << " as supporting 11v";
        station.m_failed_11v_request_count = 0;
        station.m_supports_11v             = true;
    } else {
        if (++station.m_failed_11v_request_count >= config.roaming_11v_failed_attemps_threshold) {
            LOG(DEBUG) << "station " << station.mac
                       << " exceeded maximum 11v failed attempts, updating as not supporting 11v";
            station.m_supports_11v = false;
        }
    }
}

bool db::get_node_11v_capability(const Station &station) { return station.m_supports_11v; }

std::shared_ptr<Agent::sRadio::sBss> db::add_bss(Agent::sRadio &radio, const sMacAddr &bssid,
                                                 const std::string &ssid, int vap_id)
{
    std::shared_ptr<Agent::sRadio::sBss> bss = radio.bsses.add(bssid, radio, vap_id);
    if (bss) {
        bss->ssid                    = ssid;
        std::shared_ptr<Agent> agent = get_agent_by_radio_uid(radio.radio_uid);
        if (agent) {
            dm_set_radio_bss(agent->al_mac, radio.radio_uid, bssid);
        }
    } else {
        LOG(ERROR) << "Failed to add BSS " << bssid;
    }

    return bss;
}

bool db::disable_bss(Agent::sRadio &radio, Agent::sRadio::sBss &bss)
{
    bss.enabled = false;
    return dm_remove_bss(bss);
}

bool db::update_bss(const sMacAddr &al_mac, const sMacAddr &radio_mac, const sMacAddr &bssid,
                    const std::string &ssid)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        return false;
    }
    std::shared_ptr<Agent::sRadio::sBss> bss = get_bss(bssid, al_mac);
    if (!bss) {
        LOG(DEBUG) << "update_bss: creating new BSS for " << bssid;
        return (add_bss(*radio, bssid, ssid) != nullptr);
    }
    bss->ssid = ssid;
    return dm_set_radio_bss(al_mac, radio_mac, bssid);
}

std::set<std::string> db::get_radio_bss_bssids(const std::string &mac)
{
    std::set<std::string> bssid_set;
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return bssid_set;
    }

    for (auto &bss : radio->bsses) {
        bssid_set.insert(tlvf::mac_to_string(bss.first));
    }
    return bssid_set;
}

std::string db::get_bss_ssid(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio::sBss> bss = get_bss(mac);
    if (!bss) {
        return std::string();
    }
    return bss->ssid;
}

bool db::is_vap_on_steer_list(const sMacAddr &bssid)
{
    if (config.load_steer_on_vaps.empty()) {
        return true;
    }

    std::shared_ptr<Agent::sRadio> radio = get_radio_by_bssid(bssid);
    if (!radio) {
        LOG(ERROR) << "No radio found for BSSID " << bssid;
        return false;
    }

    auto vap_name = get_radio_iface_name(radio->radio_uid);
    if (vap_name == "INVALID") {
        LOG(ERROR) << "vap name is invalid for bssid " << bssid;
        return false;
    }

    auto vap_id = get_bss_vap_id(bssid);
    if (vap_id == IFACE_ID_INVALID) {
        LOG(ERROR) << "vap id is invalid for bssid " << bssid;
        return false;
    }

    // consider vap_id shift when main vap_id is greater than 0
    // (case of glinet where main vap is wlan0-1)
    auto iface_ids = utils::get_ids_from_iface_string(vap_name);
    if (iface_ids.vap_id >= IFACE_VAP_ID_MIN) {
        vap_id += iface_ids.vap_id;
    }

    vap_name               = utils::get_iface_string_from_iface_vap_ids(vap_name, vap_id);
    const auto &steer_vaps = config.load_steer_on_vaps;
    if (steer_vaps.find(vap_name) == std::string::npos) {
        return false;
    }
    return true;
}

std::string db::get_bss_by_ssid(const sMacAddr &radio_mac, const std::string &ssid)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        return std::string();
    }

    for (const auto &bss : radio->bsses) {
        if (bss.second->ssid == ssid) {
            return tlvf::mac_to_string(bss.first);
        }
    }
    return std::string();
}

sMacAddr db::get_radio_bss_mac(const sMacAddr &radio_mac, int vap_id)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        return network_utils::ZERO_MAC;
    }
    for (const auto &bss : radio->bsses) {
        if (bss.second->get_vap_id() == vap_id) {
            return bss.first;
        }
    }

    return network_utils::ZERO_MAC;
}

// returns radio_uid to which the client is connected
std::string db::get_sta_parent_radio(const std::string &mac)
{
    std::shared_ptr<Station> station = get_station(tlvf::mac_from_string(mac));
    if (!station) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return std::string();
    }
    if (station->get_bss()) {
        return tlvf::mac_to_string(station->get_bss()->radio.radio_uid);
    } else {
        LOG(ERROR) << __FUNCTION__ << " - no parent BSS found for STA " << mac;
        return std::string();
    }
}

std::string db::get_bss_parent_radio(const std::string &bssid)
{
    std::shared_ptr<Agent::sRadio> parent_radio = get_radio_by_bssid(tlvf::mac_from_string(bssid));
    if (!parent_radio) {
        return std::string();
    }

    return tlvf::mac_to_string(parent_radio->radio_uid);
}

std::string db::get_agent_data_model_path(const sMacAddr &al_mac)
{
    std::shared_ptr<Agent> agent = get_agent(al_mac);
    if (!agent) {
        return {};
    }

    return agent->dm_path;
}

std::string db::get_sta_data_model_path(const sMacAddr &mac)
{
    std::shared_ptr<Station> station = get_station(mac);
    if (!station) {
        return {};
    }

    return station->dm_path;
}

std::string db::get_radio_data_model_path(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        return {};
    }

    return radio->dm_path;
}

int8_t db::get_bss_vap_id(const sMacAddr &bssid)
{
    std::shared_ptr<Agent::sRadio::sBss> bss = get_bss(bssid);
    return bss ? bss->get_vap_id() : IFACE_ID_INVALID;
}

bool db::set_radio_iface_name(const sMacAddr &mac, const std::string &iface_name)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }

    radio->iface_name = iface_name;
    return true;
}

std::string db::get_radio_iface_name(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return "INVALID";
    }

    return radio->iface_name;
}

bool db::set_radio_iface_type(const sMacAddr &al_mac, const sMacAddr &mac,
                              const beerocks::eIfaceType iface_type)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return false;
    }
    radio->iface_type = iface_type;
    return true;
}

beerocks::eIfaceType db::get_radio_iface_type(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    }
    return radio->iface_type;
}

bool db::set_sta_backhaul_iface_type(const sMacAddr &mac, beerocks::eIfaceType iface_type)
{
    std::shared_ptr<Station> station = get_station(mac);
    if (!station) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    if (station->get_bss() && (iface_type > beerocks::IFACE_TYPE_WIFI_END ||
                               iface_type == beerocks::IFACE_TYPE_UNSUPPORTED)) {
        LOG(ERROR) << "this should not happend!";
        return false;
    }
    station->iface_type = iface_type;
    return true;
}

beerocks::eIfaceType db::get_sta_backhaul_iface_type(const sMacAddr &mac)
{
    std::shared_ptr<Station> station = get_station(mac);
    if (!station) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    }
    return station->iface_type;
}

std::string db::get_5ghz_sibling_bss(const std::string &mac)
{
    std::shared_ptr<Agent> agent = get_agent(get_radio_parent_agent(tlvf::mac_from_string(mac)));
    std::shared_ptr<Agent::sRadio::sBss> bss = get_bss(tlvf::mac_from_string(mac));
    if (!bss) {
        return std::string();
    }

    for (const auto &radio : agent->radios) {
        if (radio.second->supports_5ghz) {
            for (const auto &sibling_bss : radio.second->bsses) {
                if (sibling_bss.second->ssid == bss->ssid) {
                    return tlvf::mac_to_string(sibling_bss.second->bssid);
                }
            }
        }
    }
    return std::string();
}

bool db::set_radio_activity_mode(const sMacAddr &mac, const eApActiveMode ap_activity_mode)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "radio " << mac << " does not exist!";
        return false;
    }
    radio->ap_activity_mode = ap_activity_mode;
    return true;
}

beerocks::eApActiveMode db::get_radio_activity_mode(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "radio " << mac << " does not exist!";
        return AP_INVALID_MODE;
    }
    return radio->ap_activity_mode;
}

bool db::set_radar_hit_stats(const sMacAddr &mac, uint8_t channel, uint8_t bw, bool is_csa_entry)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }
    Agent::sRadio::sWifiChannelRadarStats radar_statistics = {
        .channel = channel, .bandwidth = bw, .channel_ext_above_secondary = 0};

    //CSA enter channel
    if (is_csa_entry) {
        if (radio->Radar_stats.size() == RADAR_STATS_LIST_MAX) {
            radio->Radar_stats.pop_back();
        }
        auto now                             = std::chrono::steady_clock::now();
        radar_statistics.csa_enter_timestamp = now;
        radar_statistics.csa_exit_timestamp  = now;
        radio->Radar_stats.push_front(radar_statistics);
        // for_each(begin(n.hostap->Radar_stats) , end(n.hostap->Radar_stats), [&](sWifiChannelRadarStats radar_stat){
        for (const auto &radar_stat : radio->Radar_stats) {
            auto delta_radar = std::chrono::duration_cast<std::chrono::seconds>(
                                   radar_stat.csa_exit_timestamp - radar_stat.csa_enter_timestamp)
                                   .count();
            // if(delta_radar)
            LOG(DEBUG) << "channel = " << int(radar_stat.channel)
                       << " bw = " << int(radar_stat.bandwidth)
                       << " time_in_channel_sec = " << int(delta_radar);
            ;
        }
        return true;
    }
    //CSA exit channel
    radio->Radar_stats.front().csa_exit_timestamp = std::chrono::steady_clock::now();

    return true;
}

bool db::set_supported_channel_radar_affected(const sMacAddr &mac,
                                              const std::vector<uint8_t> &channels, bool affected)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }
    auto channels_count = channels.size();
    LOG(DEBUG) << " channels_count = " << int(channels_count);
    if (channels_count < 1) {
        LOG(ERROR) << "the given channel list must contain at least one value";
        return false;
    }
    auto it = find_if(std::begin(radio->supported_channels), std::end(radio->supported_channels),
                      [&](beerocks::WifiChannel supported_channel) {
                          return supported_channel.get_channel() == *channels.begin();
                      });

    if (it == std::end(radio->supported_channels)) {
        LOG(ERROR) << "channels not found ,not suppose to happen!!";
        return false;
    }
    std::for_each(it, std::next(it, channels_count), [&](beerocks::WifiChannel &supported_channel) {
        LOG(DEBUG) << " supported_channel = " << int(supported_channel.get_channel())
                   << " affected = " << int(affected);
        supported_channel.set_radar_affected(affected);
    });

    // for(auto supported_channel : n->hostap->supported_channels) {
    //     if(supported_channel.channel > 0) {
    //         LOG(DEBUG) <<" supported_channel = " << int(supported_channel.channel) << " affected = " << int(supported_channel.radar_affected);
    //     }
    // }

    return true;
}

bool db::set_radio_cac_completed(const sMacAddr &mac, bool enable)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }
    radio->cac_completed = enable;
    return true;
}

bool db::get_radio_cac_completed(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }

    return radio->cac_completed;
}

bool db::set_radio_on_dfs_reentry(const sMacAddr &mac, bool enable)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }

    radio->on_dfs_reentry = enable;
    return true;
}

bool db::get_radio_on_dfs_reentry(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }

    return radio->on_dfs_reentry;
}

bool db::set_radio_dfs_reentry_clients(const sMacAddr &mac,
                                       const std::set<std::string> &dfs_reentry_clients)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }

    radio->dfs_reentry_clients = dfs_reentry_clients;
    for_each(begin(radio->dfs_reentry_clients), end(radio->dfs_reentry_clients),
             [&](const std::string &dfs_reentry_client) {
                 LOG(DEBUG) << "dfs_reentry_client = " << dfs_reentry_client;
             });
    return true;
}

std::set<std::string> db::get_radio_dfs_reentry_clients(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    std::set<std::string> ret;
    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return ret;
    }
    for_each(begin(radio->dfs_reentry_clients), end(radio->dfs_reentry_clients),
             [&](const std::string &dfs_reentry_client) {
                 LOG(DEBUG) << "dfs_reentry_client = " << dfs_reentry_client;
             });
    return radio->dfs_reentry_clients;
}

bool db::clear_radio_dfs_reentry_clients(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);

    if (!radio) {
        LOG(ERROR) << "radio not found.... ";
        return false;
    }

    radio->dfs_reentry_clients.clear();
    return true;
}

//
// Channel Scan
//
bool db::set_channel_scan_is_enabled(const sMacAddr &mac, bool enable)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    radio->continuous_scan_config.is_enabled = enable;
    return true;
}

bool db::get_channel_scan_is_enabled(const sMacAddr &mac)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    return radio->continuous_scan_config.is_enabled;
}

bool db::set_channel_scan_interval_sec(const sMacAddr &mac, int interval_sec)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    radio->continuous_scan_config.interval_sec = interval_sec;
    return true;
}

int db::get_channel_scan_interval_sec(const sMacAddr &mac)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    return radio->continuous_scan_config.interval_sec;
}

bool db::set_channel_scan_is_pending(const sMacAddr &mac, bool scan_is_pending)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio " << mac;
        return false;
    }

    radio->single_scan_status.scan_is_pending = scan_is_pending;

    return true;
}

bool db::set_channel_scan_in_progress(const sMacAddr &mac, bool scan_in_progress, bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    LOG(DEBUG) << (single_scan ? "single" : "continuous") << " scan "
               << (scan_in_progress ? "is" : "isn't") << " in progress.";
    (single_scan ? radio->single_scan_status : radio->continuous_scan_status).scan_in_progress =
        scan_in_progress;

    return true;
}

bool db::get_channel_scan_in_progress(const sMacAddr &mac, bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }
    if (single_scan) {
        return (radio->single_scan_status.scan_in_progress ||
                radio->single_scan_status.scan_is_pending);
    } else {
        return radio->continuous_scan_status.scan_in_progress;
    }
}

bool db::set_channel_scan_results_status(const sMacAddr &mac,
                                         beerocks::eChannelScanStatusCode error_code,
                                         bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    LOG(DEBUG) << (single_scan ? "single" : "continuous")
               << " scan, last scan error code = " << int(error_code);

    (single_scan ? radio->single_scan_status : radio->continuous_scan_status).last_scan_error_code =
        error_code;

    return true;
}

beerocks::eChannelScanStatusCode db::get_channel_scan_results_status(const sMacAddr &mac,
                                                                     bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return beerocks::eChannelScanStatusCode::INTERNAL_FAILURE;
    }

    return (single_scan ? radio->single_scan_status : radio->continuous_scan_status)
        .last_scan_error_code;
}

bool db::clear_channel_preference(const sMacAddr &radio_mac)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << radio_mac;
        return false;
    }

    radio->channel_preference_report.clear();
    return true;
}

bool db::set_channel_preference(const sMacAddr &radio_mac, const uint8_t operating_class,
                                const uint8_t channel_number, const uint8_t preference)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << radio_mac;
        return false;
    }

    if (!wireless_utils::is_channel_in_operating_class(operating_class, channel_number)) {
        LOG(ERROR) << "Operating class #" << operating_class << " does not contain channel #"
                   << channel_number;
        return false;
    }

    const auto key = std::make_pair(operating_class, channel_number);

    radio->channel_preference_report[key] = preference;
    radio->last_preference_report_change  = std::chrono::steady_clock::now();
    return true;
}

int8_t db::get_channel_preference(const sMacAddr &radio_mac, const uint8_t operating_class,
                                  const uint8_t channel_number, const bool is_central_channel)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << radio_mac;
        return (int8_t)eChannelPreferenceRankingConsts::INVALID;
    }

    auto freq_type = son::wireless_utils::which_freq_op_cls(operating_class);
    if (freq_type == eFreqType::FREQ_UNKNOWN) {
        LOG(ERROR) << "the frequency type of operating class " << operating_class << " is unknown";
        return (int8_t)eChannelPreferenceRankingConsts::INVALID;
    }

    uint8_t channel = channel_number;
    if (!is_central_channel &&
        wireless_utils::is_operating_class_using_central_channel(operating_class)) {
        auto bandwidth = wireless_utils::operating_class_to_bandwidth(operating_class);
        if (freq_type == eFreqType::FREQ_5G) {
            auto source_channel_it = wireless_utils::channels_table_5g.find(channel_number);
            if (source_channel_it == wireless_utils::channels_table_5g.end()) {
                LOG(ERROR) << "Couldn't find source channel " << channel_number
                           << "from 5g channels table for overlapping channels";
                return (int8_t)eChannelPreferenceRankingConsts::INVALID;
            }
            channel = source_channel_it->second.at(bandwidth).center_channel;
        } else if (freq_type == eFreqType::FREQ_6G) {
            auto source_channel_it = wireless_utils::channels_table_6g.find(channel_number);
            if (source_channel_it == wireless_utils::channels_table_6g.end()) {
                LOG(ERROR) << "Couldn't find source channel " << channel_number
                           << "from 6g channels table for overlapping channels";
                return (int8_t)eChannelPreferenceRankingConsts::INVALID;
            }
            channel = source_channel_it->second.at(bandwidth).center_channel;
        } else {
            LOG(ERROR) << "frequency type "
                       << beerocks::utils::convert_frequency_type_to_string(freq_type)
                       << " must be either 5g or 6g";
            return (int8_t)eChannelPreferenceRankingConsts::INVALID;
        }
    }

    if (!wireless_utils::is_channel_in_operating_class(operating_class, channel)) {
        LOG(ERROR) << "Operating class #" << operating_class << " does not contain channel #"
                   << channel;
        return (int8_t)eChannelPreferenceRankingConsts::INVALID;
    }

    const auto &bw                 = wireless_utils::operating_class_to_bandwidth(operating_class);
    const auto &supported_channels = radio->supported_channels;

    // Find if the channel is supported by the radio
    if (std::find_if(supported_channels.begin(), supported_channels.end(),
                     [channel, bw, &freq_type](const beerocks::WifiChannel chan) {
                         // Find if matching channel number & bandwidth.
                         return ((chan.get_channel() == channel) && (chan.get_bandwidth() == bw) &&
                                 chan.get_freq_type() == freq_type);
                     }) == supported_channels.end()) {
        LOG(ERROR) << "Channel #" << channel
                   << "(freq type: " << beerocks::utils::convert_frequency_type_to_string(freq_type)
                   << ") in Operating Class #" << operating_class
                   << " is not supported by the radio.";
        return (int8_t)eChannelPreferenceRankingConsts::NON_OPERABLE;
    }

    const auto key  = std::make_pair(operating_class, channel);
    const auto iter = radio->channel_preference_report.find(key);
    if (iter == radio->channel_preference_report.end()) {
        // Key is not found on radio's preference, returning BEST
        return (int8_t)eChannelPreferenceRankingConsts::BEST;
    }

    // Converting to signed to fit return type
    return (int8_t)iter->second;
}

Agent::sRadio::PreferenceReportMap db::get_radio_channel_preference(const sMacAddr &radio_mac)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << radio_mac;
        return {};
    }

    // Get preference from previous report.
    Agent::sRadio::PreferenceReportMap preference_map = radio->channel_preference_report;

    // Fill missing supported channels
    for (const auto &supported_channel : radio->supported_channels) {
        const auto operating_class =
            wireless_utils::get_operating_class_by_channel(supported_channel);
        if (!operating_class) {
            // Failed to get Operating Class number
            continue;
        }
        const auto key = std::make_pair(operating_class, supported_channel.get_channel());
        if (preference_map.find(key) != preference_map.end()) {
            // Preference already exists in map, skip.
            continue;
        }
        preference_map[key] = (int8_t)eChannelPreferenceRankingConsts::BEST;
    }

    return preference_map;
}

const std::chrono::steady_clock::time_point
db::get_last_preference_report_change(const sMacAddr &radio_mac)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << radio_mac;
        return std::chrono::steady_clock::time_point::min();
    }
    return radio->last_preference_report_change;
}

bool db::is_preference_reported_expired(const sMacAddr &radio_mac)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << radio_mac;
        return false;
    }
    return ((radio->last_preference_report_change + CHANNEL_PREFERENCE_EXPIRATION) <
            std::chrono::steady_clock::now());
}

bool db::set_channel_scan_dwell_time_msec(const sMacAddr &mac, int dwell_time_msec,
                                          bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    LOG(DEBUG) << (single_scan ? "single" : "continuous")
               << ", dwell time msec = " << dwell_time_msec;

    if (dwell_time_msec < 0) {
        LOG(ERROR) << "Invalid dwell time: " << dwell_time_msec
                   << ". Only positive values are supported!";
        return false;
    }

    (single_scan ? radio->single_scan_config : radio->continuous_scan_config).dwell_time_msec =
        dwell_time_msec;

    return true;
}

int db::get_channel_scan_dwell_time_msec(const sMacAddr &mac, bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    return (single_scan ? radio->single_scan_config : radio->continuous_scan_config)
        .dwell_time_msec;
}

bool db::is_channel_scan_pool_supported(const sMacAddr &mac,
                                        const std::unordered_set<uint8_t> &channel_pool)
{
    auto supported_channels = get_radio_supported_channels(mac);
    for (const auto &channel : channel_pool) {
        auto found_channel =
            std::find_if(supported_channels.begin(), supported_channels.end(),
                         [&channel](const beerocks::WifiChannel &supported_channel) {
                             return supported_channel.get_channel() == channel;
                         });
        if (found_channel == supported_channels.end()) {
            LOG(ERROR) << "channel #" << int(channel) << " is not supported";
            return false;
        }
    }
    return true;
}

bool db::set_channel_scan_pool(const sMacAddr &mac, const std::unordered_set<uint8_t> &channel_pool,
                               bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    if (!is_channel_scan_pool_supported(mac, channel_pool)) {
        LOG(ERROR) << "setting channel pool failed, one of the channels is not supported!";
        return false;
    }

    (single_scan ? radio->single_scan_config : radio->continuous_scan_config).active_channel_pool =
        channel_pool;

    LOG(DEBUG) << (single_scan ? "single" : "continuous")
               << " scan, setting channel pool succeeded!";

    return true;
}

const std::unordered_set<uint8_t> &db::get_channel_scan_pool(const sMacAddr &mac, bool single_scan)
{
    static std::unordered_set<uint8_t> empty;

    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return empty;
    }

    return (single_scan ? radio->single_scan_config : radio->continuous_scan_config)
        .active_channel_pool;
}

bool db::is_channel_in_pool(const sMacAddr &mac, uint8_t channel, bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    auto &pool = (single_scan ? radio->single_scan_config : radio->continuous_scan_config)
                     .active_channel_pool;
    return pool.find(channel) != pool.end();
}

bool db::clear_channel_scan_results(const sMacAddr &mac, bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    (single_scan ? radio->single_scan_results : radio->continuous_scan_results).clear();

    return true;
}

bool db::add_channel_scan_results(const sMacAddr &mac, const sChannelScanResults &scan_result,
                                  bool single_scan)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    (single_scan ? radio->single_scan_results : radio->continuous_scan_results)
        .push_back(scan_result);

    return true;
}

const std::list<sChannelScanResults> &db::get_channel_scan_results(const sMacAddr &mac,
                                                                   bool single_scan)
{
    static std::list<sChannelScanResults> empty;

    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return empty;
    }

    return (single_scan ? radio->single_scan_results : radio->continuous_scan_results);
}

bool db::has_channel_report_record(const sMacAddr &mac, const std::string &ISO_8601_timestamp,
                                   const uint8_t operating_class, const uint8_t channel)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    // Find record by timestamp
    auto report_record_iter = radio->channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == radio->channel_scan_report_records.end()) {
        // The radio does not contain a record of the given timestamp
        return false;
    }

    // Find report for key
    auto key               = std::make_pair(operating_class, channel);
    auto report_index_iter = report_record_iter->second.find(key);
    if (report_index_iter == report_record_iter->second.end()) {
        // The record does not contain a report of the given key
        return false;
    }

    return true;
}

bool db::clear_channel_report_record(const sMacAddr &mac, const std::string &ISO_8601_timestamp)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }

    auto report_record_iter = radio->channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == radio->channel_scan_report_records.end()) {
        LOG(ERROR) << "unable to get record at timestamp: " << ISO_8601_timestamp;
        return false;
    }

    // Clear the report for the found record
    for (const auto &report_key : report_record_iter->second) {
        radio->scan_report[report_key].neighbors.clear();
    }

    // unordered_map::erase(const key_type& k) returns the number of elements erased
    return (radio->channel_scan_report_records.erase(ISO_8601_timestamp) == 1);
}

bool db::get_channel_report_record(const sMacAddr &mac, const std::string &ISO_8601_timestamp,
                                   Agent::sRadio::channel_scan_report_index &report_index)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << mac;
        return false;
    }
    const auto &report_record_iter = radio->channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == radio->channel_scan_report_records.end()) {
        LOG(ERROR) << "unable to get record at timestamp: " << ISO_8601_timestamp;
        return false;
    }
    report_index = report_record_iter->second;
    return true;
}

bool db::get_pool_of_all_supported_channels(std::unordered_set<uint8_t> &channel_pool_set,
                                            const sMacAddr &radio_mac)
{
    LOG(DEBUG) << "Setting channel pool to all channels";
    channel_pool_set.clear();
    auto all_channels = get_radio_supported_channels(radio_mac);
    if (all_channels.empty()) {
        LOG(ERROR) << "Supported channel list is empty, failed to set channel pool!";
        return false;
    }
    // Take only the 20MHz channels
    std::vector<beerocks::WifiChannel> subset_20MHz_channels;
    std::copy_if(all_channels.begin(), all_channels.end(),
                 std::back_inserter(subset_20MHz_channels),
                 [](const beerocks::WifiChannel &c) -> bool {
                     return c.get_bandwidth() == eWiFiBandwidth::BANDWIDTH_20;
                 });
    // Convert from beerocks::WifiChannel to uint8_t
    std::transform(subset_20MHz_channels.begin(), subset_20MHz_channels.end(),
                   std::inserter(channel_pool_set, channel_pool_set.end()),
                   [](const beerocks::WifiChannel &c) -> uint8_t { return c.get_channel(); });
    return true;
}

bool db::get_selection_channel_pool(const sMacAddr &ruid,
                                    std::unordered_set<uint8_t> &channel_pool_set)
{
    auto radio = get_radio_by_uid(ruid);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << ruid;
        return false;
    }
    if (radio->single_scan_config.default_channel_pool.empty()) {
        LOG(INFO) << "Getting static channel pool for " << radio->iface_name;
        const auto &pool_str = config.default_channel_pools[radio->iface_name];
        LOG(INFO) << "Static channel pool for " << radio->iface_name << " is: " << pool_str;
        const auto &channels_str = string_utils::str_split(pool_str, ',');
        for (const auto &channel_str : channels_str) {
            LOG(INFO) << "Adding channel " << channel_str << " to the dynamic pool";
            radio->single_scan_config.default_channel_pool.insert(
                beerocks::string_utils::stoi(channel_str));
        }
    }
    channel_pool_set = radio->single_scan_config.default_channel_pool;
    return true;
}

bool db::set_selection_channel_pool(const sMacAddr &ruid,
                                    const std::unordered_set<uint8_t> &channel_pool)
{
    auto radio = get_radio_by_uid(ruid);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << ruid;
        return false;
    }
    if (!is_channel_scan_pool_supported(ruid, channel_pool)) {
        LOG(ERROR) << "Channel pool is not supported!";
        return false;
    }
    radio->single_scan_config.default_channel_pool.clear();
    radio->single_scan_config.default_channel_pool.insert(channel_pool.begin(), channel_pool.end());
    return true;
}

bool db::add_empty_channel_report_entry(const sMacAddr &RUID, const uint8_t &operating_class,
                                        const uint8_t &channel,
                                        const std::string &ISO_8601_timestamp)
{
    auto radio = get_radio_by_uid(RUID);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << RUID;
        return false;
    }

    const auto &key = std::make_pair(operating_class, channel);
    LOG(DEBUG) << "Clearing neighbors for [" << key.first << "," << key.second << "]";
    radio->scan_report[key].neighbors.clear();

    // Find any existing report key to channel scan report record
    const auto &report_record_iter = radio->channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == radio->channel_scan_report_records.end()) {
        // If record does not exist, create a new one.
        radio->channel_scan_report_records.emplace(
            ISO_8601_timestamp,
            std::set<Agent::sRadio::channel_scan_report::channel_scan_report_key>{});
    }

    // Insert the key into the record
    radio->channel_scan_report_records[ISO_8601_timestamp].insert(key);
    return true;
}

bool db::add_channel_report(const sMacAddr &RUID, const uint8_t &operating_class,
                            const uint8_t &channel,
                            const std::vector<wfa_map::cNeighbors> &neighbors, uint8_t avg_noise,
                            uint8_t avg_utilization, const std::string &ISO_8601_timestamp,
                            bool override_existing_data)
{
    auto radio = get_radio_by_uid(RUID);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << RUID;
        return false;
    }
    const auto &key = std::make_pair(operating_class, channel);
    if (override_existing_data) {
        // Clear neighbors if Override flag is set.
        LOG(DEBUG) << "Clearing neighbors for [" << key.first << "," << key.second << "]";
        radio->scan_report[key].neighbors.clear();
    }

    auto get_bandwidth_from_str =
        [](const std::string &bw) -> beerocks_message::eChannelScanResultChannelBandwidth {
        if (bw == "20Mz") {
            return beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_20MHz;
        } else if (bw == "40Mz") {
            return beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_40MHz;
        } else if (bw == "80Mz") {
            return beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80MHz;
        } else if (bw == "80+80Mz") {
            return beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80_80;
        } else if (bw == "160Mz") {
            return beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_160MHz;
        } else {
            return beerocks_message::eChannelScanResultChannelBandwidth::eChannel_Bandwidth_NA;
        }
    };

    for (auto src_neighbor : neighbors) {
        sChannelScanResults neighbor_result = {0};

        neighbor_result.channel = channel;

        neighbor_result.bssid = src_neighbor.bssid();

        const auto neighbor_ssid_str =
            (src_neighbor.ssid_length() > 0 ? src_neighbor.ssid_str() : "") + "\0";
        neighbor_ssid_str.copy(neighbor_result.ssid, beerocks::message::WIFI_SSID_MAX_LENGTH);

        neighbor_result.signal_strength_dBm = src_neighbor.signal_strength();

        neighbor_result.operating_channel_bandwidth =
            get_bandwidth_from_str(src_neighbor.channels_bw_list_str());

        neighbor_result.noise_dBm = avg_noise;

        if (src_neighbor.bss_load_element_present() ==
            wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_PRESENT) {
            neighbor_result.channel_utilization = (uint32_t)(*src_neighbor.channel_utilization());
            neighbor_result.station_count       = (uint16_t)(*src_neighbor.station_count());
        } else {
            neighbor_result.channel_utilization = avg_utilization;
        }

        radio->scan_report[key].neighbors.push_back(neighbor_result);
    }

    // Find any existing report key to channel scan report record
    const auto &report_record_iter = radio->channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == radio->channel_scan_report_records.end()) {
        // If record does not exist, create a new one.
        radio->channel_scan_report_records.emplace(
            ISO_8601_timestamp,
            std::set<Agent::sRadio::channel_scan_report::channel_scan_report_key>{});
    }
    // Insert the key into the record
    radio->channel_scan_report_records[ISO_8601_timestamp].insert(key);

    return true;
}

const std::vector<sChannelScanResults>
db::get_channel_scan_report(const sMacAddr &RUID,
                            const Agent::sRadio::channel_scan_report_index &index)
{
    static std::vector<sChannelScanResults> empty_report;

    auto radio = get_radio_by_uid(RUID);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << RUID;
        return empty_report;
    }

    std::vector<sChannelScanResults> final_report;

    for (const auto &key : index) {
        if (radio->scan_report.find(key) == radio->scan_report.end()) {
            LOG(ERROR) << "Cannot find matching report for key: [" << key.first << ',' << key.second
                       << "].";
            continue;
        }
        auto report_neighbors = radio->scan_report[key].neighbors;
        LOG(DEBUG) << "Adding " << report_neighbors.size() << " neighbors from key: [" << key.first
                   << ',' << key.second << "].";
        final_report.insert(final_report.end(), report_neighbors.begin(), report_neighbors.end());
    }
    return final_report;
}

const std::vector<sChannelScanResults>
db::get_channel_scan_report(const sMacAddr &RUID, const std::string &ISO_8601_timestamp)
{
    static std::vector<sChannelScanResults> empty_report;
    auto radio = get_radio_by_uid(RUID);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << RUID;
        return empty_report;
    }
    const auto &report_record_iter = radio->channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == radio->channel_scan_report_records.end()) {
        LOG(ERROR) << "unable to get record at timestamp: " << ISO_8601_timestamp;
        return empty_report;
    }
    return get_channel_scan_report(RUID, report_record_iter->second);
}

const std::vector<sChannelScanResults> db::get_channel_scan_report(const sMacAddr &RUID,
                                                                   bool single_scan)
{
    static std::vector<sChannelScanResults> empty_report;
    auto radio = get_radio_by_uid(RUID);
    if (!radio) {
        LOG(ERROR) << "unable to get radio " << RUID;
        return empty_report;
    }

    auto wifi_Channel = get_radio_wifi_channel(RUID);
    if (wifi_Channel.is_empty()) {
        LOG(ERROR) << "wifi channel is empty";
        return empty_report;
    }

    Agent::sRadio::channel_scan_report_index index;
    const auto &pool = get_channel_scan_pool(RUID, single_scan);
    for (const auto &channel : pool) {
        auto operating_class = wireless_utils::get_operating_class_by_channel(beerocks::WifiChannel(
            channel, wifi_Channel.get_freq_type(), eWiFiBandwidth::BANDWIDTH_20));
        if (operating_class == 0) {
            LOG(ERROR) << "failed to find operating class of channel " << channel << " (freq type: "
                       << beerocks::utils::convert_frequency_type_to_string(
                              wifi_Channel.get_freq_type())
                       << ") and bandwidth 20MHz";
            return empty_report;
        }
        index.insert(std::make_pair(operating_class, channel));
    }
    return get_channel_scan_report(RUID, index);
}

static void dm_add_bss_neighbors(std::shared_ptr<beerocks::nbapi::Ambiorix> m_ambiorix_datamodel,
                                 const std::string &channel_path,
                                 const std::vector<wfa_map::cNeighbors> &neighbors)
{
    for (auto neighbor : neighbors) {
        // Device.WiFi.DataElements.Network.Device.1.Radio.2.ScanResult.3.OpClassScan.4.ChannelScan.5.NeighborBSS
        auto neighbor_path = m_ambiorix_datamodel->add_instance(channel_path + ".NeighborBSS");

        if (neighbor_path.empty()) {
            LOG(ERROR) << "Failed to add NeighborBSS to " << channel_path;
            return;
        }
        m_ambiorix_datamodel->set(neighbor_path, "BSSID", neighbor.bssid());
        m_ambiorix_datamodel->set(neighbor_path, "SSID", neighbor.ssid_str());
        m_ambiorix_datamodel->set(neighbor_path, "SignalStrength", neighbor.signal_strength());
        m_ambiorix_datamodel->set(neighbor_path, "ChannelBandwidth",
                                  neighbor.channels_bw_list_str());
        if (neighbor.bss_load_element_present()) {
            m_ambiorix_datamodel->set(neighbor_path, "ChannelUtilization",
                                      neighbor.channel_utilization());
            m_ambiorix_datamodel->set(neighbor_path, "StationCount", neighbor.station_count());
        }
    }
}

static std::string
dm_add_channel_scan(std::shared_ptr<beerocks::nbapi::Ambiorix> m_ambiorix_datamodel,
                    const std::string &class_path, const uint8_t &channel, const uint8_t noise,
                    const uint8_t utilization, const std::string &ISO_8601_timestamp)
{
    // Device.WiFi.DataElements.Network.Device.1.Radio.2.ScanResult.3.OpClassScan.4.ChannelScan.5
    std::string channel_path;
    uint32_t channel_index = m_ambiorix_datamodel->get_instance_index(
        class_path + ".ChannelScan.[Channel == '%s'].", std::to_string(channel));

    if (channel_index) {
        channel_path = class_path + ".ChannelScan." + std::to_string(channel_index);
    } else {
        channel_path = m_ambiorix_datamodel->add_instance(class_path + ".ChannelScan");
        if (channel_path.empty()) {
            LOG(ERROR) << "Failed to add ChannelScan instance to " << class_path;
            return {};
        }
    }
    m_ambiorix_datamodel->set(channel_path, "TimeStamp", ISO_8601_timestamp);
    m_ambiorix_datamodel->set(channel_path, "Channel", channel);
    m_ambiorix_datamodel->set(channel_path, "Utilization", utilization);
    m_ambiorix_datamodel->set(channel_path, "Noise", noise);
    return channel_path;
}

static std::string
dm_add_op_class_scan(std::shared_ptr<beerocks::nbapi::Ambiorix> m_ambiorix_datamodel,
                     const std::string &scan_result_path, const uint8_t &operating_class)
{
    // Device.WiFi.DataElements.Network.Device.1.Radio.2.ScanResult.3.OpClassScan.4
    std::string class_path;
    uint32_t class_index = m_ambiorix_datamodel->get_instance_index(
        scan_result_path + ".OpClassScan.[OperatingClass == '%s'].",
        std::to_string(operating_class));

    if (class_index) {
        class_path = scan_result_path + ".OpClassScan." + std::to_string(class_index);
    } else {
        class_path = m_ambiorix_datamodel->add_instance(scan_result_path + ".OpClassScan");
        if (class_path.empty()) {
            LOG(ERROR) << "Failed to add OpClassScan instance to " << scan_result_path;
            return {};
        }
    }
    m_ambiorix_datamodel->set(class_path, "OperatingClass", operating_class);
    return class_path;
}

bool db::dm_add_scan_result(const sMacAddr &ruid, const uint8_t &operating_class,
                            const uint8_t &channel, const uint8_t noise, const uint8_t utilization,
                            const std::vector<wfa_map::cNeighbors> &neighbors,
                            const std::string &ISO_8601_timestamp)
{
    if (!dm_check_objects_limit(m_scan_results, MAX_SCAN_RESULT_HISTORY_SIZE)) {
        return false;
    }

    std::string radio_path = get_radio_data_model_path(ruid);

    if (radio_path.empty()) {
        LOG(DEBUG) << "Missing path to NBAPI radio: " << ruid;
        return true;
    }

    // Device.WiFi.DataElements.Network.Device.1.Radio.2.ScanResult.3
    std::string scan_result_path;
    uint32_t scan_result_index = m_ambiorix_datamodel->get_instance_index(
        radio_path + ".ScanResult.[TimeStamp == '%s'].", ISO_8601_timestamp);

    if (scan_result_index) {
        scan_result_path = radio_path + ".ScanResult." + std::to_string(scan_result_index);
    } else {
        scan_result_path = m_ambiorix_datamodel->add_instance(radio_path + ".ScanResult");
        if (scan_result_path.empty()) {
            LOG(ERROR) << "Failed to add ScanResult ";
            return false;
        }

        // Keeps track of the objects amount.
        m_scan_results.push(scan_result_path);

        if (!m_ambiorix_datamodel->set(scan_result_path, "TimeStamp", ISO_8601_timestamp)) {
            LOG(ERROR) << "Failed to set " << scan_result_path
                       << ".TimeStamp: " << ISO_8601_timestamp;
            return false;
        }
    }

    auto op_class_path =
        dm_add_op_class_scan(m_ambiorix_datamodel, scan_result_path, operating_class);
    auto channel_path = dm_add_channel_scan(m_ambiorix_datamodel, op_class_path, channel, noise,
                                            utilization, ISO_8601_timestamp);
    dm_add_bss_neighbors(m_ambiorix_datamodel, channel_path, neighbors);
    return true;
}

//
// Client Persistent Data
//
bool db::is_client_in_persistent_db(const sMacAddr &mac)
{
    // if persistent db is disabled
    if (!config.persistent_db) {
        LOG(DEBUG) << "persistent db is disabled";
        return false;
    }

    auto client_db_entry = client_db_entry_from_mac(mac);

    return bpl::db_has_entry(type_to_string(beerocks::eType::TYPE_CLIENT), client_db_entry);
}

bool db::add_steer_event_to_persistent_db(const ValuesMap &params)
{
    if (!config.persistent_db) {
        return true;
    }
    while (config.steer_history_persistent_db_max_size <= m_steer_history.size()) {
        if (!bpl::db_remove_entry("steer_history", m_steer_history.front())) {
            LOG(ERROR) << "Failed to remove entry " << m_steer_history.front()
                       << " from persistent db";
            return false;
        }
        LOG(DEBUG) << "Removed steer event entry " << m_steer_history.front()
                   << " from persistent db, total steer history entries in persisttent-db: "
                   << m_steer_history.size();
        m_steer_history.pop();
    }

    std::string entry_name = "attempt" + std::to_string(m_steer_history.size() + 1);

    if (!bpl::db_add_entry("steer_history", entry_name, params)) {
        LOG(ERROR) << "Failed to add steer history entry " << entry_name << " to persistent db";
        return false;
    }
    m_steer_history.push(entry_name);
    return true;
}

bool db::restore_steer_history()
{
    std::unordered_map<std::string, son::db::ValuesMap> steer_history;
    bool ret = true;

    if (!bpl::db_get_entries_by_type("steer_history", steer_history)) {
        LOG(WARNING) << "Failed to get steer_history entries from persistent db "
                     << "or no entries registered.";
        return false;
    }
    if (steer_history.empty()) {
        return true;
    }
    for (auto entry : steer_history) {

        auto obj_path = dm_add_steer_event();

        if (obj_path.empty()) {
            LOG(ERROR) << "Failed to add SteerEvent object.";
            return false;
        }
        m_steer_history.push(entry.first);
        ret &= m_ambiorix_datamodel->set(obj_path, "DeviceId", entry.second["device_id"]);
        ret &= m_ambiorix_datamodel->set(obj_path, "SteeredFrom", entry.second["steered_from"]);
        ret &= m_ambiorix_datamodel->set(obj_path, "SteeredTo", entry.second["steered_to"]);
        ret &= m_ambiorix_datamodel->set(obj_path, "Result", entry.second["result"]);
        ret &= m_ambiorix_datamodel->set(obj_path, "TimeStamp", entry.second["time_stamp"]);
        ret &= m_ambiorix_datamodel->set(obj_path, "SteeringType", entry.second["steering_type"]);
        ret &=
            m_ambiorix_datamodel->set(obj_path, "SteeringOrigin", entry.second["steering_origin"]);
        ret &=
            m_ambiorix_datamodel->set(obj_path, "TimeTaken", std::stoi(entry.second["time_taken"]));
    }
    return ret;
}

bool db::add_client_to_persistent_db(const sMacAddr &mac, const ValuesMap &params)
{
    // if persistent db is disabled
    if (!config.persistent_db) {
        LOG(ERROR) << "persistent db is disabled";
        return false;
    }

    if (config.clients_persistent_db_max_size <= 0) {
        LOG(ERROR) << "Invalid max clients persistent db size: "
                   << config.clients_persistent_db_max_size;
        return false;
    }

    auto db_entry = client_db_entry_from_mac(mac);

    if (bpl::db_has_entry(type_to_string(beerocks::eType::TYPE_CLIENT), db_entry)) {
        // if entry already exists in DB
        if (!remove_client_entry_and_update_counter(db_entry)) {
            LOG(ERROR) << "failed to remove client entry " << db_entry
                       << "from persistent db (for re-adding)";
            return false;
        }
    } else if (bpl::db_has_entry(std::string(), db_entry)) {
        // if entry exists in db but with different type
        LOG(ERROR) << "client entry cannot be added to persistent db, " << db_entry
                   << " already exists but with different type";
        return false;
    }

    while (m_persistent_db_clients_count >= config.clients_persistent_db_max_size) {
        LOG(DEBUG) << "reached max clients size in persistent db - removing a client before adding "
                      "new client";
        // Remove a candidate but skip the current client and not select it as candidate
        // for removal.
        if (!remove_candidate_client(mac)) {
            LOG(ERROR) << "failed to remove next-to-be-aged client entry " << db_entry
                       << " from persistent db (due to full persistent db)";
            return false;
        }
    }

    // add entry to the persistent db
    if (!add_client_entry_and_update_counter(db_entry, params)) {
        LOG(ERROR) << "failed to add client entry " << db_entry << " to persistent db";
        return false;
    }

    LOG(DEBUG) << "added client entry " << db_entry
               << " to persistent db, total clients count in persisttent-db: "
               << m_persistent_db_clients_count;

    return true;
}

bool db::set_client_time_life_delay(Station &client,
                                    const std::chrono::minutes &time_life_delay_minutes,
                                    bool save_to_persistent_db)
{
    LOG(DEBUG) << "time_life_delay_minutes = " << time_life_delay_minutes.count();

    auto timestamp = std::chrono::system_clock::now();
    if (save_to_persistent_db) {
        // if persistent db is disabled
        if (!config.persistent_db) {
            LOG(DEBUG) << "persistent db is disabled";
        } else {
            LOG(DEBUG) << "configuring persistent-db, timelife = "
                       << time_life_delay_minutes.count();

            ValuesMap values_map;
            values_map[TIMESTAMP_STR]      = timestamp_to_string_seconds(timestamp);
            values_map[TIMELIFE_DELAY_STR] = std::to_string(time_life_delay_minutes.count());

            // update the persistent db
            if (!update_client_entry_in_persistent_db(client.mac, values_map)) {
                LOG(ERROR) << "failed to update client entry in persistent-db to for "
                           << client.mac;
                return false;
            }
        }
    }

    client.time_life_delay_minutes = time_life_delay_minutes;
    client.parameters_last_edit    = timestamp;

    return true;
}

bool db::set_sta_stay_on_initial_radio(Station &client, bool stay_on_initial_radio,
                                       bool save_to_persistent_db)
{
    auto mac = client.mac;
    auto sta = has_station(mac);
    if (!sta) {
        LOG(ERROR) << "Station not found for mac " << mac;
        return false;
    }

    LOG(DEBUG) << "stay_on_initial_radio=" << stay_on_initial_radio;

    auto is_client_connected = (client.state == STATE_CONNECTED);
    LOG(DEBUG) << "client "
               << " state=" << ((is_client_connected) ? "connected" : "disconnected");

    auto timestamp = std::chrono::system_clock::now();
    if (save_to_persistent_db) {
        // if persistent db is disabled
        if (!config.persistent_db) {
            LOG(DEBUG) << "Persistent db is disabled";
        } else {
            LOG(DEBUG) << "Configuring persistent-db, initial_radio_enable = "
                       << stay_on_initial_radio;

            ValuesMap values_map;
            values_map[TIMESTAMP_STR]            = timestamp_to_string_seconds(timestamp);
            values_map[INITIAL_RADIO_ENABLE_STR] = std::to_string(stay_on_initial_radio);
            // clear initial-radio data on disabling of stay_on_initial_radio
            if (!stay_on_initial_radio) {
                LOG(DEBUG) << "Clearing initial_radio in persistent DB";
                values_map[INITIAL_RADIO_STR] = std::string();
            } else if (is_client_connected) {
                // if enabling stay-on-initial-radio and client is already connected, update the initial_radio as well
                auto bss = client.get_bss();
                if (!bss) {
                    LOG(ERROR) << "BSS not found for station " << mac;
                    return false;
                }
                auto parent_radio_mac = get_bss_parent_radio(tlvf::mac_to_string(bss->bssid));
                LOG(DEBUG) << "Persistent DB, Setting client " << mac << " initial-radio to "
                           << parent_radio_mac;
                values_map[INITIAL_RADIO_STR] = parent_radio_mac;
            }

            // update the persistent db
            if (!update_client_entry_in_persistent_db(mac, values_map)) {
                LOG(ERROR) << "Failed to update client entry in persistent-db to for " << mac;
                return false;
            }
        }
    }

    client.stay_on_initial_radio =
        (stay_on_initial_radio) ? eTriStateBool::TRUE : eTriStateBool::FALSE;
    // clear initial-radio data on disabling of stay_on_initial_radio
    if (!stay_on_initial_radio) {
        LOG(DEBUG) << "Clearing initial_radio in runtime DB";
        client.initial_radio = network_utils::ZERO_MAC;
        // if enabling stay-on-initial-radio and client is already connected, update the initial_radio as well
    } else if (is_client_connected) {
        auto bss = client.get_bss();
        if (!bss) {
            LOG(ERROR) << "BSS not found for station " << mac;
            return false;
        }
        auto parent_radio_mac = get_bss_parent_radio(tlvf::mac_to_string(bss->bssid));
        client.initial_radio  = tlvf::mac_from_string(parent_radio_mac);
        LOG(DEBUG) << "Setting client " << mac << " initial-radio to " << client.initial_radio;
    }
    client.parameters_last_edit = timestamp;

    return true;
}

bool db::set_sta_initial_radio(Station &client, const sMacAddr &initial_radio_mac,
                               bool save_to_persistent_db)
{
    auto mac                      = client.mac;
    std::shared_ptr<Station> pSta = get_station(mac);
    if (!pSta) {
        LOG(ERROR) << "Station not found for mac " << mac;
        return false;
    }

    LOG(DEBUG) << "initial_radio=" << initial_radio_mac;

    // Since the initial radio is an internal parameter (not configured by the user), its value
    // is only relevant if the stay_on_initial_radio is set and although we want its value to be
    // persistent, we don't want it to affect the client's aging.
    // This means:
    // 1. We do not update the timestamp when we update only the initial_radio.
    // 2. We only set the initial_radio if the stay_on_initial_radio is set.
    if (client.stay_on_initial_radio == eTriStateBool::NOT_CONFIGURED) {
        LOG(ERROR) << "Configuring initial-radio to " << initial_radio_mac
                   << " aborted: stay-on-initial-radio is not configured yet";
        return false;
    }

    if (save_to_persistent_db) {
        // if persistent db is disabled
        if (!config.persistent_db) {
            LOG(DEBUG) << "Persistent db is disabled";
        } else {
            LOG(DEBUG) << "Configuring persistent-db, initial_radio = " << initial_radio_mac;

            ValuesMap values_map;
            values_map[INITIAL_RADIO_STR] = tlvf::mac_to_string(initial_radio_mac);
            // update the persistent db
            if (!update_client_entry_in_persistent_db(mac, values_map)) {
                LOG(ERROR) << "failed to update client entry in persistent-db to for " << mac;
                return false;
            }
        }
    }

    client.initial_radio = initial_radio_mac;

    return true;
}

bool db::set_sta_selected_bands(Station &client, int8_t selected_bands, bool save_to_persistent_db)
{
    auto mac                      = client.mac;
    std::shared_ptr<Station> pSta = get_station(mac);
    if (!pSta) {
        LOG(ERROR) << "Station not found for mac " << mac;
        return false;
    }

    LOG(DEBUG) << "selected_band = " << int(selected_bands);

    auto timestamp = std::chrono::system_clock::now();
    if (save_to_persistent_db) {
        // if persistent db is disabled
        if (!config.persistent_db) {
            LOG(DEBUG) << "persistent db is disabled";
        } else {
            LOG(DEBUG) << ", configuring persistent-db, selected_bands = " << selected_bands;

            ValuesMap values_map;
            values_map[TIMESTAMP_STR]      = timestamp_to_string_seconds(timestamp);
            values_map[SELECTED_BANDS_STR] = (selected_bands != PARAMETER_NOT_CONFIGURED)
                                                 ? std::to_string(selected_bands)
                                                 : std::string("");

            // update the persistent db
            if (!update_client_entry_in_persistent_db(mac, values_map)) {
                LOG(ERROR) << "failed to update client entry in persistent-db to for " << mac;
                return false;
            }
        }
    }

    client.selected_bands       = selected_bands;
    client.parameters_last_edit = timestamp;

    return true;
}

bool db::set_client_is_unfriendly(Station &client, bool client_is_unfriendly,
                                  bool save_to_persistent_db)
{
    auto mac = client.mac;

    LOG(DEBUG) << "Setting client " << mac << " client_is_unfriendly = " << client_is_unfriendly;

    if (save_to_persistent_db) {
        // if persistent db is disabled
        if (!config.persistent_db) {
            LOG(DEBUG) << "persistent db is disabled";
        } else {
            LOG(DEBUG) << "Configuring persistent-db, client_is_unfriendly = "
                       << client_is_unfriendly;

            ValuesMap values_map;
            // std::to_stringstatic_cast<bool>( would result in either "0" or "1"
            values_map[IS_UNFRIENDLY_STR] = std::to_string(client_is_unfriendly);

            // update the persistent db
            if (!update_client_entry_in_persistent_db(mac, values_map)) {
                LOG(ERROR) << "failed to update client entry in persistent-db to for " << mac;
                return false;
            }
        }
    }

    client.is_unfriendly = client_is_unfriendly ? eTriStateBool::TRUE : eTriStateBool::FALSE;

    return true;
}

bool db::clear_client_persistent_db(const sMacAddr &mac)
{
    auto client = get_station(mac);
    if (!client) {
        LOG(ERROR) << "client " << mac << " not found";
        return false;
    }

    LOG(DEBUG) << "setting client " << mac << " runtime info to default values";

    client->parameters_last_edit    = std::chrono::system_clock::time_point::min();
    client->time_life_delay_minutes = std::chrono::minutes(PARAMETER_NOT_CONFIGURED);
    client->stay_on_initial_radio   = eTriStateBool::NOT_CONFIGURED;
    client->initial_radio           = network_utils::ZERO_MAC;
    client->selected_bands          = PARAMETER_NOT_CONFIGURED;
    client->is_unfriendly           = eTriStateBool::NOT_CONFIGURED;

    // if persistent db is enabled
    if (config.persistent_db) {
        auto db_entry = client_db_entry_from_mac(mac);
        if (!bpl::db_has_entry(type_to_string(beerocks::eType::TYPE_CLIENT), db_entry)) {
            LOG(DEBUG) << "client entry does not exist in persistent-db for " << db_entry;
            return true;
        }

        LOG(DEBUG) << "removing client entry " << db_entry << " from persistent db";
        if (!remove_client_entry_and_update_counter(db_entry)) {
            LOG(ERROR) << "failed to remove client entry " << db_entry;
            return false;
        }
    }

    return true;
}

bool db::is_hostap_on_client_selected_bands(const sMacAddr &client_mac, const sMacAddr &hostap)
{
    auto radio_wifi_channel = get_radio_wifi_channel(hostap);
    if (radio_wifi_channel.is_empty()) {
        LOG(ERROR) << "empty wifi channel of " << tlvf::mac_to_string(hostap) << " in DB";
        return false;
    }

    auto client = get_station(client_mac);
    if (!client) {
        LOG(WARNING) << "client " << client_mac << " not found";
        return false;
    }
    auto selected_bands = client->selected_bands;

    if (selected_bands == PARAMETER_NOT_CONFIGURED) {
        LOG(WARNING) << "the frequency type that's used by the client is not supported";
        return false;
    }

    auto freq_type = radio_wifi_channel.get_freq_type();
    switch (freq_type) {
    case beerocks::eFreqType::FREQ_24G:
        return (selected_bands & eClientSelectedBands::eSelectedBands_24G);
    case beerocks::eFreqType::FREQ_5G:
        return (selected_bands & eClientSelectedBands::eSelectedBands_5G);
    default:
        LOG(WARNING) << "hostap band " << freq_type << " is not supported by client";
        return false;
    }
}

bool db::update_client_persistent_db(Station &client)
{
    // if persistent db is disabled
    if (!config.persistent_db) {
        LOG(ERROR) << "Persistent db is disabled";
        return false;
    }

    auto mac = client.mac;

    // any persistent parameter update also sets the last-edit timestamp
    // if it is with default value - no other persistent configuration was performed
    if (client.parameters_last_edit == std::chrono::system_clock::time_point::min()) {
        LOG(DEBUG) << "Persistent client parameters are empty for " << mac
                   << ", no need to update persistent-db";
        return true;
    }

    ValuesMap values_map;

    // fill values map of client persistent params
    values_map[TIMESTAMP_STR] = timestamp_to_string_seconds(client.parameters_last_edit);

    if (client.time_life_delay_minutes != std::chrono::minutes(PARAMETER_NOT_CONFIGURED)) {
        LOG(DEBUG) << "Setting client time-life-delay in persistent-db to "
                   << client.time_life_delay_minutes.count() << " for " << mac;
        values_map[TIMELIFE_DELAY_STR] = std::to_string(client.time_life_delay_minutes.count());
    }

    if (client.stay_on_initial_radio != eTriStateBool::NOT_CONFIGURED) {
        auto enable = (client.stay_on_initial_radio == eTriStateBool::TRUE);
        LOG(DEBUG) << "Setting client stay-on-initial-radio in persistent-db to " << enable
                   << " for " << mac;
        values_map[INITIAL_RADIO_ENABLE_STR] = std::to_string(enable);
        // initial radio should be configured only if the stay_on_initial_radio is set
        if (client.initial_radio != network_utils::ZERO_MAC) {
            LOG(DEBUG) << "Setting client initial-radio in persistent-db to "
                       << client.initial_radio << " for " << mac;
            values_map[INITIAL_RADIO_STR] = tlvf::mac_to_string(client.initial_radio);
        }
    }

    if (client.selected_bands != PARAMETER_NOT_CONFIGURED) {
        LOG(DEBUG) << "Setting client selected-bands in persistent-db to " << client.selected_bands
                   << " for " << mac;
        values_map[SELECTED_BANDS_STR] = std::to_string(client.selected_bands);
    }

    if (client.is_unfriendly != eTriStateBool::NOT_CONFIGURED) {
        auto is_unfriendly = (client.is_unfriendly == eTriStateBool::TRUE);
        LOG(DEBUG) << "Setting client is-unfriendly in persistent-db to " << is_unfriendly
                   << " for " << mac;
        values_map[IS_UNFRIENDLY_STR] = std::to_string(is_unfriendly);
    }

    // update the persistent db
    if (!update_client_entry_in_persistent_db(mac, values_map)) {
        LOG(ERROR) << "Failed to update client entry in persistent-db for " << mac;
        return false;
    }

    LOG(DEBUG) << "Client successfully updated in persistent-db for " << mac;

    return true;
}

bool db::load_persistent_db_clients()
{
    // If persistent db is disabled function should not be called
    if (!config.persistent_db) {
        LOG(ERROR) << "Persistent db is disabled";
        return false;
    }

    std::unordered_map<std::string, ValuesMap> clients;
    if (!bpl::db_get_entries_by_type(type_to_string(beerocks::eType::TYPE_CLIENT), clients)) {
        LOG(ERROR) << "Failed to get all clients from persistent DB";
        return false;
    }

    if (clients.empty()) {
        LOG(DEBUG) << "Persistent DB doesn't exist, is empty, or doesn't contain clients";
        return false;
    }

    uint16_t add_error_count = 0, set_error_count = 0, set_error_mac_count = 0;

    // move it to a vector so it can be sorted properly
    std::vector<std::pair<std::string, std::unordered_map<std::string, std::string>>>
        vector_of_clients;

    // loop through clients, then insert the rightful data to the back of vector_of_clients
    // after the checks for null mac and wrong timestamp data has been verified as false
    // it'll will be removed as well as not getting further down this function pipeline.
    std::for_each(clients.begin(), clients.end(),
                  [&](const std::pair<std::string, ValuesMap> &client_pair) {
                      auto client_entry = client_pair.first;
                      auto client_mac   = client_db_entry_to_mac(client_entry);
                      auto time         = get_client_remaining_sec(client_pair);
                      bool add          = true;

                      // Clients with invalid mac are invalid.
                      if (client_mac == network_utils::ZERO_MAC) {
                          LOG(DEBUG) << "Invalid entry - not a valid mac as client entry -"
                                     << "removing the data." << client_entry;
                          set_error_mac_count++;
                          add = false;
                      }

                      // Client is still alive?
                      if (time == 0) {
                          LOG(DEBUG) << "Filtering aged client data - client entry -"
                                     << "removing the data." << client_entry;

                          add = false;
                      }

                      if (add) {
                          vector_of_clients.push_back(client_pair);
                      } else {
                          bpl::db_remove_entry(type_to_string(beerocks::eType::TYPE_CLIENT),
                                               client_pair.first);
                      }
                  });

    // If DB is too big, we need to delete those who're close to the end of their lifespan
    int diff = vector_of_clients.size() - config.clients_persistent_db_max_size;
    auto threshold_violation_count = (diff > 0) ? diff : 0;

    if (threshold_violation_count > 0) {
        std::sort(
            std::begin(vector_of_clients), std::end(vector_of_clients),
            [&](const std::pair<std::string, std::unordered_map<std::string, std::string>> &a,
                const std::pair<std::string, std::unordered_map<std::string, std::string>> &b) {
                auto get_timestamp_sec = [](const std::pair<
                                             std::string,
                                             std::unordered_map<std::string, std::string>>
                                                &client) {
                    // A 2nd validation to assert if clients doesn't have a timestamp value
                    // since this meant to deduce the best candidate between two unaging clients.
                    // Returning db::timestamp_from_seconds(0) will automatically prioritize the
                    // trailing client assuming it has a timestamp value ofc.
                    auto timestamp_it = client.second.find(TIMESTAMP_STR);
                    if (timestamp_it == client.second.end()) {
                        return db::timestamp_from_seconds(0);
                    }

                    int64_t timestamp_sec = beerocks::string_utils::stoi(timestamp_it->second);
                    auto timestamp        = db::timestamp_from_seconds(timestamp_sec);

                    return timestamp;
                };
                auto is_not_aging =
                    [&](const std::pair<std::string, std::unordered_map<std::string, std::string>>
                            &client) -> bool {
                    auto timelife_delay_itr = client.second.find(TIMELIFE_DELAY_STR);
                    if (timelife_delay_itr != client.second.end()) {
                        if (beerocks::string_utils::stoi(timelife_delay_itr->second) == 0) {
                            return true;
                        }
                    }

                    return false;
                };

                // If both clients have time_life_delay_minutes set to not aging, evaluate
                // them by their timestamp.
                auto is_not_aging_a = is_not_aging(a);
                auto is_not_aging_b = is_not_aging(b);
                if (is_not_aging_a && is_not_aging_b) {
                    return (get_timestamp_sec(a) > get_timestamp_sec(b));
                } else if (is_not_aging_a) {
                    return true;
                } else if (is_not_aging_b) {
                    return false;
                }

                return (get_client_remaining_sec(a) > get_client_remaining_sec(b));
            });

        // remove the most aged clients from clients vector and from the persistent DB
        // to meet the persistent DB max size limit.
        std::for_each(vector_of_clients.end() - threshold_violation_count, vector_of_clients.end(),
                      [](const std::pair<std::string, std::unordered_map<std::string, std::string>>
                             &client_pair) {
                          bpl::db_remove_entry(type_to_string(beerocks::eType::TYPE_CLIENT),
                                               client_pair.first);
                      });

        vector_of_clients.erase(vector_of_clients.end() - threshold_violation_count,
                                vector_of_clients.end());
    }

    for (const auto &client : vector_of_clients) {
        // Send results to add_sta_from_data and return to increment
        // the local variable declared previously
        std::pair<uint16_t, uint16_t> result = std::make_pair(0, 0);

        db::add_sta_from_data(client.first, client.second, result);

        // If result i equals 0 it wouldn't affect the real results.
        add_error_count += result.first;
        set_error_count += result.second;
    }

    auto sum = static_cast<uint16_t>(vector_of_clients.size()) - add_error_count - set_error_count -
               threshold_violation_count;

    // Print counters
    LOG_IF(set_error_mac_count, DEBUG)
        << set_error_mac_count << " were deleted because of malformed mac address";
    LOG_IF(add_error_count, DEBUG) << "Unable to add nodes for " << add_error_count << "clients";
    LOG_IF(set_error_count, DEBUG) << "Unable to set the nodes with values from persistent db for "
                                   << set_error_count << " clients";
    LOG(DEBUG) << "Filtered: " << threshold_violation_count
               << " clients due to max DB capacity reached:"
               << " max-capacity: " << config.clients_persistent_db_max_size;
    LOG(DEBUG) << " Added " << sum << " clients successfully";

    return true;
}

std::deque<sMacAddr> db::get_clients_with_persistent_data_configured()
{
    std::deque<sMacAddr> configured_clients;
    for (const auto &station : m_stations) {
        if (has_station(station.second->mac)) {
            auto client = get_station(station.second->mac);
            if (client &&
                client->parameters_last_edit != std::chrono::system_clock::time_point::min()) {
                configured_clients.push_back(client->mac);
            }
        }
    }

    LOG_IF(configured_clients.empty(), DEBUG) << "No clients are found";

    return configured_clients;
}

//
// CLI
//
void db::add_cli_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        remove_cli_socket(sd);
        cli_debug_sockets.push_back(sd);
    }
}

void db::remove_cli_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = cli_debug_sockets.begin(); it < cli_debug_sockets.end(); it++) {
            if (sd == (*it)) {
                it = cli_debug_sockets.erase(it);
                return;
            }
        }
    }
}
bool db::get_cli_debug_enable(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = cli_debug_sockets.begin(); it < cli_debug_sockets.end(); it++) {
            if (sd == (*it)) {
                return true;
            }
        }
    }
    return false;
}

void db::set_slave_stop_on_failure_attempts(int attempts)
{
    slaves_stop_on_failure_attempts = attempts;
}

int db::get_slave_stop_on_failure_attempts() { return slaves_stop_on_failure_attempts; }

int db::get_cli_socket_at(int idx)
{
    if (idx < int(cli_debug_sockets.size())) {
        return cli_debug_sockets.at(idx);
    }
    return beerocks::net::FileDescriptor::invalid_descriptor;
}

//
// BML
//
void db::add_bml_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return;
            }
        }
        sBmlListener bml_listener = {0};
        bml_listener.sd           = sd;
        bml_listeners_sockets.push_back(bml_listener);
    }
}

void db::remove_bml_socket(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                it = bml_listeners_sockets.erase(it);
                return;
            }
        }
    }
}

bool db::get_bml_nw_map_update_enable(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return (*it).map_updates;
            }
        }
    }
    return false;
}

bool db::set_bml_topology_update_enable(int sd, bool update_enable)
{
    if (sd == beerocks::net::FileDescriptor::invalid_descriptor) {
        return false;
    }
    auto it = std::find_if(bml_listeners_sockets.begin(), bml_listeners_sockets.end(),
                           [&](const sBmlListener &element) { return element.sd == sd; });
    if (it == bml_listeners_sockets.end()) {
        LOG(ERROR) << "set_bml_topology_update_enable failed!, cannot find bml listener";
        return false;
    }
    it->topology_updates = update_enable;
    return true;
}

bool db::get_bml_topology_update_enable(int sd)
{
    if (sd == beerocks::net::FileDescriptor::invalid_descriptor) {
        return false;
    }
    auto it = std::find_if(bml_listeners_sockets.begin(), bml_listeners_sockets.end(),
                           [&](const sBmlListener &element) { return element.sd == sd; });
    if (it == bml_listeners_sockets.end()) {
        LOG(ERROR) << "set_bml_topology_update_enable failed!, cannot find bml listener";
        return false;
    }
    return it->topology_updates;
}

bool db::set_bml_nw_map_update_enable(int sd, bool update_enable)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                (*it).map_updates = update_enable;
                return true;
            }
        }
    }
    return false;
}

bool db::get_bml_stats_update_enable(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return (*it).stats_updates;
            }
        }
    }
    return false;
}

bool db::set_bml_stats_update_enable(int sd, bool update_enable)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                (*it).stats_updates = update_enable;
                return true;
            }
        }
    }
    return false;
}

bool db::get_bml_events_update_enable(int sd)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                return (*it).events_updates;
            }
        }
    }
    return false;
}

bool db::set_bml_events_update_enable(int sd, bool update_enable)
{
    if (sd != beerocks::net::FileDescriptor::invalid_descriptor) {
        for (auto it = bml_listeners_sockets.begin(); it < bml_listeners_sockets.end(); it++) {
            if (sd == (*it).sd) {
                (*it).events_updates = update_enable;
                return true;
            }
        }
    }
    return false;
}

int db::get_bml_socket_at(int idx)
{
    if (idx < int(bml_listeners_sockets.size())) {
        return bml_listeners_sockets.at(idx).sd;
    }
    return beerocks::net::FileDescriptor::invalid_descriptor;
}

bool db::is_bml_listener_exist()
{
    for (const auto &listener : bml_listeners_sockets) {
        bool listener_exist = listener.map_updates || listener.stats_updates ||
                              listener.events_updates || listener.topology_updates;
        if (listener_exist) {
            return true;
        }
    }
    return false;
}

//
// Measurements
//

bool db::set_radio_stats_info(const sMacAddr &mac, const beerocks_message::sApStatsParams *params)
{
    auto radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << "radio " << mac << " not found";
        return false;
    }

    if (params == nullptr) { // clear stats
        radio->stats_info = std::make_shared<Agent::sRadio::s_ap_stats_params>();
    } else if (radio->stats_info) {
        // Also be aware of VS messages to replace with EM messages.
        radio->stats_info->active_sta_count             = params->active_client_count;
        radio->stats_info->rx_packets                   = params->rx_packets;
        radio->stats_info->tx_packets                   = params->tx_packets;
        radio->stats_info->rx_bytes                     = params->rx_bytes;
        radio->stats_info->tx_bytes                     = params->tx_bytes;
        radio->stats_info->errors_sent                  = params->errors_sent;
        radio->stats_info->errors_received              = params->errors_received;
        radio->stats_info->retrans_count                = params->retrans_count;
        radio->stats_info->noise                        = params->noise;
        radio->stats_info->channel_load_percent         = params->channel_load_percent;
        radio->stats_info->total_client_tx_load_percent = params->client_tx_load_percent;
        radio->stats_info->total_client_rx_load_percent = params->client_rx_load_percent;
        radio->stats_info->stats_delta_ms               = params->stats_delta_ms;
        radio->stats_info->timestamp                    = std::chrono::steady_clock::now();
    }

    return true;
}

void db::clear_radio_stats_info(const sMacAddr &al_mac, const sMacAddr &mac)
{
    set_radio_stats_info(mac, nullptr);
}

bool db::dm_check_objects_limit(std::queue<std::string> &paths, uint8_t limit)
{
    while (limit <= paths.size()) {
        std::string obj_path = paths.front();
        auto path            = get_dm_index_from_path(obj_path);

        if (!m_ambiorix_datamodel->remove_instance(path.first, path.second)) {
            LOG(ERROR) << "Failed to remove " << obj_path;
            return false;
        }
        paths.pop();
    }
    return true;
}

bool db::notify_sta_disconnection(const std::string &client_mac, const uint16_t reason_code,
                                  const std::string &bssid)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(client_mac));
    if (!pSta) {
        LOG(ERROR) << "Station not found for mac " << client_mac;
        return false;
    }

    std::string path_to_disassoc_event_data =
        CONTROLLER_ROOT_DM ".DisassociationEvent.DisassociationEventData";

    if (!dm_check_objects_limit(m_disassoc_events, MAX_EVENT_HISTORY_SIZE)) {
        return false;
    }

    std::string path_to_eventdata = m_ambiorix_datamodel->add_instance(path_to_disassoc_event_data);

    if (path_to_eventdata.empty()) {
        return false;
    }

    m_disassoc_events.push(path_to_eventdata);

    bool ret_val = true;

    ret_val &= m_ambiorix_datamodel->set(path_to_eventdata, "BSSID", bssid);
    ret_val &= m_ambiorix_datamodel->set(path_to_eventdata, "MACAddress", client_mac);
    ret_val &= m_ambiorix_datamodel->set(path_to_eventdata, "ReasonCode", reason_code);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_eventdata, "BytesSent", pSta->stats_info->tx_bytes);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_eventdata, "BytesReceived", pSta->stats_info->rx_bytes);
    ret_val &=
        m_ambiorix_datamodel->set(path_to_eventdata, "PacketsSent", pSta->stats_info->tx_packets);
    ret_val &= m_ambiorix_datamodel->set(path_to_eventdata, "PacketsReceived",
                                         pSta->stats_info->rx_packets);

    // ErrorsSent and ErrorsReceived are not available yet on stats_info
    ret_val &= m_ambiorix_datamodel->set(path_to_eventdata, "ErrorsSent", static_cast<uint32_t>(0));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_eventdata, "ErrorsReceived", static_cast<uint32_t>(0));
    ret_val &= m_ambiorix_datamodel->set(path_to_eventdata, "RetransCount",
                                         pSta->stats_info->retrans_count);
    ret_val &= m_ambiorix_datamodel->set_current_time(path_to_eventdata);

    return ret_val;
}

bool db::set_sta_stats_info(const sMacAddr &mac, const beerocks_message::sStaStatsParams *params)

{
    std::shared_ptr<Station> pSta = get_station(mac);
    if (!pSta) {
        return false;
    }
    if (params == nullptr) { // clear stats
        pSta->clear_sta_stats_info();
    } else {
        auto pStats = pSta->stats_info;
        if (!pStats) {
            LOG(ERROR) << "station: " << mac << " has no stats_info!";
            return false;
        }
        pStats->rx_packets        = params->rx_packets;
        pStats->tx_packets        = params->tx_packets;
        pStats->tx_bytes          = params->tx_bytes;
        pStats->rx_bytes          = params->rx_bytes;
        pStats->retrans_count     = params->retrans_count;
        pStats->tx_phy_rate_100kb = params->tx_phy_rate_100kb;
        pStats->rx_phy_rate_100kb = params->rx_phy_rate_100kb;
        pStats->tx_load_percent   = params->tx_load_percent;
        pStats->rx_load_percent   = params->rx_load_percent;
        pStats->stats_delta_ms    = params->stats_delta_ms;
        pStats->rx_rssi           = params->rx_rssi;
        pStats->timestamp         = std::chrono::steady_clock::now();
    }
    return true;
}

void db::clear_sta_stats_info(const sMacAddr &mac) { set_sta_stats_info(mac, nullptr); }

bool db::set_vap_stats_info(const sMacAddr &bssid, uint64_t uc_tx_bytes, uint64_t uc_rx_bytes,
                            uint64_t mc_tx_bytes, uint64_t mc_rx_bytes, uint64_t bc_tx_bytes,
                            uint64_t bc_rx_bytes)
{
    auto bss = get_bss(bssid);
    if (!bss) {
        LOG(ERROR) << "Failed to get BSS with BSSID: " << bssid;
        return false;
    }
    if (bss->dm_path.empty()) {
        return true;
    }

    bool ret_val = true;

    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "UnicastBytesSent", uc_tx_bytes);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "UnicastBytesReceived", uc_rx_bytes);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "MulticastBytesSent", mc_tx_bytes);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "MulticastBytesReceived", mc_rx_bytes);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "BroadcastBytesSent", bc_tx_bytes);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "BroadcastBytesReceived", bc_rx_bytes);

    m_ambiorix_datamodel->set_current_time(bss->dm_path);

    return ret_val;
}

bool db::commit_persistent_db_changes()
{
    bool ret = bpl::db_commit_changes();

    if (ret) {
        persistent_db_changes_made = false;
    }

    return ret;
}

bool db::is_commit_to_persistent_db_required() { return persistent_db_changes_made; }

int db::get_radio_stats_measurement_duration(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return -1;
    }
    return radio->stats_info->stats_delta_ms;
}

std::chrono::steady_clock::time_point db::get_radio_stats_info_timestamp(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        std::chrono::steady_clock::time_point();
    }
    return radio->stats_info->timestamp;
}

uint32_t db::get_sta_rx_bytes(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        return -1;
    }
    return pSta->stats_info->rx_bytes;
}

uint32_t db::get_sta_tx_bytes(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        return -1;
    }
    return pSta->stats_info->tx_bytes;
}

uint32_t db::get_radio_total_sta_rx_bytes(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return -1;
    }
    return radio->stats_info->rx_bytes;
}

uint32_t db::get_radio_total_sta_tx_bytes(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return -1;
    }
    return radio->stats_info->tx_bytes;
}

double db::get_sta_rx_bitrate(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return (1000 * 8 * double(pSta->stats_info->rx_bytes) / pSta->stats_info->stats_delta_ms) /
           1e+6;
}

double db::get_sta_tx_bitrate(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return (1000 * 8 * double(pSta->stats_info->tx_bytes) / pSta->stats_info->stats_delta_ms) /
           1e+6;
}

uint16_t db::get_sta_rx_phy_rate_100kb(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->rx_phy_rate_100kb;
}

uint16_t db::get_sta_tx_phy_rate_100kb(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->tx_phy_rate_100kb;
}

int db::get_radio_channel_load_percent(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return -1;
    }
    return radio->stats_info->channel_load_percent;
}

int db::get_radio_total_client_tx_load_percent(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return -1;
    }
    return radio->stats_info->total_client_tx_load_percent;
}

int db::get_radio_total_client_rx_load_percent(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << mac << " does not exist!";
        return -1;
    }
    return radio->stats_info->total_client_rx_load_percent;
}

int db::get_sta_rx_load_percent(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->rx_load_percent;
}

int db::get_sta_tx_load_percent(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->tx_load_percent;
}

int8_t db::get_sta_load_rx_rssi(const std::string &sta_mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(sta_mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << sta_mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->rx_rssi;
}

uint16_t db::get_sta_load_rx_phy_rate_100kb(const std::string &sta_mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(sta_mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << sta_mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->rx_phy_rate_100kb;
}

uint16_t db::get_sta_load_tx_phy_rate_100kb(const std::string &sta_mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(sta_mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << sta_mac << " does not exist!";
        return -1;
    }
    return pSta->stats_info->tx_phy_rate_100kb;
}

bool db::set_measurement_delay(const std::string &mac, int measurement_delay)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return false;
    }
    radio->measurement_delay = measurement_delay;
    LOG(DEBUG) << "set_measurement_delay: mac " << mac
               << " n->measurement_delay = " << int(radio->measurement_delay);
    return true;
}

int db::get_measurement_delay(const std::string &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return -1;
    }
    return radio->measurement_delay;
}

bool db::set_measurement_sent_timestamp(const std::string &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return false;
    }
    radio->measurement_sent_timestamp = std::chrono::steady_clock::now();
    LOG(DEBUG) << "set_measurement_sent_timestamp: mac " << mac;
    return true;
}

int db::get_measurement_recv_delta(const std::string &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return -1;
    }
    LOG(DEBUG) << "get_measurement_recv_delta: mac " << mac
               << " radio->measurement_recv_delta = " << int(radio->measurement_recv_delta)
               << " actual delay = " << int((radio->measurement_recv_delta / 2));
    return radio->measurement_recv_delta;
}

bool db::set_measurement_recv_delta(const std::string &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return false;
    }
    auto measurement_recv_timestamp = std::chrono::steady_clock::now();
    radio->measurement_recv_delta =
        std::chrono::duration_cast<std::chrono::milliseconds>(measurement_recv_timestamp -
                                                              radio->measurement_sent_timestamp)
            .count();
    return true;
}

int db::get_measurement_window_size(const std::string &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return -1;
    }
    return radio->measurement_window_size;
}

bool db::set_measurement_window_size(const std::string &mac, int window_size)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(tlvf::mac_from_string(mac));
    if (!radio) {
        return false;
    }
    radio->measurement_window_size = window_size;
    return true;
}

beerocks::WifiChannel db::get_radio_wifi_channel(const sMacAddr &radio_mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "No Radio found with MAC " << radio_mac;
        return {};
    }
    LOG(DEBUG) << "Get Radio wifiChannel channel " << radio->wifi_channel.get_channel()
               << " bandwidth " << radio->wifi_channel.get_bandwidth();
    return radio->wifi_channel;
}

bool db::set_radio_wifi_channel(const sMacAddr &radio_mac,
                                const beerocks::WifiChannel &wifi_channel)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        return false;
    }

    LOG(INFO) << "Set Radio " << radio_mac << ", previous wifiChannel: " << radio->wifi_channel
              << ", current wifiChannel: " << wifi_channel;
    radio->wifi_channel = wifi_channel;

    radio->operating_class = son::wireless_utils::get_operating_class_by_channel(wifi_channel);
    if (radio->operating_class == 0) {
        LOG(ERROR) << "failed to get operating class of " << wifi_channel;
    }

    switch (radio->wifi_channel.get_freq_type()) {
    case eFreqType::FREQ_24G: {
        radio->supports_24ghz = true;
    } break;
    case eFreqType::FREQ_5G: {
        radio->supports_5ghz = true;
    } break;
    case eFreqType::FREQ_6G: {
        radio->supports_6ghz = true;
    } break;
    default:
        LOG(ERROR) << "frequency type unknown, channel=" << radio->wifi_channel.get_channel();
        break;
    }

    return true;
}

bool db::set_sta_wifi_channel(const sMacAddr &sta_mac, const beerocks::WifiChannel &wifi_channel)
{
    std::shared_ptr<Station> pSta = get_station(sta_mac);
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << sta_mac << " does not exist!";
        return false;
    }

    LOG(INFO) << "Set Station " << sta_mac << ", previous wifiChannel: " << pSta->wifi_channel
              << ", current wifiChannel: " << wifi_channel;
    pSta->wifi_channel = wifi_channel;

    pSta->operating_class = son::wireless_utils::get_operating_class_by_channel(wifi_channel);
    if (pSta->operating_class == 0) {
        LOG(ERROR) << "failed to get operating class of " << wifi_channel;
    }

    switch (pSta->wifi_channel.get_freq_type()) {
    case eFreqType::FREQ_24G: {
        LOG(DEBUG) << "Station supports 2.4GHz";
        pSta->supports_24ghz = true;
    } break;
    case eFreqType::FREQ_5G: {
        LOG(DEBUG) << "Station supports 5GHz";
        pSta->supports_5ghz = true;
    } break;
    case eFreqType::FREQ_6G: {
        LOG(DEBUG) << "Station supports 6GHz";
        pSta->supports_6ghz = true;
    } break;
    default:
        LOG(ERROR) << "frequency type unknown, channel=" << pSta->wifi_channel.get_channel();
        break;
    }

    return true;
}

beerocks::WifiChannel db::get_sta_wifi_channel(const std::string &mac)
{
    std::shared_ptr<Station> pSta = get_station(tlvf::mac_from_string(mac));
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return {};
    }
    LOG(DEBUG) << "Get Station wifiChannel channel " << pSta->wifi_channel.get_channel()
               << " bandwidth " << pSta->wifi_channel.get_bandwidth();
    return pSta->wifi_channel;
}

bool db::update_sta_wifi_channel_bw(const sMacAddr &mac, beerocks::eWiFiBandwidth bw)
{
    std::shared_ptr<Station> pSta = get_station(mac);
    if (!pSta) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    if (pSta->wifi_channel.get_freq_type() == eFreqType::FREQ_UNKNOWN) {
        LOG(ERROR) << "frequency type of station " << mac
                   << " is unknown, channel=" << int(pSta->wifi_channel.get_channel());
        return false;
    }

    if (bw == eWiFiBandwidth::BANDWIDTH_UNKNOWN) {
        LOG(ERROR) << "the new bandwidth of station " << mac << " can't be unknown";
        return false;
    }

    if (bw == pSta->wifi_channel.get_bandwidth()) {
        return true;
    }

    if (bw == eWiFiBandwidth::BANDWIDTH_MAX) {
        LOG(INFO) << "update wifiChannel station " << mac << " bw from "
                  << beerocks::utils::convert_bandwidth_to_int(pSta->wifi_channel.get_bandwidth())
                  << "MHz to MAX";
    } else {
        LOG(INFO) << "update wifiChannel station " << mac << " bw from "
                  << beerocks::utils::convert_bandwidth_to_int(pSta->wifi_channel.get_bandwidth())
                  << " to " << bw;
    }

    eWiFiBandwidth prev_bw = pSta->wifi_channel.get_bandwidth();
    pSta->wifi_channel.set_bandwidth(bw);
    LOG(INFO) << "updating station " << mac << " bandwidth from "
              << beerocks::utils::convert_bandwidth_to_int(prev_bw) << "MHz to "
              << beerocks::utils::convert_bandwidth_to_int(bw) << "MHz";
    return true;
}

//
// tasks
//

bool db::assign_agent_load_balancer_task_id(const sMacAddr &mac, int new_task_id)
{
    std::shared_ptr<Agent> agent = get_agent(mac);
    if (!agent) {
        LOG(WARNING) << __FUNCTION__ << " - agent " << mac << " does not exist!";
        return false;
    }
    agent->load_balancer_task_id = new_task_id;
    return true;
}

int db::get_agent_load_balancer_task_id(const sMacAddr &mac)
{
    std::shared_ptr<Agent> agent = get_agent(mac);
    if (!agent) {
        LOG(WARNING) << __FUNCTION__ << " - agent " << mac << " does not exist!";
        return -1;
    }
    return agent->load_balancer_task_id;
}

bool db::assign_station_load_balancer_task_id(const sMacAddr &mac, int new_task_id)
{
    std::shared_ptr<Station> station = get_station(mac);
    if (!station) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return false;
    }
    station->load_balancer_task_id = new_task_id;
    return true;
}

int db::get_station_load_balancer_task_id(const sMacAddr &mac)
{
    std::shared_ptr<Station> station = get_station(mac);
    if (!station) {
        LOG(WARNING) << __FUNCTION__ << " - station " << mac << " does not exist!";
        return -1;
    }
    return station->load_balancer_task_id;
}

bool db::assign_channel_selection_task_id(int new_task_id)
{
    channel_selection_task_id = new_task_id;
    return true;
}

int db::get_channel_selection_task_id()
{
    if (!(channel_selection_task_id > 0))
        LOG(INFO) << "channel_selection_task not running";

    return channel_selection_task_id;
}

bool db::assign_network_optimization_task_id(int new_task_id)
{
    network_optimization_task_id = new_task_id;
    return true;
}

int db::get_network_optimization_task_id() { return network_optimization_task_id; }

bool db::assign_bml_task_id(int new_task_id)
{
    bml_task_id = new_task_id;
    return true;
}

int db::get_bml_task_id() { return bml_task_id; }

bool db::assign_pre_association_steering_task_id(int new_task_id)
{
    pre_association_steering_task_id = new_task_id;
    return true;
}

int db::get_pre_association_steering_task_id() { return pre_association_steering_task_id; }

bool db::assign_agent_monitoring_task_id(int new_task_id)
{
    agent_monitoring_task_id = new_task_id;
    return true;
}

int db::get_agent_monitoring_task_id() { return agent_monitoring_task_id; }

bool db::assign_dynamic_channel_selection_task_id(const sMacAddr &mac, int new_task_id)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << tlvf::mac_to_string(mac)
                     << " does not exist!";
        return false;
    }
    radio->dynamic_channel_selection_task_id = new_task_id;
    return true;
}

int db::get_dynamic_channel_selection_task_id(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sRadio> radio = get_radio_by_uid(mac);
    if (!radio) {
        LOG(WARNING) << __FUNCTION__ << " - radio " << tlvf::mac_to_string(mac)
                     << " does not exist!";
        return -1;
    }
    return radio->dynamic_channel_selection_task_id;
}

bool db::assign_dynamic_channel_selection_r2_task_id(int new_task_id)
{
    dynamic_channel_selection_r2_task_id = new_task_id;
    return true;
}

int db::get_dynamic_channel_selection_r2_task_id()
{
    if (!(dynamic_channel_selection_r2_task_id > 0))
        LOG(INFO) << "dynamic_channel_selection_r2_task not running";

    return dynamic_channel_selection_r2_task_id;
}

bool db::assign_persistent_db_aging_operation_id(int new_operation_id)
{
    persistent_db_aging_operation_id = new_operation_id;
    return true;
}
int db::get_persistent_db_aging_operation_id() { return persistent_db_aging_operation_id; }

bool db::assign_persistent_db_data_commit_operation_id(int new_operation_id)
{
    persistent_db_data_commit_operation_id = new_operation_id;
    return true;
}

int db::get_persistent_db_data_commit_operation_id()
{
    return persistent_db_data_commit_operation_id;
}

bool db::assign_dhcp_task_id(int new_task_id)
{
    dhcp_task_id = new_task_id;
    return true;
}

int db::get_dhcp_task_id() { return dhcp_task_id; }

bool db::assign_statistics_polling_task_id(int new_task_id)
{
    statistics_polling_task_id = new_task_id;
    return true;
}

int db::get_statistics_polling_task_id() { return statistics_polling_task_id; }

bool db::assign_vbss_task_id(const int new_task_id)
{
    vbss_task_id = new_task_id;
    return true;
}
int db::get_vbss_task_id() { return vbss_task_id; }

bool db::assign_link_metrics_task_id(int new_task_id)
{
    link_metrics_task_id = new_task_id;
    return true;
}

int db::get_link_metrics_task_id() { return link_metrics_task_id; }
void db::lock() { db_mutex.lock(); }

void db::unlock() { db_mutex.unlock(); }

void db::add_bss_info_configuration(const sMacAddr &al_mac,
                                    const wireless_utils::sBssInfoConf &bss_info)
{
    bss_infos[al_mac].push_back(bss_info);
}

void db::add_bss_info_configuration(const wireless_utils::sBssInfoConf &bss_info)
{
    bss_infos_global.push_back(bss_info);
}

void db::add_configured_bss_info(const sMacAddr &ruid, const wireless_utils::sBssInfoConf &bss_info)
{
    configured_bss_infos[ruid].push_back(bss_info);
}

std::list<wireless_utils::sBssInfoConf> &db::get_bss_info_configuration(const sMacAddr &al_mac)
{
    // If al_mac not exist, it will be added, and return empty list
    if (bss_infos[al_mac].empty()) {
        return bss_infos_global;
    } else {
        return bss_infos[al_mac];
    }
}

std::list<wireless_utils::sBssInfoConf> &db::get_bss_info_configuration()
{
    return bss_infos_global;
}

std::list<wireless_utils::sBssInfoConf> &db::get_configured_bss_info(const sMacAddr &ruid)
{
    return configured_bss_infos[ruid];
}

void db::clear_bss_info_configuration()
{
    bss_infos.clear();
    bss_infos_global.clear();
}

void db::clear_bss_info_configuration(const sMacAddr &al_mac) { bss_infos[al_mac].clear(); }

void db::clear_configured_bss_info(const sMacAddr &ruid) { configured_bss_infos[ruid].clear(); }

void db::add_traffic_separation_configuration(const sMacAddr &al_mac,
                                              const wireless_utils::sTrafficSeparationSsid &config)
{
    traffic_separation_policy_configurations[al_mac].push_back(config);
}

void db::add_default_8021q_settings(const sMacAddr &al_mac,
                                    const wireless_utils::s8021QSettings &config)
{
    default_8021q_settings[al_mac] = config;
}

const std::list<wireless_utils::sTrafficSeparationSsid>
db::get_traffic_separation_configuration(const sMacAddr &al_mac)
{
    auto config = traffic_separation_policy_configurations.find(al_mac);
    if (config != traffic_separation_policy_configurations.end()) {
        return config->second;
    }

    return std::list<wireless_utils::sTrafficSeparationSsid>();
}
wireless_utils::s8021QSettings db::get_default_8021q_setting(const sMacAddr &al_mac)
{
    auto config = default_8021q_settings.find(al_mac);
    if (config != default_8021q_settings.end()) {
        return config->second;
    }

    return wireless_utils::s8021QSettings();
}

void db::clear_traffic_separation_configurations()
{
    traffic_separation_policy_configurations.clear();
}

void db::clear_traffic_separation_configurations(const sMacAddr &al_mac)
{
    traffic_separation_policy_configurations.erase(al_mac);
}

void db::clear_default_8021q_settings() { default_8021q_settings.clear(); }

void db::clear_default_8021q_settings(const sMacAddr &al_mac)
{
    default_8021q_settings.erase(al_mac);
}

void db::disable_periodic_link_metrics_requests()
{
    config.link_metrics_request_interval_seconds = std::chrono::seconds::zero();

    beerocks::bpl::cfg_set_link_metrics_request_interval(
        config.link_metrics_request_interval_seconds);

    m_ambiorix_datamodel->set(CONTROLLER_ROOT_DM ".Configuration", "LinkMetricsRequestInterval",
                              config.link_metrics_request_interval_seconds.count());
}

bool db::dm_set_sta_link_metrics(const sMacAddr &sta_mac, uint32_t downlink_est_mac_data_rate,
                                 uint32_t uplink_est_mac_data_rate, uint8_t signal_strength)
{
    auto station = get_station(sta_mac);
    if (!station) {
        LOG(ERROR) << "Failed to get station on db with mac: " << sta_mac;
        return false;
    }

    // Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.
    if (station->dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "EstMACDataRateDownlink",
                                         downlink_est_mac_data_rate);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "EstMACDataRateUplink",
                                         uplink_est_mac_data_rate);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "SignalStrength", signal_strength);

    return ret_val;
}

//
// PRIVATE FUNCTIONS
//   must be used from a thread safe context
//
int db::get_agent_hierarchy(const sMacAddr &al_mac)
{
    std::shared_ptr<Agent> agent = get_agent(al_mac);
    if (!agent) {
        return -1;
    } else {
        std::shared_ptr<Agent> parent_agent = agent->backhaul.parent_agent.lock();
        if (parent_agent) {
            return get_agent_hierarchy(parent_agent->al_mac) + 1;
        } else {
            return 0;
        }
    }
}

std::shared_ptr<Agent::sRadio> db::get_radio_by_uid(const sMacAddr &radio_uid)
{
    for (const auto &agent : m_agents) {
        auto radio = agent.second->radios.get(radio_uid);
        if (radio) {
            return radio;
        }
    }

    LOG(ERROR) << "radio " << radio_uid << " not found";
    return {};
}

std::shared_ptr<Agent::sRadio::sBss> db::get_bss(const sMacAddr &bssid, const sMacAddr &al_mac)
{
    for (const auto &agent : m_agents) {
        if (al_mac != beerocks::net::network_utils::ZERO_MAC && al_mac != agent.second->al_mac) {
            continue;
        }
        for (const auto &radio : agent.second->radios) {
            auto bss = radio.second->bsses.get(bssid);
            if (bss) {
                return bss;
            }
        }
    }
    LOG(INFO) << "BSS " << bssid << " not found in db";
    return {};
}

std::shared_ptr<Station> db::get_station(const sMacAddr &mac)
{
    auto station = m_stations.get(mac);
    if (!station) {
        LOG(WARNING) << "station " << mac << " not found";
        return {};
    }

    return station;
}

void db::set_vap_list(std::shared_ptr<db::vaps_list_t> vaps_list) { m_vap_list = vaps_list; }

void db::clear_vap_list()
{
    if (m_vap_list) {
        m_vap_list.reset();
    }
}

const std::shared_ptr<db::vaps_list_t> db::get_vap_list() { return m_vap_list; }

bool db::is_prplmesh(const sMacAddr &mac)
{
    std::shared_ptr<Agent> agent = get_agent(mac);
    if (!agent) {
        LOG(ERROR) << "can't find agent with mac " << mac << ", consider as not prplmesh";
        return false;
    }
    return agent->is_prplmesh;
}

void db::set_prplmesh(const sMacAddr &mac)
{
    auto local_bridge_mac        = get_local_bridge_mac();
    std::shared_ptr<Agent> agent = get_agent(mac);
    if (!agent) {
        if (local_bridge_mac == mac) {
            agent = add_gateway(mac);
        } else {
            agent = add_agent(mac);
        }
    }

    if (agent) {
        agent->is_prplmesh = true;
    }
}

bool db::update_client_entry_in_persistent_db(const sMacAddr &mac, const ValuesMap &values_map)
{
    auto db_entry        = client_db_entry_from_mac(mac);
    auto type_client_str = type_to_string(beerocks::eType::TYPE_CLIENT);

    if (!bpl::db_has_entry(type_client_str, db_entry)) {
        if (!add_client_to_persistent_db(mac, values_map)) {
            LOG(ERROR) << "failed to add client entry in persistent-db for " << mac;
            return false;
        }
    } else if (!bpl::db_set_entry(type_client_str, db_entry, values_map)) {
        LOG(ERROR) << "failed to set client in persistent-db for " << mac;
        return false;
    }

    persistent_db_changes_made = true;

    return true;
}

bool db::set_sta_params_from_map(const sMacAddr &mac, const ValuesMap &values_map)
{
    auto client = get_station(mac);
    if (!client) {
        LOG(WARNING) << "client " << mac << " not found";
        return false;
    }

    auto initial_radio = network_utils::ZERO_MAC;

    for (const auto &param : values_map) {
        if (param.first == TIMESTAMP_STR) {
            LOG(DEBUG) << "Setting client parameters_last_edit to " << param.second << " for "
                       << mac;
            client->parameters_last_edit = timestamp_from_seconds(string_utils::stoi(param.second));
        } else if (param.first == TIMELIFE_DELAY_STR) {
            LOG(DEBUG) << "Setting client_time_life_delay_sec to " << param.second << " for "
                       << mac;
            client->time_life_delay_minutes =
                std::chrono::minutes(string_utils::stoi(param.second));
        } else if (param.first == INITIAL_RADIO_ENABLE_STR) {
            LOG(DEBUG) << "Setting client stay_on_initial_radio to " << param.second << " for "
                       << mac;
            client->stay_on_initial_radio =
                (param.second == "1") ? eTriStateBool::TRUE : eTriStateBool::FALSE;
        } else if (param.first == INITIAL_RADIO_STR) {
            LOG(DEBUG) << "Received client_initial_radio=" << param.second << " for " << mac;
            initial_radio = tlvf::mac_from_string(param.second);
        } else if (param.first == SELECTED_BANDS_STR) {
            LOG(DEBUG) << "Setting client selected_bands to " << param.second << " for " << mac;
            client->selected_bands = string_utils::stoi(param.second);
        } else if (param.first == IS_UNFRIENDLY_STR) {
            LOG(DEBUG) << "Setting client is_unfriendly to " << param.second << " for " << mac;
            client->is_unfriendly =
                (param.second == std::to_string(true)) ? eTriStateBool::TRUE : eTriStateBool::FALSE;
        } else {
            LOG(WARNING) << "Unknown parameter, skipping: " << param.first << " for " << mac;
        }
    }

    // After configuring the values we can determine if the client_initial_radio should be set as well.
    // Since its value is only relevant if stay_on_initial_radio is set.
    // clear initial-radio data on disabling of stay_on_initial_radio.
    if (client->stay_on_initial_radio != eTriStateBool::TRUE) {
        LOG_IF((initial_radio != network_utils::ZERO_MAC), WARNING)
            << "ignoring initial-radio=" << initial_radio
            << " since stay-on-initial-radio is not enabled";
        client->initial_radio = network_utils::ZERO_MAC;
    } else if (initial_radio != network_utils::ZERO_MAC) {
        // If stay-on-initial-radio is set to enable and initial_radio is provided.
        client->initial_radio = initial_radio;
    } else if (client->state == STATE_CONNECTED) {
        // If stay-on-initial-radio is enabled and initial_radio is not set and client is already connected:
        // Set the initial_radio from parent radio mac (not bssid).
        std::shared_ptr<Agent::sRadio::sBss> parent_bss = client->get_bss();
        client->initial_radio                           = parent_bss->radio.radio_uid;
        LOG(DEBUG) << "Setting client " << mac << " initial-radio to " << client->initial_radio;
    }

    return true;
}

bool db::add_client_entry_and_update_counter(const std::string &entry_name,
                                             const ValuesMap &values_map)
{
    if (!bpl::db_add_entry(type_to_string(beerocks::eType::TYPE_CLIENT), entry_name, values_map)) {
        LOG(ERROR) << "failed to add client entry " << entry_name << " to persistent db";
        return false;
    }

    ++m_persistent_db_clients_count;

    return true;
}

bool db::remove_client_entry_and_update_counter(const std::string &entry_name)
{
    if (!bpl::db_remove_entry(type_to_string(beerocks::eType::TYPE_CLIENT), entry_name)) {
        LOG(ERROR) << "failed to remove entry " << entry_name << "from persistent db";
        return false;
    }
    --m_persistent_db_clients_count;

    LOG(DEBUG) << "Removed client entry " << entry_name
               << " from persistent db, total clients count in persisttent-db: "
               << m_persistent_db_clients_count;

    persistent_db_changes_made = true;

    return true;
}

bool db::remove_candidate_client(sMacAddr client_to_skip)
{

    // find cadidate client to be removed
    const sMacAddr &client_to_remove = get_candidate_client_for_removal(client_to_skip);
    if (client_to_remove == network_utils::ZERO_MAC) {
        LOG(ERROR) << "failed to find client to be removed, number of persistent db clients is "
                   << m_persistent_db_clients_count;
        return false;
    }

    // clear persistent data in runtime db and remove from persistent db
    if (!clear_client_persistent_db(client_to_remove)) {
        LOG(ERROR) << "failed to clear client persistent data and remove it from persistent db";
        return false;
    }

    return true;
}

sMacAddr db::get_candidate_client_for_removal(sMacAddr client_to_skip)
{
    const auto max_timelife_delay_sec =
        std::chrono::seconds(config.max_timelife_delay_minutes * 60);
    const auto unfriendly_device_max_timelife_delay_sec =
        std::chrono::seconds(config.unfriendly_device_max_timelife_delay_minutes * 60);

    sMacAddr candidate_client_to_be_removed  = network_utils::ZERO_MAC;
    bool is_disconnected_candidate_available = false;
    bool is_aging_candidate_available        = false;
    auto candidate_client_expiry_due_time    = std::chrono::system_clock::time_point::max();

    for (const auto &station : m_stations) {
        if (has_station(station.second->mac)) {
            const auto client     = station.second;
            const auto client_mac = station.first;

            auto pSta = get_station(client_mac);
            if (!pSta) {
                LOG(WARNING) << "client " << client_mac << " not found";
                continue;
            }

            // skip client if matches the provided client to skip
            if (client_mac == client_to_skip) {
                continue;
            }
            //TODO: improvement - stop search if "already-aged" candidate is found (don't-care of connectivity status)

            // Skip clients which have no persistent information.
            if (pSta->parameters_last_edit == std::chrono::system_clock::time_point::min()) {
                continue;
            }

            // Max client timelife delay
            // This is ditermined according to the friendliness status of the client.
            // If a client is unfriendly we can
            auto selected_max_timelife_delay_sec = (pSta->is_unfriendly == eTriStateBool::TRUE)
                                                       ? unfriendly_device_max_timelife_delay_sec
                                                       : max_timelife_delay_sec;

            // Client timelife delay
            auto timelife_delay_sec = (pSta->time_life_delay_minutes !=
                                       std::chrono::seconds(beerocks::PARAMETER_NOT_CONFIGURED))
                                          ? std::chrono::seconds(pSta->time_life_delay_minutes)
                                          : selected_max_timelife_delay_sec;

            // Calculate client expiry due time.
            // In case both clients are non-aging - both time-life will be 0 - so only the
            // last-edit-time will affect the candidate selected.
            auto current_client_expiry_due_time = pSta->parameters_last_edit + timelife_delay_sec;

            // Preferring non-aging clients over aging ones (even if disconnected).
            // If client is non-aging and candidate is aging - skip it
            if (is_aging_candidate_available &&
                pSta->time_life_delay_minutes == std::chrono::seconds::zero()) {
                continue;
            }

            // Previous candidate is not aging and current client is aging - replace candidate
            if (!is_aging_candidate_available &&
                (pSta->time_life_delay_minutes > std::chrono::seconds::zero())) {
                // Update candidate
                candidate_client_to_be_removed = client_mac;
                // Set the candidate client expiry due time for later comparison
                candidate_client_expiry_due_time = current_client_expiry_due_time;
                // Set aging-candidate-available
                is_aging_candidate_available = true;
                // Set disconnected-candidate-available
                is_disconnected_candidate_available = (pSta->state == beerocks::STATE_DISCONNECTED);
                continue;
            }

            // Preferring disconnected clients over connected ones (even if less aged).
            if (is_disconnected_candidate_available &&
                pSta->state != beerocks::STATE_DISCONNECTED) {
                continue;
            }

            // Compare to currently chosen candidate expiry due time.
            // All other parameters that affect the candidate selection are already handled above
            if (current_client_expiry_due_time < candidate_client_expiry_due_time) {
                // Set the candidate client expiry due time for later comparison
                candidate_client_expiry_due_time = current_client_expiry_due_time;
                // Set the candidate client
                candidate_client_to_be_removed = client_mac;
                // Set disconnected-candidate-available
                is_disconnected_candidate_available = (pSta->state == beerocks::STATE_DISCONNECTED);
            }
        }
    }

    if (candidate_client_to_be_removed == network_utils::ZERO_MAC) {
        LOG(DEBUG) << "no client to be removed is found";
    } else {
        LOG(DEBUG) << "candidate client to be removed " << candidate_client_to_be_removed
                   << " is currently "
                   << ((is_disconnected_candidate_available) ? "disconnected" : "connected");
    }

    return candidate_client_to_be_removed;
}

void db::add_sta_from_data(const std::string &client_entry, const ValuesMap &values_map,
                           std::pair<uint16_t, uint16_t> &result)
{
    auto client_mac = client_db_entry_to_mac(client_entry);

    // Add client node with defaults and in default location
    LOG(DEBUG) << "Adding station node from data: " << client_mac;

    if (!add_station(network_utils::ZERO_MAC, client_mac)) {
        LOG(ERROR) << "Failed to add client node for client_entry " << client_entry;
        result.first = 1;
        return;
    }

    // Set clients persistent information in the node
    if (!set_sta_params_from_map(client_mac, values_map)) {
        LOG(ERROR) << "Failed to set client " << client_entry
                   << " node in runtime db with values read from persistent db: " << values_map;
        result.second = 1;
        return;
    }

    LOG(DEBUG) << "Client " << client_entry
               << " added successfully to node-list with parameters: " << values_map;

    // Update the number of clients in persistent DB
    ++m_persistent_db_clients_count;
}

uint64_t db::get_client_remaining_sec(const std::pair<std::string, ValuesMap> &client)
{
    static const int max_timelife_delay_sec = config.max_timelife_delay_minutes * 60;
    static const int unfriendly_device_max_timelife_delay_sec =
        config.unfriendly_device_max_timelife_delay_minutes * 60;

    auto timestamp_it = client.second.find(TIMESTAMP_STR);
    if (timestamp_it == client.second.end())
        return 0;

    // Save current time as a separate variable for fair comparison of current client
    auto now           = std::chrono::system_clock::now();
    auto timestamp_sec = beerocks::string_utils::stoi(timestamp_it->second);
    auto timestamp     = db::timestamp_from_seconds(timestamp_sec);
    auto client_timelife_passed_sec =
        std::chrono::duration_cast<std::chrono::seconds>(now - timestamp).count();

    auto client_remaining_timelife_sec = max_timelife_delay_sec;
    if ((client.second.find(IS_UNFRIENDLY_STR)) != client.second.end() &&
        (client.second.at(IS_UNFRIENDLY_STR) == std::to_string(true))) {
        client_remaining_timelife_sec = unfriendly_device_max_timelife_delay_sec;
    }

    return ((client_remaining_timelife_sec > client_timelife_passed_sec)
                ? (client_remaining_timelife_sec - client_timelife_passed_sec)
                : 0);
}

bool db::clear_ap_capabilities(const sMacAddr &radio_uid)
{
    auto radio = get_radio_by_uid(radio_uid);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with RUID: " << radio_uid;
        return false;
    }

    if (radio->dm_path.empty()) {
        return true;
    }

    bool ret_val           = true;
    const auto path_to_obj = radio->dm_path + ".Capabilities";

    ret_val &= m_ambiorix_datamodel->remove_optional_subobject(path_to_obj, "HTCapabilities");
    ret_val &= m_ambiorix_datamodel->remove_optional_subobject(path_to_obj, "VHTCapabilities");
    ret_val &= m_ambiorix_datamodel->remove_optional_subobject(path_to_obj, "WiFi6Capabilities");

    return ret_val;
}

bool db::set_ap_ht_capabilities(const sMacAddr &radio_mac,
                                const wfa_map::tlvApHtCapabilities::sFlags &flags)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with mac: " << radio_mac;
        return false;
    }

    std::string path_to_obj = radio->dm_path;
    if (path_to_obj.empty()) {
        return true;
    }

    path_to_obj += ".Capabilities.";
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "HTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_obj << ".HTCapabilities";
        return false;
    }

    bool ret_val = true;
    path_to_obj += "HTCapabilities.";

    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HTShortGI20",
                                         static_cast<bool>(flags.short_gi_support_20mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "HTShortGI40",
                                         static_cast<bool>(flags.short_gi_support_40mhz));
    ret_val &=
        m_ambiorix_datamodel->set(path_to_obj, "HT40", static_cast<bool>(flags.ht_support_40mhz));
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfTxSpatialStreams",
                                         flags.max_num_of_supported_tx_spatial_streams + 1);
    ret_val &= m_ambiorix_datamodel->set(path_to_obj, "MaxNumberOfRxSpatialStreams",
                                         flags.max_num_of_supported_rx_spatial_streams + 1);

    return ret_val;
}

bool db::dm_set_device_multi_ap_capabilities(const std::string &device_mac)
{
    std::shared_ptr<Agent> agent = get_agent(tlvf::mac_from_string(device_mac));
    std::string path_to_obj      = agent->dm_path;
    bool return_val              = true;

    if (path_to_obj.empty()) {
        return true;
    }

    path_to_obj += ".MultiAPCapabilities";
    //For the time being, agent does not do steering so Steering Policy TLV is ignored.
    if (!m_ambiorix_datamodel->set(path_to_obj, "AgentInitiatedRCPIBasedSteering", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "AgentInitiatedRCPIBasedSteering: " << false;
        return_val = false;
    }
    // UnassociatedSTALinkMetricsCurrentlyOn not supported for now (PPM-172)
    if (!m_ambiorix_datamodel->set(path_to_obj, "UnassociatedSTALinkMetricsCurrentlyOn", false)) {
        LOG(ERROR) << "Failed to set: " << path_to_obj
                   << "UnassociatedSTALinkMetricsCurrentlyOn: " << false;
        return_val = false;
    }
    // UnassociatedSTALinkMetricsCurrentlyOff not supported for now (PPM-172)
    if (!m_ambiorix_datamodel->set(path_to_obj, "UnassociatedSTALinkMetricsCurrentlyOff", false)) {
        LOG(ERROR) << "Failed to set : " << path_to_obj
                   << "UnassociatedSTALinkMetricsCurrentlyOff: " << false;
        return_val = false;
    }
    return return_val;
}

bool db::dm_add_sta_element(const sMacAddr &al_mac, const sMacAddr &bssid, Station &station)
{

    auto bss = get_bss(bssid, al_mac);
    if (!bss) {
        LOG(ERROR) << "Failed to get BSS with BSSID: " << bssid;
        return false;
    }
    if (bss->dm_path.empty()) {
        LOG(DEBUG) << __func__ << " ignoring empty datamodel path for BSS " << bssid;
        return true;
    }

    // TODO In refactoring Database nodes (PPM-1057),
    // we need to make sure to remove datamodel index when database objects are deleted/removed.
    // We are verifying STA datamodel path from database, so it should be consistent.

    // Verify Station object data model path is changed or not.
    if (!station.dm_path.empty()) {

        // Verify if STA is added under different BSS. If so, remove old data model object.
        if (station.dm_path.find(bss->dm_path) == std::string::npos) {

            LOG(DEBUG) << "Station is added to different BSS " << bssid
                       << " remove previous object";

            auto sta_path = get_dm_index_from_path(station.dm_path);

            if (!m_ambiorix_datamodel->remove_instance(sta_path.first, sta_path.second)) {
                LOG(ERROR) << "Failed to remove " << station.dm_path;
            }
            station.dm_path.clear();
        }
    }

    // If dm_path is empty, either it is steered or firstly added. New dm instance should be added.
    if (station.dm_path.empty()) {

        const std::string path_to_sta = bss->dm_path + ".STA";

        station.dm_path = m_ambiorix_datamodel->add_instance(path_to_sta);
        if (station.dm_path.empty()) {
            LOG(ERROR) << "Failed to add sta instance " << path_to_sta
                       << ". STA mac: " << station.mac;
            return false;
        }

        dm_restore_sta_steering_event(station);
    }
    dm_restore_steering_summary_stats(station);

    LOG(DEBUG) << "Station is added with data model " << station.dm_path;

    if (!m_ambiorix_datamodel->set(station.dm_path, "MACAddress", station.mac)) {
        LOG(ERROR) << "Failed to set " << station.dm_path << ".MACAddress: " << station.mac;
        return false;
    }

    m_ambiorix_datamodel->set_current_time(station.dm_path);
    m_ambiorix_datamodel->set_current_time(station.dm_path + ".MultiAPSTA", "AssociationTime");

    uint64_t add_sta_time = time(NULL);
    if (!m_ambiorix_datamodel->set(station.dm_path, "LastConnectTime", add_sta_time)) {
        LOG(ERROR) << "Failed to set " << station.dm_path << ".LastConnectTime: " << add_sta_time;
        return false;
    }

    return true;
}

void db::dm_set_status(const std::string &event_path, const uint8_t status_code)
{
    uint8_t max_status_code = 9;
    std::string m_status_code_vals[max_status_code]{
        "Accept",
        "Unspecified reject reason",
        "Insufficient Beacon or Probe Response frames received",
        "Insufficient available capacity from all candidates",
        "BSS termination undesired",
        "BSS termination delay requested",
        "STA BSS Transition Candidate List provided",
        "No suitable BSS transition candidates",
        "Reject—Leaving ESS"};

    // By default status is in datamodel is 'Unknown'
    if (status_code < max_status_code) {
        m_ambiorix_datamodel->set(event_path, "Status", m_status_code_vals[status_code]);
    }
}

std::string db::dm_add_steer_event()
{
    if (!dm_check_objects_limit(m_steer_events, MAX_EVENT_HISTORY_SIZE)) {
        LOG(ERROR) << "Failed to remove Exceeding SteerEvent objects.";
        return {};
    }

    std::string event_path = m_ambiorix_datamodel->add_instance(CONTROLLER_ROOT_DM ".SteerEvent");

    if (event_path.empty() && NBAPI_ON) {
        LOG(ERROR) << "Failed to add instance " CONTROLLER_ROOT_DM ".SteerEvent";
        return {};
    }
    m_steer_events.push(event_path);
    return event_path;
}

bool db::dm_restore_steering_summary_stats(Station &station)
{
    bool ret_val = true;

    if (station.dm_path.empty()) {
        LOG(DEBUG) << "Empty station dm_path";
        return true;
    }

    auto steer_summary = station.steering_summary_stats;
    auto obj_path      = station.dm_path + ".MultiAPSTA.SteeringSummaryStats";

    ret_val &=
        m_ambiorix_datamodel->set(obj_path, "BlacklistAttempts", steer_summary.blacklist_attempts);
    ret_val &= m_ambiorix_datamodel->set(obj_path, "BlacklistSuccesses",
                                         steer_summary.blacklist_successes);
    ret_val &=
        m_ambiorix_datamodel->set(obj_path, "BlacklistFailures", steer_summary.blacklist_failures);
    ret_val &= m_ambiorix_datamodel->set(obj_path, "BTMAttempts", steer_summary.btm_attempts);
    ret_val &= m_ambiorix_datamodel->set(obj_path, "BTMSuccesses", steer_summary.btm_successes);
    ret_val &= m_ambiorix_datamodel->set(obj_path, "BTMFailures", steer_summary.btm_failures);
    ret_val &=
        m_ambiorix_datamodel->set(obj_path, "BTMQueryResponses", steer_summary.btm_query_responses);
    ret_val &= m_ambiorix_datamodel->set(obj_path, "LastSteerTime", steer_summary.last_steer_time);

    return ret_val;
}

void db::dm_increment_steer_summary_stats(const std::string &param_name)
{
    dm_uint64_param_one_up(CONTROLLER_ROOT_DM ".Network.MultiAPSteeringSummaryStats", param_name);
}

bool db::dm_add_failed_connection_event(const sMacAddr &bssid, const sMacAddr &sta_mac,
                                        const uint16_t reason_code, const uint16_t status_code)
{
    std::string event_path = CONTROLLER_ROOT_DM ".FailedConnectionEvent.FailedConnectionEventData";

    event_path = m_ambiorix_datamodel->add_instance(event_path);

    if (event_path.empty() && NBAPI_ON) {
        return false;
    }

    bool ret_val = true;

    ret_val &= m_ambiorix_datamodel->set_current_time(event_path);
    ret_val &= m_ambiorix_datamodel->set(event_path, "BSSID", bssid);
    ret_val &= m_ambiorix_datamodel->set(event_path, "MACAddress", sta_mac);
    ret_val &= m_ambiorix_datamodel->set(event_path, "StatusCode", status_code);
    ret_val &= m_ambiorix_datamodel->set(event_path, "ReasonCode", reason_code);
    return ret_val;
}

std::string db::dm_add_association_event(const sMacAddr &bssid, const sMacAddr &client_mac,
                                         const std::string &assoc_ts)
{
    std::string path_association_event =
        CONTROLLER_ROOT_DM ".AssociationEvent.AssociationEventData";

    if (!dm_check_objects_limit(m_assoc_events, MAX_EVENT_HISTORY_SIZE)) {
        return {};
    }
    path_association_event = m_ambiorix_datamodel->add_instance(path_association_event);

    if (path_association_event.empty()) {
        return {};
    }
    m_assoc_events.push(path_association_event);
    if (!m_ambiorix_datamodel->set(path_association_event, "BSSID", bssid)) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".BSSID: " << bssid;
        return {};
    }
    if (!m_ambiorix_datamodel->set(path_association_event, "MACAddress", client_mac)) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".MACAddress: " << client_mac;
        return {};
    }

    if (assoc_ts.empty()) {
        m_ambiorix_datamodel->set_current_time(path_association_event);
    } else if (!m_ambiorix_datamodel->set(path_association_event, "TimeStamp", assoc_ts)) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".TimeStamp: " << client_mac;
        return {};
    }

    /*
     TODO:  Set the status code to real value. Now value hardcoded to 0
            means connection successfull (IEEE802.11-16, Table 9.46).
            Should be fixed after PPM-864.
    */
    if (!m_ambiorix_datamodel->set(path_association_event, "StatusCode",
                                   static_cast<uint16_t>(0))) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".StatusCode: " << 0;
        return {};
    }
    return path_association_event;
}

std::string db::dm_add_device_element(const sMacAddr &mac)
{
    auto index = m_ambiorix_datamodel->get_instance_index(
        CONTROLLER_ROOT_DM ".Network.Device.[ID == '%s'].", tlvf::mac_to_string(mac));
    if (index) {
        LOG(WARNING) << "Device with ID: " << mac << " exists in the data model!";
        return {};
    }

    auto device_path = m_ambiorix_datamodel->add_instance(CONTROLLER_ROOT_DM ".Network.Device");
    if (device_path.empty()) {
        LOG(ERROR) << "Failed to add instance " << device_path << ". Device mac: " << mac;
        return {};
    }

    if (!m_ambiorix_datamodel->set(device_path, "ID", mac)) {
        LOG(ERROR) << "Failed to set " << device_path << ".ID: " << mac;
        return {};
    }

    return device_path;
}

bool db::add_current_op_class(const sMacAddr &radio_mac, uint8_t op_class, uint8_t op_channel,
                              int8_t tx_power)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio for mac: " << radio_mac;
        return false;
    }

    if (radio->band != utils::get_freq_type_from_op_class(op_class)) {
        LOG(ERROR) << "This should not happen. Radio band changed from " << radio->band << " to "
                   << utils::get_freq_type_from_op_class(op_class);
    }

    auto radio_path = radio->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Prepare path to the CurrentOperatingClasses instance
    // Data model path example: Device.WiFi.DataElements.Network.Device.1.Radio.1.CurrentOperatingClasses
    auto op_class_path = radio_path + ".CurrentOperatingClasses";

    auto op_class_path_instance = m_ambiorix_datamodel->add_instance(op_class_path);
    if (op_class_path_instance.empty()) {
        LOG(ERROR) << "Failed to add instance " << op_class_path;
        return false;
    }

    m_ambiorix_datamodel->set_current_time(op_class_path_instance);

    //Set Operating class
    //Data model path: Device.WiFi.DataElements.Network.Device.1.Radio.1.CurrentOperatingClasses.Class
    if (!m_ambiorix_datamodel->set(op_class_path_instance, "Class", op_class)) {
        LOG(ERROR) << "Failed to set " << op_class_path_instance << ".Class: " << op_class;
        return false;
    }

    //Set Operating channel
    //Data model path example: Device.WiFi.DataElements.Network.Device.1.Radio.1.CurrentOperatingClasses.Channel
    if (!m_ambiorix_datamodel->set(op_class_path_instance, "Channel", op_channel)) {
        LOG(ERROR) << "Failed to set " << op_class_path_instance << ".Channel: " << op_channel;
        return false;
    }

    //Set TX power
    //Data model path example: Device.WiFi.DataElements.Network.Device.1.Radio.1.CurrentOperatingClasses.TxPower
    if (!m_ambiorix_datamodel->set(op_class_path_instance, "TxPower", tx_power)) {
        LOG(ERROR) << "Failed to set " << op_class_path_instance << ".TxPower: " << tx_power;
        return false;
    }

    return true;
}

bool db::remove_current_op_classes(const sMacAddr &radio_mac)
{
    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio for mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Prepare path to the CurrentOperatingClasses instance
    // Data model path example: Device.WiFi.DataElements.Network.Device.1.Radio.1.CurrentOperatingClasses
    auto op_class_path = radio_path + ".CurrentOperatingClasses";

    if (!m_ambiorix_datamodel->remove_all_instances(op_class_path)) {
        LOG(ERROR) << "Failed to remove all instances for: " << op_class_path;
        return false;
    }

    return true;
}

bool db::add_spatial_reuse_parameters(wfa_map::tlvSpatialReuseReport &spatial_reuse_report_tlv)
{
    LOG(INFO) << "add_spatial_reuse_parameters, radio_uid: "
              << spatial_reuse_report_tlv.radio_uid();
    auto radio = get_radio_by_uid(spatial_reuse_report_tlv.radio_uid());
    if (!radio) {
        LOG(ERROR) << "Failed to get radio for mac: " << spatial_reuse_report_tlv.radio_uid();
        return false;
    }

    auto radio_path = radio->dm_path;
    if (radio_path.empty()) {
        LOG(INFO) << "radio_path is empty";
        return true;
    }

    bool is_any_field_set =
        spatial_reuse_report_tlv.flags1().bss_color ||
        spatial_reuse_report_tlv.flags1().partial_bss_color ||
        spatial_reuse_report_tlv.flags2().psr_disallowed ||
        spatial_reuse_report_tlv.flags2().non_srg_offset_valid ||
        spatial_reuse_report_tlv.flags2().srg_information_valid ||
        spatial_reuse_report_tlv.flags2().hesiga_spatial_reuse_value15_allowed ||
        spatial_reuse_report_tlv.non_srg_obsspd_max_offset() ||
        spatial_reuse_report_tlv.srg_obsspd_min_offset() ||
        spatial_reuse_report_tlv.srg_obsspd_max_offset() ||
        spatial_reuse_report_tlv.srg_bss_color_bitmap() ||
        spatial_reuse_report_tlv.srg_partial_bssid_bitmap() ||
        spatial_reuse_report_tlv.neighbor_bss_color_in_use_bitmap();

    // Do not set SpatialReuse parameters if they all are empty. Checking is cheaper than ambiorix call.
    if (!is_any_field_set) {
        LOG(INFO) << "All parameters in spatial_reuse_report_tlv are empty";
        return true;
    }

    // Data model path example: Device.WiFi.DataElements.Network.Device.1.Radio.1.SpatialReuse
    const auto spatial_reuse_path = radio_path + ".SpatialReuse";

    //Data model path: Device.WiFi.DataElements.Network.Device.1.Radio.1.SpatialReuse.BSSColor
    if (!m_ambiorix_datamodel->set(spatial_reuse_path, "BSSColor",
                                   spatial_reuse_report_tlv.flags1().bss_color)) {
        LOG(ERROR) << "Failed to set " << spatial_reuse_path
                   << ".BSSColor: " << spatial_reuse_report_tlv.flags1().bss_color;
        return false;
    }
    if (!m_ambiorix_datamodel->set(spatial_reuse_path, "PartialBSSColor",
                                   spatial_reuse_report_tlv.flags1().partial_bss_color)) {
        LOG(ERROR) << "Failed to set " << spatial_reuse_path
                   << ".PartialBSSColor: " << spatial_reuse_report_tlv.flags1().partial_bss_color;
        return false;
    }
    if (!m_ambiorix_datamodel->set(
            spatial_reuse_path, "HESIGASpatialReuseValue15Allowed",
            spatial_reuse_report_tlv.flags2().hesiga_spatial_reuse_value15_allowed)) {
        LOG(ERROR) << "Failed to set " << spatial_reuse_path
                   << ".HESIGASpatialReuseValue15Allowed: "
                   << spatial_reuse_report_tlv.flags2().hesiga_spatial_reuse_value15_allowed;
        return false;
    }
    if (!m_ambiorix_datamodel->set(spatial_reuse_path, "SRGInformationValid",
                                   spatial_reuse_report_tlv.flags2().srg_information_valid)) {
        LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".SRGInformationValid: "
                   << spatial_reuse_report_tlv.flags2().srg_information_valid;
        return false;
    }
    if (!m_ambiorix_datamodel->set(spatial_reuse_path, "NonSRGOffsetValid",
                                   spatial_reuse_report_tlv.flags2().non_srg_offset_valid)) {
        LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".NonSRGOffsetValid: "
                   << spatial_reuse_report_tlv.flags2().non_srg_offset_valid;
        return false;
    }
    if (!m_ambiorix_datamodel->set(spatial_reuse_path, "PSRDisallowed",
                                   spatial_reuse_report_tlv.flags2().psr_disallowed)) {
        LOG(ERROR) << "Failed to set " << spatial_reuse_path
                   << ".PSRDisallowed: " << spatial_reuse_report_tlv.flags2().psr_disallowed;
        return false;
    }
    if (spatial_reuse_report_tlv.flags2().non_srg_offset_valid) {
        if (!m_ambiorix_datamodel->set(spatial_reuse_path, "NonSRGOBSSPDMaxOffset",
                                       spatial_reuse_report_tlv.non_srg_obsspd_max_offset())) {
            LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".NonSRGOBSSPDMaxOffset: "
                       << spatial_reuse_report_tlv.non_srg_obsspd_max_offset();
            return false;
        }
    }
    if (spatial_reuse_report_tlv.flags2().srg_information_valid) {
        if (!m_ambiorix_datamodel->set(spatial_reuse_path, "SRGOBSSPDMinOffset",
                                       spatial_reuse_report_tlv.srg_obsspd_min_offset())) {
            LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".SRGOBSSPDMinOffset: "
                       << spatial_reuse_report_tlv.srg_obsspd_min_offset();
            return false;
        }
        if (!m_ambiorix_datamodel->set(spatial_reuse_path, "SRGOBSSPDMaxOffset",
                                       spatial_reuse_report_tlv.srg_obsspd_max_offset())) {
            LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".SRGOBSSPDMaxOffset: "
                       << spatial_reuse_report_tlv.srg_obsspd_max_offset();
            return false;
        }
        if (!m_ambiorix_datamodel->set(
                spatial_reuse_path, "SRGBSSColorBitmap",
                get_bss_color_bitmap_string(spatial_reuse_report_tlv.srg_bss_color_bitmap()))) {
            LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".SRGBSSColorBitmap: "
                       << get_bss_color_bitmap_string(
                              spatial_reuse_report_tlv.srg_bss_color_bitmap());
            return false;
        }
        if (!m_ambiorix_datamodel->set(
                spatial_reuse_path, "SRGPartialBSSIDBitmap",
                get_bss_color_bitmap_string(spatial_reuse_report_tlv.srg_partial_bssid_bitmap()))) {
            LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".SRGPartialBSSIDBitmap: "
                       << get_bss_color_bitmap_string(
                              spatial_reuse_report_tlv.srg_partial_bssid_bitmap());
            return false;
        }
        if (!m_ambiorix_datamodel->set(
                spatial_reuse_path, "NeighborBSSColorInUseBitmap",
                get_bss_color_bitmap_string(
                    spatial_reuse_report_tlv.neighbor_bss_color_in_use_bitmap()))) {
            LOG(ERROR) << "Failed to set " << spatial_reuse_path << ".NeighborBSSColorInUseBitmap: "
                       << get_bss_color_bitmap_string(
                              spatial_reuse_report_tlv.neighbor_bss_color_in_use_bitmap());
            return false;
        }
    }
    return true;
}

bool db::remove_hostap_supported_operating_classes(const sMacAddr &radio_mac)
{
    auto supported_channels = get_radio_supported_channels(radio_mac);
    auto radio              = get_radio_by_uid(radio_mac);

    // Remove from data model
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    auto op_class_path = radio_path + ".Capabilities.OperatingClasses";
    if (!m_ambiorix_datamodel->remove_all_instances(op_class_path)) {
        LOG(ERROR) << "Failed to remove all instances for: " << op_class_path;
        return false;
    }

    // Remove from database
    std::vector<beerocks::WifiChannel>().swap(supported_channels);

    return true;
}

bool db::set_radio_utilization(const sMacAddr &bssid, uint8_t utilization)
{
    auto radio = get_radio_by_bssid(bssid);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio for bssid: " << bssid;
        return false;
    }

    if (radio->dm_path.empty()) {
        return true;
    }

    // Path to the object example: Device.WiFi.DataElements.Network.Device.1.Radio.1.Utilization
    if (!m_ambiorix_datamodel->set(radio->dm_path, "Utilization", utilization)) {
        LOG(ERROR) << "Failed to set " << radio->dm_path << ".Utilization: " << utilization;
        return false;
    }

    return true;
}

bool db::dm_set_radio_bss(const sMacAddr &al_mac, const sMacAddr &radio_mac, const sMacAddr &bssid,
                          bool is_vbss)
{
    LOG(DEBUG) << "Setting BSS for radio " << radio_mac << " bssid " << bssid << " al_mac "
               << al_mac;

    auto agent = get_agent(al_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to get agent with ALID: " << al_mac;
        return false;
    }

    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with mac: " << radio_mac;
        return false;
    }

    if (radio->dm_path.empty()) {
        LOG(DEBUG) << __func__ << "Ignoring empty datamodel path for radio " << radio_mac;
        return true;
    }

    auto bss = get_bss(bssid, al_mac);
    if (!bss) {
        LOG(ERROR) << "Failed to get BSS with BSSID: " << bssid;
        return false;
    }

    if (bss->dm_path.empty()) {

        auto bss_path = radio->dm_path + ".BSS";
        LOG(DEBUG) << "Adding new BSS instance for radio MAC " << radio_mac << " bssid " << bssid;
        auto bss_instance = m_ambiorix_datamodel->add_instance(bss_path);
        if (bss_instance.empty()) {
            LOG(ERROR) << "Failed to add " << bss_path << " instance.";
            return false;
        }
        bss->dm_path = bss_instance;
        LOG(DEBUG) << "New BSS instance successfully added. Path: " << bss_instance;
    }

    auto ret_val = true;

    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "BSSID", bssid);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "SSID", bss->ssid);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "Enabled", bss->enabled);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "FronthaulUse", bss->fronthaul);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "BackhaulUse", bss->backhaul);
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "IsVBSS", is_vbss);
    LOG(DEBUG) << "Setting byte counter unit to " << agent->byte_counter_units;
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "ByteCounterUnits",
                                         static_cast<uint32_t>(agent->byte_counter_units));
    LOG(DEBUG) << "Result " << ret_val;

    /*
        Set value for LastChange variable - it is creation time, when someone will
        try to get data from this parameter action method will calculate time in seconds
        from creation moment.
        Example: Device.WiFi.DataElements.Network.Device.1.Radio.1.BSS.1.LastChange
    */
    uint32_t creation_time =
        static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::steady_clock::now().time_since_epoch())
                                  .count());
    ret_val &= m_ambiorix_datamodel->set(bss->dm_path, "LastChange", creation_time);
    ret_val &= m_ambiorix_datamodel->set_current_time(bss->dm_path);

    return ret_val;
}

bool db::dm_uint64_param_one_up(const std::string &obj_path, const std::string &param_name)
{
    if (obj_path.empty()) {
        LOG(WARNING) << "Path to data model object is empty.";
        return false;
    }

    uint64_t ret_val;

    if (!m_ambiorix_datamodel->read_param(obj_path, param_name, &ret_val)) {
        LOG(WARNING) << "Failed to get " << obj_path << "." << param_name;
        return false;
    }
    if (!m_ambiorix_datamodel->set(obj_path, param_name, ret_val + 1)) {
        LOG(WARNING) << "Failed to increment " << obj_path << "." << param_name;
        return false;
    }
    return true;
}

bool db::set_radio_metrics(const sMacAddr &radio_mac, uint8_t noise, uint8_t transmit,
                           uint8_t receive_self, uint8_t receive_other)
{

    auto radio = get_radio_by_uid(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio for mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Data model path example: Device.WiFi.DataElements.Network.Device.1.Radio.1.Noise
    if (!m_ambiorix_datamodel->set(radio_path, "Noise", noise)) {
        LOG(ERROR) << "Failed to set " << radio_path << ".Noise " << noise;
        return false;
    }

    if (!m_ambiorix_datamodel->set(radio_path, "Transmit", transmit)) {
        LOG(ERROR) << "Failed to set " << radio_path << ".Transmit " << transmit;
        return false;
    }

    if (!m_ambiorix_datamodel->set(radio_path, "ReceiveSelf", receive_self)) {
        LOG(ERROR) << "Failed to set " << radio_path << ".ReceiveSelf " << receive_self;
        return false;
    }

    if (!m_ambiorix_datamodel->set(radio_path, "ReceiveOther", receive_other)) {
        LOG(ERROR) << "Failed to set " << radio_path << ".ReceiveOther " << receive_other;
        return false;
    }

    return true;
}

bool db::set_estimated_service_param(const sMacAddr &bssid, const std::string &param_name,
                                     uint32_t esp_value)
{
    auto bss = get_bss(bssid);
    if (!bss) {
        LOG(ERROR) << "Failed to get BSS with BSSID: " << bssid;
        return false;
    }
    if (bss->dm_path.empty()) {
        return true;
    }

    return m_ambiorix_datamodel->set(bss->dm_path, param_name, esp_value);
}

bool db::add_interface(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                       uint16_t media_type, const std::string &status, const std::string &name)
{
    std::shared_ptr<Agent> agent = m_agents.get(device_mac);
    if (!agent) {
        LOG(ERROR) << "No Agent found with mac " << device_mac;
        return false;
    }

    agent->interfaces.add(interface_mac, name, (ieee1905_1::eMediaType)media_type);

    return dm_add_interface_element(device_mac, interface_mac, media_type, status, name);
}

std::shared_ptr<Agent::sInterface> db::get_interface_on_agent(const sMacAddr &device_mac,
                                                              const sMacAddr &interface_mac)
{
    std::shared_ptr<Agent> agent = get_agent(device_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to get agent with mac: " << device_mac;
        return nullptr;
    }

    return agent->interfaces.get(interface_mac);
}

bool db::dm_add_interface_element(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                                  uint16_t media_type, const std::string &status,
                                  const std::string &name)
{
    std::shared_ptr<Agent::sInterface> iface = get_interface_on_agent(device_mac, interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    // Empty data path refers for newly created object, so add instance to data model.
    if (iface->m_dm_path.empty()) {

        // Disabled NBAPI error prevention
        std::shared_ptr<Agent> agent = get_agent(device_mac);
        if (!agent) {
            return false;
        }
        if (agent->dm_path.empty()) {
            return true;
        }

        // Prepare path to the Interface object, like Device.WiFi.DataElements.Network.Device.{i}.Interface
        auto interface_path = agent->dm_path + ".Interface";

        iface->m_dm_path = m_ambiorix_datamodel->add_instance(interface_path);
        if (iface->m_dm_path.empty()) {
            LOG(ERROR) << "Failed to add " << interface_path
                       << ". Interface MAC: " << interface_mac;
            return false;
        }

        // Prepare path to the Interface object MACAddress, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.MACAddress
        m_ambiorix_datamodel->set(iface->m_dm_path, "MACAddress", interface_mac);
    }

    // Prepare path to the Interface object Status, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Status
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "Status", status)) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".Status: " << status;
        return false;
    }
    // Prepare path to the Interface object MACAddress, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.MACAddress
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "MACAddress", interface_mac)) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".MACAddress: " << interface_mac;
        return false;
    }
    // Prepare path to the Interface object Name, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Name
    if (name.empty()) {
        if (!m_ambiorix_datamodel->set(iface->m_dm_path, "Name", interface_mac)) {
            LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".Name: " << name;
            return false;
        }
    } else {
        if (!m_ambiorix_datamodel->set(iface->m_dm_path, "Name", name)) {
            LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".Name: " << name;
            return false;
        }
    }

    // Prepare path to the Interface object MediaType, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.MediaType
    auto media_type_str =
        std::string(ieee1905_1::eMediaType_str(ieee1905_1::eMediaType(media_type)));
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "MediaType", media_type_str)) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".MediaType: " << media_type;
        return false;
    }
    return true;
}

std::shared_ptr<beerocks::nbapi::Ambiorix> db::get_ambiorix_obj() { return m_ambiorix_datamodel; }

bool db::remove_interface(const sMacAddr &device_mac, const sMacAddr &interface_mac)
{
    dm_remove_interface_element(device_mac, interface_mac);

    auto agent = m_agents.get(device_mac);
    if (agent) {
        agent->interfaces.erase(interface_mac);
    }

    return true;
}

bool db::dm_remove_interface_element(const sMacAddr &device_mac, const sMacAddr &interface_mac)
{
    std::shared_ptr<Agent::sInterface> iface = get_interface_on_agent(device_mac, interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    if (iface->m_dm_path.empty()) {
        return true;
    }

    auto instance = get_dm_index_from_path(iface->m_dm_path);

    if (!m_ambiorix_datamodel->remove_instance(instance.first, instance.second)) {
        LOG(ERROR) << "Failed to remove " << iface->m_dm_path << " instance.";
        return false;
    }

    return true;
}

bool db::dm_update_interface_elements(const sMacAddr &device_mac,
                                      const std::vector<sMacAddr> &interface_macs)
{
    std::shared_ptr<Agent> agent = get_agent(device_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to get agent node with mac: " << device_mac;
        return false;
    }

    std::vector<sMacAddr> erase_mac_list;
    for (const auto &interface : agent->interfaces) {
        erase_mac_list.emplace_back(interface.first);
    }
    for (const auto &interface : interface_macs) {
        erase_mac_list.erase(std::remove(erase_mac_list.begin(), erase_mac_list.end(), interface),
                             erase_mac_list.end());
    }
    for (const auto &iface_mac : erase_mac_list) {
        remove_interface(device_mac, iface_mac);
    }
    return true;
}

bool db::dm_update_interface_tx_stats(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                                      uint64_t packets_sent, uint32_t errors_sent)
{
    std::shared_ptr<Agent> agent = get_agent(device_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to get Agent with mac: " << device_mac;
        return false;
    }

    std::shared_ptr<Agent::sInterface> iface = agent->interfaces.get(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    if (iface->m_dm_path.empty()) {
        return true;
    }

    // Prepare path to the Interface object Stats, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Stats
    auto stats_path = iface->m_dm_path + ".Stats";

    // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Stats.PacketsSent
    if (!m_ambiorix_datamodel->set(stats_path, "PacketsSent", packets_sent)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".PacketsSent: " << packets_sent;
        return false;
    }

    // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Stats.ErrorsSent
    if (!m_ambiorix_datamodel->set(stats_path, "ErrorsSent", errors_sent)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".ErrorsSent: " << errors_sent;
        return false;
    }

    return true;
}

bool db::dm_update_interface_rx_stats(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                                      uint64_t packets_received, uint32_t errors_received)
{
    std::shared_ptr<Agent> agent = get_agent(device_mac);
    if (!agent) {
        LOG(ERROR) << "Failed to get Agent with mac: " << device_mac;
        return false;
    }

    std::shared_ptr<Agent::sInterface> iface = agent->interfaces.get(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    if (iface->m_dm_path.empty()) {
        return true;
    }

    // Prepare path to the Interface object Stats, like Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Stats
    auto stats_path = iface->m_dm_path + ".Stats";

    // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Stats.PacketsReceived
    if (!m_ambiorix_datamodel->set(stats_path, "PacketsReceived", packets_received)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".PacketsReceived: " << packets_received;
        return false;
    }

    // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Stats.ErrorsReceived
    if (!m_ambiorix_datamodel->set(stats_path, "ErrorsReceived", errors_received)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".ErrorsReceived: " << errors_received;
        return false;
    }

    return true;
}

bool db::add_neighbor(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                      const sMacAddr &neighbor_mac, bool is_IEEE1905)
{
    std::shared_ptr<Agent::sInterface> interface =
        get_interface_on_agent(device_mac, interface_mac);
    if (!interface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    std::shared_ptr<Agent::sNeighbor> neighbor =
        interface->m_neighbors.add(neighbor_mac, is_IEEE1905);
    if (!neighbor) {
        LOG(ERROR) << "Failed to add neighbor with mac: " << neighbor_mac;
        return false;
    }

    return dm_add_interface_neighbor(interface, neighbor);
}

bool db::dm_add_interface_neighbor(const std::shared_ptr<Agent::sInterface> &interface,
                                   std::shared_ptr<Agent::sNeighbor> &neighbor)
{
    if (!interface) {
        LOG(ERROR) << "Failed because of nullptr interface.";
        return false;
    }

    if (!neighbor) {
        LOG(ERROR) << "Failed because of nullptr neighbor.";
        return false;
    }

    // Empty data path refers for newly created object, so add instance to data model.
    if (neighbor->dm_path.empty()) {

        // Disabled NBAPI error prevention
        if (interface->m_dm_path.empty()) {
            return true;
        }

        // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Neighbor.{i}
        auto neighbor_path = interface->m_dm_path + ".Neighbor";

        auto neighbor_instance = m_ambiorix_datamodel->add_instance(neighbor_path);
        if (neighbor_instance.empty()) {
            LOG(ERROR) << "Failed to add " << neighbor_path << ". Neighbor MAC: " << neighbor->mac;
            return false;
        }

        neighbor->dm_path = neighbor_instance;
    }

    // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Neighbor.{i}.ID
    if (!m_ambiorix_datamodel->set(neighbor->dm_path, "ID", neighbor->mac)) {
        LOG(ERROR) << "Failed to set " << neighbor->dm_path << ".ID: " << neighbor->mac;
        return false;
    }

    // Set value for the path as Device.WiFi.DataElements.Network.Device.{i}.Interface.{i}.Neighbor.{i}.IsIEEE1905
    if (!m_ambiorix_datamodel->set(neighbor->dm_path, "IsIEEE1905", neighbor->ieee1905_flag)) {
        LOG(ERROR) << "Failed to set " << neighbor->dm_path
                   << ".IsIEEE1905: " << neighbor->ieee1905_flag;
        return false;
    }

    return true;
}

bool db::dm_remove_interface_neighbor(const std::string &dm_path)
{
    if (dm_path.empty()) {
        return true;
    }

    auto instance = get_dm_index_from_path(dm_path);

    if (!m_ambiorix_datamodel->remove_instance(instance.first, instance.second)) {
        LOG(ERROR) << "Failed to remove " << dm_path << " instance.";
        return false;
    }
    return true;
}

bool db::dm_set_sta_extended_link_metrics(
    const sMacAddr &sta_mac, const wfa_map::tlvAssociatedStaExtendedLinkMetrics::sMetrics &metrics)
{
    auto station = get_station(sta_mac);
    if (!station) {
        LOG(ERROR) << "Failed to get station on db with mac: " << sta_mac;
        return false;
    }

    // Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.
    if (station->dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "LastDataDownlinkRate",
                                         metrics.last_data_down_link_rate);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "LastDataUplinkRate",
                                         metrics.last_data_up_link_rate);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "UtilizationReceive",
                                         metrics.utilization_receive);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "UtilizationTransmit",
                                         metrics.utilization_transmit);

    return ret_val;
}

bool db::dm_set_sta_traffic_stats(const sMacAddr &sta_mac, sAssociatedStaTrafficStats &stats)
{
    auto station = get_station(sta_mac);
    if (!station) {
        LOG(ERROR) << "Failed to get station on db with mac: " << sta_mac;
        return false;
    }

    // Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.
    if (station->dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "BytesSent", stats.m_byte_sent);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "BytesReceived", stats.m_byte_received);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "PacketsSent", stats.m_packets_sent);
    ret_val &=
        m_ambiorix_datamodel->set(station->dm_path, "PacketsReceived", stats.m_packets_received);
    ret_val &=
        m_ambiorix_datamodel->set(station->dm_path, "RetransCount", stats.m_retransmission_count);
    ret_val &= m_ambiorix_datamodel->set(station->dm_path, "ErrorsSent", stats.m_tx_packets_error);
    ret_val &=
        m_ambiorix_datamodel->set(station->dm_path, "ErrorsReceived", stats.m_rx_packets_error);
    ret_val &= m_ambiorix_datamodel->set_current_time(station->dm_path);

    return ret_val;
}

bool db::dm_add_tid_queue_sizes(
    const Station &station,
    const std::vector<wfa_map::tlvAssociatedWiFi6StaStatusReport::sTidQueueSize> &tid_queue_vector)
{
    if (station.dm_path.empty()) {
        return true;
    }

    if (!m_ambiorix_datamodel->remove_all_instances(station.dm_path + ".TIDQueueSizes")) {
        return false;
    }

    bool ret_val = true;

    // Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TIDQueueSizes.{i}.
    for (auto &tid_queue : tid_queue_vector) {
        auto tid_queue_size_path =
            m_ambiorix_datamodel->add_instance(station.dm_path + ".TIDQueueSizes");
        if (tid_queue_size_path.empty()) {
            return false;
        }

        ret_val &= m_ambiorix_datamodel->set(tid_queue_size_path, "TID", tid_queue.tid);
        ret_val &= m_ambiorix_datamodel->set(tid_queue_size_path, "Size", tid_queue.queue_size);
    }

    return ret_val;
}

bool db::dm_clear_sta_stats(const sMacAddr &sta_mac)
{
    dm_set_sta_link_metrics(sta_mac, 0, 0, 0);

    wfa_map::tlvAssociatedStaExtendedLinkMetrics::sMetrics metrics;
    metrics.last_data_down_link_rate = 0;
    metrics.last_data_up_link_rate   = 0;
    metrics.utilization_receive      = 0;
    metrics.utilization_transmit     = 0;
    dm_set_sta_extended_link_metrics(sta_mac, metrics);

    sAssociatedStaTrafficStats stats;
    dm_set_sta_traffic_stats(sta_mac, stats);
    return true;
}

bool db::dm_remove_sta(Station &station)
{
    if (station.dm_path.empty()) {
        LOG(INFO) << "Station dm_path is already empty";
        return true;
    }
    auto instance = get_dm_index_from_path(station.dm_path);
    station.dm_path.clear();

    return m_ambiorix_datamodel->remove_instance(instance.first, instance.second);
}

bool db::set_sta_dhcp_v4_lease(const sMacAddr &sta_mac, const std::string &host_name,
                               const std::string &ipv4_address)
{
    std::shared_ptr<Station> pSta = get_station(sta_mac);
    if (!pSta) {
        LOG(ERROR) << "Failed to get station with mac: " << sta_mac;
        return false;
    }

    // Update node attributes.
    pSta->ipv4 = ipv4_address;
    pSta->name = host_name;

    // Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.
    if (pSta->dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(pSta->dm_path, "Hostname", host_name);
    ret_val &= m_ambiorix_datamodel->set(pSta->dm_path, "IPV4Address", ipv4_address);

    return ret_val;
}

bool db::set_sta_dhcp_v6_lease(const sMacAddr &sta_mac, const std::string &host_name,
                               const std::string &ipv6_address)
{
    std::shared_ptr<Station> pSta = get_station(sta_mac);
    if (!pSta) {
        LOG(ERROR) << "Failed to get station with mac: " << sta_mac;
        return false;
    }

    // Update node attributes.
    pSta->name = host_name;
    pSta->ipv6 = ipv6_address;

    // Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.
    if (pSta->dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(pSta->dm_path, "Hostname", host_name);
    ret_val &= m_ambiorix_datamodel->set(pSta->dm_path, "IPV6Address", ipv6_address);

    return ret_val;
}

bool db::update_master_configuration(const sDbNbapiConfig &nbapi_config)
{
    auto ret_val = true;

    config.diagnostics_measurements_polling_rate_sec =
        nbapi_config.diagnostics_measurements_polling_rate_sec;
    config.link_metrics_request_interval_seconds =
        nbapi_config.link_metrics_request_interval_seconds;
    config.load_channel_select_task         = nbapi_config.channel_select_task;
    config.load_client_11k_roaming          = nbapi_config.client_11k_roaming;
    config.load_client_band_steering        = nbapi_config.client_band_steering;
    config.load_client_optimal_path_roaming = nbapi_config.client_optimal_path_roaming;
    config.load_dfs_reentry                 = nbapi_config.enable_dfs_reentry;
    config.load_diagnostics_measurements    = nbapi_config.diagnostics_measurements;
    config.load_dynamic_channel_select_task = nbapi_config.dynamic_channel_select_task;
    config.load_health_check                = nbapi_config.health_check;
    config.load_ire_roaming                 = nbapi_config.ire_roaming;
    config.load_load_balancing              = nbapi_config.load_balancing;
    config.load_optimal_path_roaming_prefer_signal_strength =
        nbapi_config.optimal_path_prefer_signal_strength;
    config.roaming_hysteresis_percent_bonus = nbapi_config.roaming_hysteresis_percent_bonus;
    config.steering_disassoc_timer_msec     = nbapi_config.steering_disassoc_timer_msec;
    config.daisy_chaining_disabled          = nbapi_config.daisy_chaining_disabled;

    // Update persistent configuration.
    ret_val &= beerocks::bpl::cfg_set_band_steering(config.load_client_band_steering);
    ret_val &= beerocks::bpl::cfg_set_channel_select_task(config.load_channel_select_task);
    ret_val &= beerocks::bpl::cfg_set_client_11k_roaming(config.load_client_11k_roaming);
    ret_val &= beerocks::bpl::cfg_set_client_roaming(config.load_client_optimal_path_roaming);
    ret_val &= beerocks::bpl::cfg_set_dfs_reentry(config.load_dfs_reentry);
    ret_val &= beerocks::bpl::cfg_set_dfs_task(config.load_dynamic_channel_select_task);
    ret_val &=
        beerocks::bpl::cfg_set_diagnostics_measurements(config.load_diagnostics_measurements);
    ret_val &= beerocks::bpl::cfg_set_diagnostics_measurements_polling_rate_sec(
        config.diagnostics_measurements_polling_rate_sec);
    ret_val &= beerocks::bpl::cfg_set_health_check(config.load_health_check);
    ret_val &= beerocks::bpl::cfg_set_ire_roaming(config.load_ire_roaming);
    ret_val &= beerocks::bpl::cfg_set_link_metrics_request_interval(
        config.link_metrics_request_interval_seconds);
    ret_val &= beerocks::bpl::cfg_set_load_balancing(config.load_load_balancing);
    ret_val &= beerocks::bpl::cfg_set_optimal_path_prefer_signal_strenght(
        config.load_optimal_path_roaming_prefer_signal_strength);
    ret_val &= beerocks::bpl::cfg_set_roaming_hysteresis_percent_bonus(
        config.roaming_hysteresis_percent_bonus);
    ret_val &=
        beerocks::bpl::cfg_set_steering_disassoc_timer_msec(config.steering_disassoc_timer_msec);
    ret_val &= beerocks::bpl::cfg_set_daisy_chaining_disabled(config.daisy_chaining_disabled);

    ret_val &= beerocks::bpl::cfg_commit_changes();

    update_master_settings_from_config();

    return ret_val;
}

void db::update_master_settings_from_config()
{
    // calling these functions with "true" is equivalent to copying the value from config container
    settings_channel_select_task(true);
    settings_client_11k_roaming(true);
    settings_client_band_steering(true);
    settings_client_optimal_path_roaming_prefer_signal_strength(true);
    settings_client_optimal_path_roaming(true);
    settings_dfs_reentry(true);
    settings_diagnostics_measurements(true);
    settings_dynamic_channel_select_task(true);
    settings_health_check(true);
    settings_ire_roaming(true);
    settings_load_balancing(true);
    settings_daisy_chaining_disabled(true);
}

uint64_t db::recalculate_attr_to_byte_units(
    wfa_map::tlvProfile2ApCapability::eByteCounterUnits byte_counter_units, uint64_t bytes)
{
    if (byte_counter_units == wfa_map::tlvProfile2ApCapability::eByteCounterUnits::KIBIBYTES) {
        bytes = bytes * 1024;
    } else if (byte_counter_units ==
               wfa_map::tlvProfile2ApCapability::eByteCounterUnits::MEBIBYTES) {
        bytes = bytes * 1024 * 1024;
    }

    return bytes;
}

std::string db::calculate_dpp_bootstrapping_str()
{
    // e.g. DPP:V:2;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADezecPyVDIgJVgdGBHGBdxRxGpNU7x9cHFBE=;;
    //  DPP:
    //  [C:<channel/opClass>,...;]                                                # Channel list
    //  [M:<mac(e.g. aabbccddeeff);]                                              # MAC
    //  [I:<any sequence of printable character except ';', no length limit>;]    # Information
    //  [V:<at least 1 (ALPHA / DIGIT) character (e.g "1", "2", etc>;]            # Version
    //  [H:<1-255 characters of (DIGIT / ALPHA / "." / "-" / ":")>;]              # Host
    //  [<Any sequence of characters which is not one of
    //    ("C", "M", "I", "V", "H", "K")>:
    //    <any sequence of printable character except ';', no length limit>;]     # Reserve
    //  K:<any sequence of (ALPHA / DIGIT / '+' / '/' / '=') , no length limit>;; # Public key

    std::string dpp_conn_string = "";
    std::string opclass_channel_str;
    for (const auto &ch : dpp_bootstrapping_info.operating_class_channel) {
        opclass_channel_str += std::to_string(ch.first) + "/" + std::to_string(ch.second) + ",";
    }
    if (!opclass_channel_str.empty()) {
        // Channel/OpClass has been added
        opclass_channel_str.pop_back();
        dpp_conn_string += "C:" + opclass_channel_str + ";";
    }

    if (dpp_bootstrapping_info.mac != net::network_utils::ZERO_MAC) {
        // Since semicolons are not in DPP str, remove them
        std::string mac_string = tlvf::mac_to_string(dpp_bootstrapping_info.mac);
        mac_string.erase(std::remove_if(mac_string.begin(), mac_string.end(),
                                        [&mac_string](const char &c) {
                                            return mac_string.find(c) != std::string::npos;
                                        }),
                         mac_string.end());
        dpp_conn_string += "M:" + mac_string + ";";
    }
    if (!dpp_bootstrapping_info.info.empty())
        dpp_conn_string += "I:" + dpp_bootstrapping_info.info + ";";

    if (dpp_bootstrapping_info.version != 0)
        dpp_conn_string += "V:" + std::to_string(dpp_bootstrapping_info.version) + ";";

    if (!dpp_bootstrapping_info.host.empty())
        dpp_conn_string += "H:" + dpp_bootstrapping_info.host + ";";

    if (!dpp_bootstrapping_info.public_key.empty())
        dpp_conn_string += "K:" + dpp_bootstrapping_info.public_key + ";";

    if (dpp_conn_string.empty()) {
        // No data elements were added, bootstrapping data is not initialized, return ""
        return "";
    }

    return "DPP:" + dpp_conn_string + ";";
}

bool db::dm_clear_cac_status_reports(std::shared_ptr<Agent> agent)
{
    if (agent->dm_path.empty()) {
        return true;
    }

    return m_ambiorix_datamodel->remove_all_instances(agent->dm_path + ".CACStatus");
}

bool db::dm_add_cac_status_report(
    std::shared_ptr<Agent> agent,
    const std::vector<wfa_map::tlvProfile2CacStatusReport::sAvailableChannels> &available_channels,
    const std::vector<wfa_map::tlvProfile2CacStatusReport::sDetectedPairs> &non_occupancy_channels,
    const std::vector<wfa_map::tlvProfile2CacStatusReport::sActiveCacPairs> &active_channels)
{
    if (agent->dm_path.empty()) {
        return true;
    }

    auto cac_status_path = m_ambiorix_datamodel->add_instance(agent->dm_path + ".CACStatus");
    if (cac_status_path.empty()) {
        LOG(ERROR) << "Failed to add: " << agent->dm_path << ".CACStatus";
        return false;
    }

    bool ret_val = true;

    if (!available_channels.empty()) {

        for (const auto &available_channel : available_channels) {
            auto available_channel_path =
                m_ambiorix_datamodel->add_instance(cac_status_path + ".CACAvailableChannel");
            if (available_channel_path.empty()) {
                LOG(ERROR) << "Failed to add instance to " << cac_status_path
                           << ".CACAvailableChannel";
                return false;
            }

            ret_val &= m_ambiorix_datamodel->set(available_channel_path, "OpClass",
                                                 available_channel.operating_class);
            ret_val &= m_ambiorix_datamodel->set(available_channel_path, "Channel",
                                                 available_channel.channel);
            ret_val &= m_ambiorix_datamodel->set(available_channel_path, "Minutes",
                                                 available_channel.minutes_since_cac_completion);
        }
    }

    if (!non_occupancy_channels.empty()) {

        for (const auto &non_occupancy_channel : non_occupancy_channels) {
            auto non_occupancy_channel_path =
                m_ambiorix_datamodel->add_instance(cac_status_path + ".CACNonOccupancyChannel");
            if (non_occupancy_channel_path.empty()) {
                LOG(ERROR) << "Failed to add instance to " << cac_status_path
                           << ".CACNonOccupancyChannel";
                return false;
            }

            ret_val &= m_ambiorix_datamodel->set(non_occupancy_channel_path, "OpClass",
                                                 non_occupancy_channel.operating_class_detected);
            ret_val &= m_ambiorix_datamodel->set(non_occupancy_channel_path, "Channel",
                                                 non_occupancy_channel.channel_detected);
            ret_val &= m_ambiorix_datamodel->set(non_occupancy_channel_path, "Seconds",
                                                 non_occupancy_channel.duration);
        }
    }

    if (!active_channels.empty()) {

        for (const auto &active_channel : active_channels) {
            auto active_channel_path =
                m_ambiorix_datamodel->add_instance(cac_status_path + ".CACActiveChannel");
            if (active_channel_path.empty()) {
                LOG(ERROR) << "Failed to add instance to " << cac_status_path
                           << ".CACActiveChannel";
                return false;
            }

            ret_val &= m_ambiorix_datamodel->set(active_channel_path, "OpClass",
                                                 active_channel.operating_class_active_cac);
            ret_val &= m_ambiorix_datamodel->set(active_channel_path, "Channel",
                                                 active_channel.channel_active_cac);
            uint32_t countdown;
            memcpy(&countdown, active_channel.countdown, sizeof(active_channel.countdown));
            ret_val &= m_ambiorix_datamodel->set(active_channel_path, "Countdown", countdown);
        }
    }

    ret_val &= m_ambiorix_datamodel->set_current_time(cac_status_path);

    return ret_val;
}

bool db::dm_update_collection_intervals(std::chrono::milliseconds interval)
{
    auto ret_val = true;

    auto agents = get_all_connected_agents();
    for (auto agent : agents) {
        ret_val &= m_ambiorix_datamodel->set(agent->dm_path, "CollectionInterval",
                                             (uint32_t)interval.count());
    }

    return ret_val;
}

bool db::update_last_contact_time(const sMacAddr &agent_mac)
{
    auto ret_val = true;
    auto agent   = m_agents.get(agent_mac);
    if (!agent) {
        LOG(WARNING) << "Agent with mac is not found in database mac=" << agent_mac;
        return false;
    }

    agent->last_contact_time = std::chrono::system_clock::now();
    ret_val = m_ambiorix_datamodel->set_current_time(agent->dm_path + ".MultiAPDevice",
                                                     "LastContactTime");
    return ret_val;
}

bool db::dm_set_agent_oui(std::shared_ptr<Agent> agent)
{

    std::string oui_string = tlvf::int_to_hex_string(agent->al_mac.oct[0], 2) +
                             tlvf::int_to_hex_string(agent->al_mac.oct[1], 2) +
                             tlvf::int_to_hex_string(agent->al_mac.oct[2], 2);

    transform(oui_string.begin(), oui_string.end(), oui_string.begin(), ::toupper);

    return m_ambiorix_datamodel->set(agent->dm_path + ".MultiAPDevice", "ManufacturerOUI",
                                     oui_string);
}

bool db::add_sta_steering_event(const sMacAddr &sta_mac, sStaSteeringEvent &event)
{

    // Updating station steering event map
    auto &sta_events = m_stations_steering_events[sta_mac];

    // Derivative usage of dm_check_objects_limit()
    while (MAX_EVENT_HISTORY_SIZE <= sta_events.size()) {

        auto path = get_dm_index_from_path(sta_events.front().dm_path);
        if (!m_ambiorix_datamodel->remove_instance(path.first, path.second)) {
            LOG(ERROR) << "Failed to remove " << sta_events.front().dm_path;
            return false;
        }

        sta_events.erase(sta_events.begin());
    }

    // Updating station datamodel incase of it is associated.
    auto station = get_station(sta_mac);
    if (!station) {
        LOG(TRACE) << "Station " << sta_mac << " not found in database";
        return false;
    }

    if (station->dm_path.empty()) {
        return true;
    }

    bool ret_val          = true;
    auto steering_history = station->dm_path + ".MultiAPSTA.SteeringHistory";

    auto steering_event_path = m_ambiorix_datamodel->add_instance(steering_history);
    if (steering_event_path.empty()) {
        LOG(ERROR) << "Failed to add instance to " << steering_history;
        return false;
    }

    LOG(DEBUG) << "Add station steering event to database sta:" << sta_mac;
    sta_events.push_back(event);

    // Update steering event data model path
    sta_events.back().dm_path = steering_event_path;

    ret_val &= m_ambiorix_datamodel->set(steering_event_path, "APOrigin", event.original_bssid);
    ret_val &= m_ambiorix_datamodel->set(steering_event_path, "APDestination", event.target_bssid);
    ret_val &=
        m_ambiorix_datamodel->set(steering_event_path, "SteeringDuration", event.duration.count());
    ret_val &=
        m_ambiorix_datamodel->set(steering_event_path, "SteeringApproach", event.steering_approach);
    ret_val &= m_ambiorix_datamodel->set(steering_event_path, "TriggerEvent", event.trigger_event);
    ret_val &= m_ambiorix_datamodel->set(steering_event_path, "Time", event.timestamp);

    return ret_val;
}

bool db::dm_restore_sta_steering_event(const Station &station)
{
    bool ret_val = true;

    auto &sta_events      = m_stations_steering_events[station.mac];
    auto steering_history = station.dm_path + ".MultiAPSTA.SteeringHistory";

    LOG(DEBUG) << "Restore Station steering events sta: " << station.mac
               << " event size:" << sta_events.size();

    for (auto &event : sta_events) {

        auto steering_event_path = m_ambiorix_datamodel->add_instance(steering_history);
        if (steering_event_path.empty()) {
            LOG(ERROR) << "Failed to add instance to " << steering_history;
            return false;
        }

        // Set steering event data model path
        event.dm_path = steering_event_path;

        ret_val &= m_ambiorix_datamodel->set(steering_event_path, "APOrigin",
                                             tlvf::mac_to_string(event.original_bssid));
        ret_val &= m_ambiorix_datamodel->set(steering_event_path, "APDestination",
                                             tlvf::mac_to_string(event.target_bssid));
        ret_val &= m_ambiorix_datamodel->set(steering_event_path, "SteeringDuration",
                                             event.duration.count());
        ret_val &= m_ambiorix_datamodel->set(steering_event_path, "SteeringApproach",
                                             event.steering_approach);
        ret_val &=
            m_ambiorix_datamodel->set(steering_event_path, "TriggerEvent", event.trigger_event);
        ret_val &= m_ambiorix_datamodel->set(steering_event_path, "Time", event.timestamp);
    }

    return ret_val;
}

bool db::dm_set_device_multi_ap_backhaul(const Agent &agent)
{
    bool ret_val = true;

    if (agent.dm_path.empty()) {
        return true;
    }

    const auto multiap_backhaul_path = agent.dm_path + ".MultiAPDevice.Backhaul";

    // Controller does not have any Backhaul, so leave it as TR-181 states it.
    if (agent.is_gateway) {
        ret_val &=
            m_ambiorix_datamodel->set(multiap_backhaul_path, "LinkType", std::string{"None"});
        ret_val &= m_ambiorix_datamodel->set(multiap_backhaul_path, "MACAddress", std::string{});
        ret_val &=
            m_ambiorix_datamodel->set(multiap_backhaul_path, "BackhaulMACAddress", std::string{});
        ret_val &=
            m_ambiorix_datamodel->set(multiap_backhaul_path, "BackhaulDeviceID", std::string{});
        return ret_val;
    }

    // TODO: Implement different link types (PPM-1656)
    std::string iface_link_str;
    switch (agent.backhaul.backhaul_iface_type) {
    case beerocks::IFACE_TYPE_WIFI_UNSPECIFIED:
    case beerocks::IFACE_TYPE_WIFI_INTEL:
        iface_link_str = "Wi-Fi";
        break;
    case beerocks::IFACE_TYPE_ETHERNET:
        iface_link_str = "Ethernet";
        break;
    default:
        LOG(INFO) << "Uncovered interface link type " << agent.backhaul.backhaul_iface_type
                  << " assign as None";
        iface_link_str = "None";
        break;
    }

    ret_val &= m_ambiorix_datamodel->set(multiap_backhaul_path, "LinkType", iface_link_str);
    ret_val &= m_ambiorix_datamodel->set(multiap_backhaul_path, "MACAddress",
                                         agent.backhaul.backhaul_interface);
    ret_val &= m_ambiorix_datamodel->set(multiap_backhaul_path, "BackhaulMACAddress",
                                         agent.backhaul.parent_interface);

    auto parent_agent = agent.backhaul.parent_agent.lock();
    if (!parent_agent) {

        //TODO: Error log could be added after (PPM-2043), otherwise it floods logs
        m_ambiorix_datamodel->set(multiap_backhaul_path, "BackhaulDeviceID", std::string{});
        return false;
    }
    ret_val &=
        m_ambiorix_datamodel->set(multiap_backhaul_path, "BackhaulDeviceID", parent_agent->al_mac);

    return ret_val;
}

bool db::dm_set_device_ssid_to_vid_map(const Agent &agent,
                                       const wireless_utils::sTrafficSeparationSsid &config)
{
    bool ret_val = true;

    if (agent.dm_path.empty()) {
        return true;
    }

    auto ssidtovidmapping_path =
        m_ambiorix_datamodel->add_instance(agent.dm_path + ".SSIDtoVIDMapping");
    if (ssidtovidmapping_path.empty()) {
        LOG(ERROR) << "Failed to add: " << agent.dm_path << ".SSIDtoVIDMapping";
        return false;
    }
    ret_val &= m_ambiorix_datamodel->set(ssidtovidmapping_path, "SSID", config.ssid);
    ret_val &= m_ambiorix_datamodel->set(ssidtovidmapping_path, "VID", config.vlan_id);

    return ret_val;
}

bool db::dm_set_default_8021q(const Agent &agent, const uint16_t primary_vlan_id,
                              const uint8_t default_pcp)
{
    bool ret_val = true;

    if (agent.dm_path.empty()) {
        return true;
    }

    if (!m_ambiorix_datamodel->remove_all_instances(agent.dm_path + ".Default8021Q")) {
        return false;
    }

    auto default_8021q_path = m_ambiorix_datamodel->add_instance(agent.dm_path + ".Default8021Q");
    if (default_8021q_path.empty()) {
        return false;
    }
    ret_val &= m_ambiorix_datamodel->set(default_8021q_path, "Enable", bool(primary_vlan_id > 0));
    ret_val &= m_ambiorix_datamodel->set(default_8021q_path, "PrimaryVID", primary_vlan_id);
    ret_val &= m_ambiorix_datamodel->set(default_8021q_path, "DefaultPCP", default_pcp);

    return ret_val;
}

bool db::dm_set_profile1_device_info(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &=
        m_ambiorix_datamodel->set(agent.dm_path, "Manufacturer", agent.device_info.manufacturer);
    ret_val &=
        m_ambiorix_datamodel->set(agent.dm_path, "SerialNumber", agent.device_info.serial_number);
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "ManufacturerModel",
                                         agent.device_info.manufacturer_model);
    return ret_val;
}

bool db::dm_set_profile3_device_info(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &=
        m_ambiorix_datamodel->set(agent.dm_path, "SerialNumber", agent.device_info.serial_number);
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "SoftwareVersion",
                                         agent.device_info.software_version);
    ret_val &=
        m_ambiorix_datamodel->set(agent.dm_path, "ExecutionEnv", agent.device_info.execution_env);
    ret_val &=
        m_ambiorix_datamodel->set(agent.dm_path, "CountryCode", agent.device_info.country_code);

    for (const auto &radio : agent.radios) {
        if (radio.second->dm_path.empty()) {
            continue;
        }

        ret_val &= m_ambiorix_datamodel->set(radio.second->dm_path, "ChipsetVendor",
                                             radio.second->chipset_vendor);
    }

    return ret_val;
}

bool db::dm_remove_radio(Agent::sRadio &radio)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    auto instance = get_dm_index_from_path(radio.dm_path);
    if (instance.first.empty()) {
        return false;
    }
    if (!m_ambiorix_datamodel->remove_instance(instance.first, instance.second)) {
        return false;
    }
    radio.dm_path.clear();
    return true;
}

bool db::dm_remove_bss(Agent::sRadio::sBss &bss)
{
    LOG(DEBUG) << "Removing BSS with path " << bss.dm_path << " from the datamodel";
    if (bss.dm_path.empty()) {
        return true;
    }

    auto bss_path = get_dm_index_from_path(bss.dm_path);
    if (!m_ambiorix_datamodel->remove_instance(bss_path.first, bss_path.second)) {
        LOG(ERROR) << "Failed to remove " << bss_path.first << bss_path.second << " instance.";
        return false;
    }
    bss.dm_path.clear();

    return true;
}

bool db::dm_set_radio_bh_sta(const Agent::sRadio &radio, const sMacAddr &bh_sta_mac)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    return m_ambiorix_datamodel->set(radio.dm_path + ".BackhaulSta", "MACAddress", bh_sta_mac);
}

bool db::dm_clear_radio_cac_capabilities(const Agent::sRadio &radio)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    return m_ambiorix_datamodel->remove_all_instances(radio.dm_path + ".CACCapability.CACMethod");
}

bool db::dm_add_radio_cac_capabilities(
    const Agent::sRadio &radio, const wfa_map::eCacMethod &method, const uint8_t &duration,
    const std::unordered_map<uint8_t, std::vector<uint8_t>> &oc_channels)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    auto cac_method_path =
        m_ambiorix_datamodel->add_instance(radio.dm_path + ".CACCapability.CACMethod");
    if (cac_method_path.empty()) {
        return false;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(cac_method_path, "Method", method);
    ret_val &= m_ambiorix_datamodel->set(cac_method_path, "NumberOfSeconds", duration);

    for (auto &oc_ch : oc_channels) {
        auto oc_channels_path =
            m_ambiorix_datamodel->add_instance(cac_method_path + ".OpClassChannels");
        if (oc_channels_path.empty()) {
            return false;
        }

        ret_val &= m_ambiorix_datamodel->set(oc_channels_path, "OpClass", oc_ch.first);

        for (auto &channel : oc_ch.second) {
            auto channels_path = m_ambiorix_datamodel->add_instance(oc_channels_path + ".Channel");
            if (oc_channels_path.empty()) {
                return false;
            }

            ret_val &= m_ambiorix_datamodel->set(channels_path, "Channel", channel);
        }
    }

    return ret_val;
}

bool db::dm_save_radio_cac_completion_report(wfa_map::cCacCompletionReportRadio &radioReport)
{
    auto radioMac = radioReport.radio_uid();
    auto pRadio   = get_radio_by_uid(radioMac);
    if (nullptr == pRadio) {
        return false;
    }
    if (pRadio->dm_path.empty()) {
        return true;
    }

    const auto CAC_completion_path       = pRadio->dm_path + ".CACCompletion";
    const auto CAC_completion_pairs_path = CAC_completion_path + ".Pairs";
    bool ret_val                         = true;

    // Clear old pairs instances
    if (!m_ambiorix_datamodel->remove_all_instances(CAC_completion_pairs_path)) {
        return false;
    }

    ret_val &= m_ambiorix_datamodel->set(CAC_completion_path, "OperatingClass",
                                         radioReport.operating_class());
    ret_val &= m_ambiorix_datamodel->set(CAC_completion_path, "Channel", radioReport.channel());
    ret_val &= m_ambiorix_datamodel->set(CAC_completion_path, "Status",
                                         static_cast<uint8_t>(radioReport.cac_completion_status()));

    for (size_t i = 0; i < radioReport.number_of_detected_pairs(); i++) {
        if (!std::get<0>(radioReport.detected_pairs(i))) {
            continue;
        }

        auto pair_path = m_ambiorix_datamodel->add_instance(CAC_completion_pairs_path);
        if (pair_path.empty()) {
            return false;
        }

        auto &detected_pair = std::get<1>(radioReport.detected_pairs(i));
        ret_val &= m_ambiorix_datamodel->set(pair_path, "OperatingClassDetected",
                                             detected_pair.operating_class_detected);
        ret_val &=
            m_ambiorix_datamodel->set(pair_path, "ChannelDetected", detected_pair.channel_detected);
    }

    return ret_val;
}

bool db::dm_add_radio_scan_capabilities(const Agent::sRadio &radio)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    auto scan_capability_path = radio.dm_path + ".ScanCapability";

    // Clearing ScanCapability data model object and its sub-objects.
    if (!m_ambiorix_datamodel->remove_all_instances(scan_capability_path)) {
        return false;
    }

    auto &scan_capabilities = radio.scan_capabilities;
    bool ret_val            = true;

    ret_val &= m_ambiorix_datamodel->set(scan_capability_path, "OnBootOnly",
                                         scan_capabilities.on_boot_only);
    ret_val &=
        m_ambiorix_datamodel->set(scan_capability_path, "Impact", scan_capabilities.scan_impact);
    ret_val &= m_ambiorix_datamodel->set(scan_capability_path, "MinimumInterval",
                                         scan_capabilities.minimum_scan_interval);

    if (scan_capabilities.operating_classes.empty()) {
        LOG(ERROR) << "Invalid number of operating classes for radio " << radio.radio_uid;
        return false;
    }

    for (auto &oc_ch : scan_capabilities.operating_classes) {
        auto oc_channels_path =
            m_ambiorix_datamodel->add_instance(scan_capability_path + ".OpClassChannels");
        if (oc_channels_path.empty()) {
            return false;
        }

        ret_val &= m_ambiorix_datamodel->set(oc_channels_path, "OpClass", oc_ch.first);

        for (auto &channel : oc_ch.second) {
            auto channels_path = m_ambiorix_datamodel->add_instance(oc_channels_path + ".Channel");
            if (oc_channels_path.empty()) {
                return false;
            }

            ret_val &= m_ambiorix_datamodel->set(channels_path, "Channel", channel);
        }
    }

    return ret_val;
}

bool db::dm_add_radio_akm_suite_capabilities(
    const Agent::sRadio &radio,
    const std::vector<wfa_map::tlvAkmSuiteCapabilities::sBssAkmSuiteSelector>
        &fronthaul_bss_selectors,
    const std::vector<wfa_map::tlvAkmSuiteCapabilities::sBssAkmSuiteSelector>
        &backhaul_bss_selectors)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    if (!m_ambiorix_datamodel->remove_all_instances(radio.dm_path + ".Capabilities.AKMFrontHaul")) {
        return false;
    }

    bool ret_val = true;

    for (auto &selector : fronthaul_bss_selectors) {
        auto akm_fronthaul_path =
            m_ambiorix_datamodel->add_instance(radio.dm_path + ".Capabilities.AKMFrontHaul");
        if (akm_fronthaul_path.empty()) {
            return false;
        }

        ret_val &= m_ambiorix_datamodel->set(akm_fronthaul_path, "OUI", selector.oui);
        ret_val &= m_ambiorix_datamodel->set(akm_fronthaul_path, "Type", selector.akm_suite_type);
    }

    if (!m_ambiorix_datamodel->remove_all_instances(radio.dm_path + ".Capabilities.AKMBackhaul")) {
        return false;
    }

    for (auto &selector : backhaul_bss_selectors) {
        auto akm_backhaul_path =
            m_ambiorix_datamodel->add_instance(radio.dm_path + ".Capabilities.AKMBackhaul");
        if (akm_backhaul_path.empty()) {
            return false;
        }

        ret_val &= m_ambiorix_datamodel->set(akm_backhaul_path, "OUI", selector.oui);
        ret_val &= m_ambiorix_datamodel->set(akm_backhaul_path, "Type", selector.akm_suite_type);
    }

    return ret_val;
}

bool db::dm_set_radio_advanced_capabilities(const Agent::sRadio &radio)
{
    if (radio.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(
        radio.dm_path, "TrafficSeparationCombinedFronthaul",
        radio.advanced_capabilities.traffic_separation_combined_fronthaul);
    ret_val &=
        m_ambiorix_datamodel->set(radio.dm_path, "TrafficSeparationCombinedBackhaul",
                                  radio.advanced_capabilities.traffic_separation_combined_backhaul);
    return ret_val;
}

bool db::dm_set_radio_vbss_capabilities(const sMacAddr &radio_uid, uint8_t max_vbss,
                                        bool vbsses_subtract, bool apply_vbssid_restrictions,
                                        bool apply_vbssid_match_mask_restrictions,
                                        bool apply_fixed_bits_restrictions,
                                        const sMacAddr &fixed_bits_mask,
                                        const sMacAddr &fixed_bits_value)
{

    auto radio = get_radio_by_uid(radio_uid);
    if (!radio) {
        LOG(ERROR) << "Failed to get radio with UID: " << radio_uid;
        return false;
    }

    if (radio->dm_path.empty()) {
        return true;
    }

    std::string vbss_caps_dm_path = radio->dm_path + ".Capabilities.VBSSCapabilities";

    bool ret_val = true;

    ret_val &= m_ambiorix_datamodel->set(vbss_caps_dm_path, "MaxVBSS", max_vbss);
    ret_val &= m_ambiorix_datamodel->set(vbss_caps_dm_path, "VBSSsSubtract", vbsses_subtract);
    ret_val &= m_ambiorix_datamodel->set(vbss_caps_dm_path, "ApplyVBSSIDRestrictions",
                                         apply_vbssid_restrictions);
    ret_val &= m_ambiorix_datamodel->set(vbss_caps_dm_path, "ApplyVBSSIDMatchMaskRestrictions",
                                         apply_vbssid_match_mask_restrictions);
    ret_val &= m_ambiorix_datamodel->set(vbss_caps_dm_path, "ApplyVBSSIDFixedBitsRestrictions",
                                         apply_fixed_bits_restrictions);
    ret_val &= m_ambiorix_datamodel->set(vbss_caps_dm_path, "VBSSIDFixedBitsMask", fixed_bits_mask);
    ret_val &=
        m_ambiorix_datamodel->set(vbss_caps_dm_path, "VBSSIDFixedBitsValue", fixed_bits_value);

    return ret_val;
}

bool db::dm_add_agent_1905_layer_security_capabilities(
    const Agent &agent,
    const wfa_map::tlv1905LayerSecurityCapability::eOnboardingProtocol &onboard_protocol,
    const wfa_map::tlv1905LayerSecurityCapability::eMicAlgorithm &integrity_algorithm,
    const wfa_map::tlv1905LayerSecurityCapability::eEncryptionAlgorithm &encryption_algorithm)
{
    m_ambiorix_datamodel->remove_all_instances(agent.dm_path + ".IEEE1905Security");

    auto ieee_1905_sec_path =
        m_ambiorix_datamodel->add_instance(agent.dm_path + ".IEEE1905Security");
    if (ieee_1905_sec_path.empty()) {
        return false;
    }

    bool ret_val = true;
    ret_val &=
        m_ambiorix_datamodel->set(ieee_1905_sec_path, "OnboardingProtocol", onboard_protocol);
    ret_val &=
        m_ambiorix_datamodel->set(ieee_1905_sec_path, "IntegrityAlgorithm", integrity_algorithm);
    ret_val &=
        m_ambiorix_datamodel->set(ieee_1905_sec_path, "EncryptionAlgorithm", encryption_algorithm);

    return ret_val;
}

bool db::dm_set_metric_reporting_policies(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "APMetricsReportingInterval",
                                         config.link_metrics_request_interval_seconds.count());

    for (const auto &radio : agent.radios) {
        if (radio.second->dm_path.empty()) {
            continue;
        }

        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "STAReportingRCPIThreshold",
            radio.second->metric_reporting_policies.sta_reporting_rcpi_threshold);
        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "STAReportingRCPIHysteresisMarginOverride",
            radio.second->metric_reporting_policies
                .sta_reporting_rcpi_hyst_margin_override_threshold);
        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "ChannelUtilizationReportingThreshold",
            radio.second->metric_reporting_policies.ap_reporting_channel_utilization_threshold);
        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "AssociatedSTATrafficStatsInclusionPolicy",
            radio.second->metric_reporting_policies.assoc_sta_traffic_stats_inclusion_policy);
        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "AssociatedSTALinkMetricsInclusionPolicy",
            radio.second->metric_reporting_policies.assoc_sta_link_metrics_inclusion_policy);
        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "APMetricsWiFi6",
            radio.second->metric_reporting_policies.assoc_wifi6_sta_status_report_inclusion_policy);
    }
    return ret_val;
}

bool db::dm_set_steering_policies(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;

    if (!m_ambiorix_datamodel->remove_all_instances(agent.dm_path +
                                                    ".LocalSteeringDisallowedSTA")) {
        return false;
    }

    for (auto &sta : agent.disallowed_local_steering_stations) {
        auto disallowed_local_steering_sta_path =
            m_ambiorix_datamodel->add_instance(agent.dm_path + ".LocalSteeringDisallowedSTA");
        if (disallowed_local_steering_sta_path.empty()) {
            return false;
        }

        ret_val &=
            m_ambiorix_datamodel->set(disallowed_local_steering_sta_path, "MACAddress", sta.first);
    }

    if (!m_ambiorix_datamodel->remove_all_instances(agent.dm_path +
                                                    ".BTMSteeringDisallowedSTAList")) {
        return false;
    }

    for (auto &sta : agent.disallowed_btm_steering_stations) {
        auto disallowed_btm_steering_sta_path =
            m_ambiorix_datamodel->add_instance(agent.dm_path + ".BTMSteeringDisallowedSTAList");
        if (disallowed_btm_steering_sta_path.empty()) {
            return false;
        }

        ret_val &=
            m_ambiorix_datamodel->set(disallowed_btm_steering_sta_path, "MACAddress", sta.first);
    }

    for (const auto &radio : agent.radios) {
        if (radio.second->dm_path.empty()) {
            continue;
        }

        ret_val &= m_ambiorix_datamodel->set(radio.second->dm_path, "SteeringPolicy",
                                             int(radio.second->steering_policies.steering_policy));
        ret_val &= m_ambiorix_datamodel->set(
            radio.second->dm_path, "ChannelUtilizationThreshold",
            radio.second->steering_policies.channel_utilization_threshold);
        ret_val &=
            m_ambiorix_datamodel->set(radio.second->dm_path, "RCPISteeringThreshold",
                                      radio.second->steering_policies.rcpi_steering_threshold);
    }
    return ret_val;
}

bool db::dm_set_device_multi_ap_profile(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    return m_ambiorix_datamodel->set(agent.dm_path, "MultiAPProfile", agent.profile);
}

bool db::dm_set_device_unsuccessful_association_policy(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "ReportUnsuccessfulAssociations",
                                         agent.unsuccessful_assoc_report_policy);
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "MaxReportingRate",
                                         agent.unsuccessful_assoc_max_reporting_rate);

    return ret_val;
}

bool db::dm_set_service_prioritization_rules(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;

    std::string dscp_map_str;
    std::transform(agent.service_prioritization.dscp_mapping_table.begin(),
                   agent.service_prioritization.dscp_mapping_table.end(),
                   std::back_inserter(dscp_map_str), [](int const &i) { return i + '0'; });

    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "DSCPMap", dscp_map_str);

    if (!m_ambiorix_datamodel->remove_all_instances(agent.dm_path + ".SPRule")) {
        return false;
    }

    for (const auto &rule : agent.service_prioritization.rules) {
        auto sp_rule_path = m_ambiorix_datamodel->add_instance(agent.dm_path + ".SPRule");
        if (sp_rule_path.empty()) {
            return false;
        }

        ret_val &= m_ambiorix_datamodel->set(sp_rule_path, "ID", rule.first);
        ret_val &= m_ambiorix_datamodel->set(sp_rule_path, "Precedence", rule.second.precedence);
        ret_val &= m_ambiorix_datamodel->set(sp_rule_path, "Output", rule.second.output);
        ret_val &= m_ambiorix_datamodel->set(sp_rule_path, "AlwaysMatch",
                                             rule.second.bits_field2.always_match);
    }

    return ret_val;
}

bool db::dm_configure_service_prioritization()
{
    const std::string cfgPath = "Device.WiFi.DataElements.Configuration.QoS";
    uint64_t ruleOutput{0};
    if (!m_ambiorix_datamodel->read_param(cfgPath, "SPRuleOutput", &ruleOutput)) {
        LOG(ERROR) << "no valid priority rule found at " << cfgPath;
        return false;
    }
    std::string dscpHex;
    m_ambiorix_datamodel->read_param(cfgPath, "DSCPMap", &dscpHex);

    for (auto it = m_agents.begin(); it != m_agents.end(); ++it) {
        auto &agent = it->second;

        agent->service_prioritization.rules.clear();

        wfa_map::tlvServicePrioritizationRule::sServicePrioritizationRule rule;
        rule.id                       = 1;
        rule.precedence               = 1;
        rule.output                   = static_cast<uint8_t>(ruleOutput);
        rule.bits_field1.add_remove   = 1;
        rule.bits_field2.always_match = 1;

        uint32_t id = rule.id;
        agent->service_prioritization.rules.insert({id, rule});

        auto &dscpTable = agent->service_prioritization.dscp_mapping_table;
        for (uint8_t i = 0; i < dscpTable.size(); ++i) {
            if (i < dscpHex.length()) {
                dscpTable[i] = dscpHex[i] - '0';
            } else {
                dscpTable[i] = 0;
            }
        }
    }

    return true;
}

bool db::dm_set_device_ap_capabilities(const Agent &agent)
{
    if (agent.dm_path.empty()) {
        return true;
    }

    bool ret_val = true;
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "MaxPrioritizationRules",
                                         agent.max_prioritization_rules);
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "PrioritizationSupport",
                                         agent.prioritization_support);
    ret_val &= m_ambiorix_datamodel->set(agent.dm_path, "MaxVIDs", agent.max_total_number_of_vids);
    return ret_val;
}

bool db::add_unassociated_station(sMacAddr const &new_station_mac_add, uint8_t channel,
                                  uint8_t operating_class, sMacAddr const &agent_mac_addr,
                                  sMacAddr const &radio_mac_addr)
{
    std::string new_station_mac_add_str(tlvf::mac_to_string(new_station_mac_add));
    std::string agent_mac_addr_str(tlvf::mac_to_string(agent_mac_addr));

    bool all_connected_agents =
        agent_mac_addr_str ==
        network_utils::
            ZERO_MAC_STRING; //flag if the command is for a specific agent or to all of them
    std::shared_ptr<UnassociatedStation> new_station(nullptr);

    //Lambda function responsbible of updating the datamodel
    //return false for any problem, otherwise true
    auto add_un_station_dm = [&](const std::string &agent_mac, const std::string &radio_mac,
                                 const std::string &station_mac) {
        //example Device.WiFi.DataElements.Network.Device.1.Radio.2.UnassociatedSTA.
        std::string device_path = "Device.WiFi.DataElements.Network.Device";

        //Device.WiFi.DataElements.Network.Device.1.Radio.2.UnassociatedSTA.1.MACAddress
        auto agent_path_index =
            m_ambiorix_datamodel->get_instance_index(device_path + ".[ID == '%s'].", agent_mac);
        if (agent_path_index == 0) {
            LOG(ERROR) << "could not find device/agent with mac_addr: " << agent_mac;
            return false;
        }
        auto radio_path_index = m_ambiorix_datamodel->get_instance_index(
            device_path + "." + std::to_string(agent_path_index) + ".Radio" + ".[ID == '%s'].",
            radio_mac);
        if (radio_path_index == 0) {
            LOG(ERROR) << "could not find radio path with ID " << radio_mac;
            return false;
        }
        std::string unassociated_sta_path = device_path + "." + std::to_string(agent_path_index) +
                                            ".Radio." + std::to_string(radio_path_index) +
                                            ".UnassociatedSTA";
        auto index = m_ambiorix_datamodel->get_instance_index(
            unassociated_sta_path + ".[MACAddress == '%s'].", station_mac);
        if (!index) {
            //add its!
            auto new_station_path = m_ambiorix_datamodel->add_instance(unassociated_sta_path);
            if (new_station_path.empty()) {
                LOG(ERROR) << "Failed to add new unassociated station stats with path "
                           << unassociated_sta_path;
                return false;
            } else {
                new_station_path.append(".");
                m_ambiorix_datamodel->set(new_station_path, "MACAddress", station_mac);
                LOG(DEBUG) << "Successfully added  UnassociatedSTA with path : "
                           << new_station_path;
            }
        } else {
            LOG(DEBUG) << "UnassociatedSTA with mac_addr " << station_mac
                       << " already exists! under path " << unassociated_sta_path << "."
                       << station_mac;
        }
        return true;
    };

    //Lambda function to update an existing un_station(related to one specific agent)
    //return false if the station has not been updated, true otherwise
    auto update_existing_un_station = [](std::shared_ptr<UnassociatedStation> &existing_un_station,
                                         const std::string &agent_mac_str, uint8_t new_channel,
                                         uint8_t new_operating_class) {
        if ((existing_un_station->get_channel() != new_channel)) {
            LOG(DEBUG) << " agent " << agent_mac_str << ", un_station "
                       << tlvf::mac_to_string(existing_un_station->get_mac_Address())
                       << "'s channel changed into " << new_channel;
            existing_un_station->set_channel(new_channel);
        }
        if ((existing_un_station->get_operating_class() != new_operating_class)) {
            LOG(DEBUG) << " agent " << agent_mac_str << ", un_station "
                       << tlvf::mac_to_string(existing_un_station->get_mac_Address())
                       << "'s operating_class changed into " << new_operating_class;
            existing_un_station->set_operating_class(new_operating_class);
        }
    };

    // lambda function to detect which radio supports the preferred  channel|operating_class
    // return pointer to radio if one of the radios supports channel and operating_class, else nullptr.
    auto get_agent_radio = [channel,
                            operating_class](const beerocks::mac_map<Agent::sRadio> &radios) {
        std::shared_ptr<Agent::sRadio> agent_radio = nullptr;

        for (auto &radio_it : radios) {
            auto &scan_capabilities = radio_it.second->scan_capabilities;
            for (auto &oc_ch : scan_capabilities.operating_classes) {
                if (oc_ch.first != operating_class) {
                    continue;
                }
                std::vector<uint8_t>::iterator iter =
                    std::find_if(oc_ch.second.begin(), oc_ch.second.end(),
                                 [channel](uint8_t input) { return (input == channel); });

                if (iter != oc_ch.second.end()) {
                    agent_radio = radio_it.second;
                    return agent_radio;
                }
            }
        }
        return agent_radio;
    };

    //lambda function to add/update an unassociated station related to a specific agent
    //return a shared pointer to the new  added/updated station, nullptr otherwise
    auto add_update_unassociated_station_within_agent =
        [&](const std::shared_ptr<Agent> &agent) -> std::shared_ptr<UnassociatedStation> {
        std::shared_ptr<UnassociatedStation> new_updated_station(nullptr);
        std::shared_ptr<Agent::sRadio> agent_radio(nullptr);
        if (radio_mac_addr == network_utils::ZERO_MAC) {
            agent_radio = get_agent_radio(agent->radios);
        } else {
            agent_radio = get_radio_by_uid(radio_mac_addr);
        }
        std::string agent_mac_addr_str = tlvf::mac_to_string(agent->al_mac);

        if (!agent_radio) {
            //The channel is not accepted/available for any radios! --> lets revert to the active channel in one radio
            // and warn the user!
            // NOTE: We do this "overwride" because the Specs allow the agent to use its active channel instead of the preferrred one received by the command!
            agent_radio               = agent->radios.begin()->second;
            uint8_t channel_overwrite = agent_radio->wifi_channel.get_channel();
            beerocks::message::sWifiChannel local(channel_overwrite,
                                                  agent_radio->wifi_channel.get_bandwidth());
            uint8_t operating_class_overwrite =
                wireless_utils::get_operating_class_by_channel(local);
            LOG(WARNING) << "add_unassociated_station : channel " << channel << ",operating_class "
                         << operating_class << " ARE NOT AVAILABE on any radios of agent "
                         << agent_mac_addr_str
                         << " -->  REVERTING to use active radio with mac_addr "
                         << tlvf::mac_to_string(agent_radio->radio_uid) << ",active channel "
                         << channel_overwrite << " and operating_class "
                         << operating_class_overwrite;
            channel         = channel_overwrite;
            operating_class = operating_class_overwrite;
        }

        if (!agent_radio->ap_capabilities
                 .support_unassociated_sta_link_metrics_on_operating_bssid ||
            !agent_radio->ap_capabilities
                 .support_unassociated_sta_link_metrics_on_non_operating_bssid) {
            LOG(ERROR) << "Agent  with mac_addr " << agent_mac_addr_str
                       << " does not support unassociated stations!!, un_station with mac_addr "
                       << new_station_mac_add_str << " will NOT be added.";
            return nullptr;
        }

        new_updated_station = m_unassociated_stations.get(new_station_mac_add);
        if (new_updated_station) {
            update_existing_un_station(new_updated_station, agent_mac_addr_str, channel,
                                       operating_class);
        } else {
            new_updated_station = m_unassociated_stations.add(new_station_mac_add);
            new_updated_station->set_channel(channel);
            new_updated_station->set_operating_class(operating_class);
        }
        new_updated_station->add_agent(agent_mac_addr, agent_radio->radio_uid);

        LOG(DEBUG) << "added un_station with mac_address " + new_station_mac_add_str + ",channel " +
                          std::to_string(channel) + ",operating_class " +
                          std::to_string(operating_class) + " to monitoring agent " +
                          agent_mac_addr_str;

        //lets update the data model
        add_un_station_dm(agent_mac_addr_str, tlvf::mac_to_string(agent_radio->radio_uid),
                          new_station_mac_add_str);

        return new_updated_station;
    };

    if (!all_connected_agents) { //This case treats 1 single agent
        auto existing_agent = m_agents.get(agent_mac_addr);
        if (existing_agent == nullptr) {
            LOG(ERROR) << " agent with mac_addr " << agent_mac_addr_str
                       << " could not be found! station will not be added. ";
            return false;
        } else {
            new_station = add_update_unassociated_station_within_agent(existing_agent);
        }
        return new_station != nullptr;
    } else { //all connected agents
        bool status(true);
        for (auto &agent : m_agents) {
            new_station = add_update_unassociated_station_within_agent(agent.second);
            if (new_station == nullptr) {
                status = false;
            }
        }

        return status;
    }
}

bool db::remove_unassociated_station(sMacAddr const &mac_address, sMacAddr const &agent_mac_addr,
                                     sMacAddr const &radio_mac_addr)
{

    auto remove_un_staton_from_dm = [&](std::string agent_mac, std::string station_mac) {
        LOG(DEBUG) << "removing un_station with mac_addr " << mac_address
                   << " connected to agent with mac_addr " << agent_mac
                   << " on radio: " << tlvf::mac_to_string(radio_mac_addr);
        //example Device.WiFi.DataElements.Network.Device.1.Radio.2.UnassociatedSTA.
        std::string device_path = "Device.WiFi.DataElements.Network.Device";
        sMacAddr radio_mac(radio_mac_addr);
        if (radio_mac == network_utils::ZERO_MAC) {
            // if not given as an argument, for example, from a bml command--> deduc it from the db
            auto station = m_unassociated_stations.get(tlvf::mac_from_string(station_mac));
            if (station != nullptr) {
                station->get_radio_mac(tlvf::mac_from_string(agent_mac), radio_mac);
            } else {
                LOG(ERROR) << "radio_mac for agent with mac_addr: " << agent_mac
                           << " not found!,  failure to remove station with mac: " << station_mac;
                return false;
            }
        };
        //Device.WiFi.DataElements.Network.Device.1.Radio.2.UnassociatedSTA.1.MACAddress
        auto agent_path_index =
            m_ambiorix_datamodel->get_instance_index(device_path + ".[ID == '%s'].", agent_mac);

        if (agent_path_index == 0) {
            LOG(ERROR) << "could not find device/agent with mac_addr: " << agent_mac;
            return false;
        }

        auto radio_path_index = m_ambiorix_datamodel->get_instance_index(
            device_path + "." + std::to_string(agent_path_index) + ".Radio" + ".[ID == '%s'].",
            tlvf::mac_to_string(radio_mac));

        if (radio_path_index == 0) {
            LOG(ERROR) << "could not find radio path with ID " << tlvf::mac_to_string(radio_mac);
            return false;
        }

        std::string unassociated_sta_path = device_path + "." + std::to_string(agent_path_index) +
                                            ".Radio." + std::to_string(radio_path_index) +
                                            ".UnassociatedSTA";

        auto index = m_ambiorix_datamodel->get_instance_index(
            unassociated_sta_path + ".[MACAddress == '%s'].", station_mac);
        if (index == 0) {
            LOG(ERROR) << " UnassociatedSTA with mac " << station_mac
                       << " does not exists under the path " << unassociated_sta_path;
            return false;
        } else {
            if (m_ambiorix_datamodel->remove_instance(unassociated_sta_path, index)) {
                LOG(DEBUG) << " Successfully removed un_station with mac_addr  " << station_mac
                           << " with the path " << unassociated_sta_path << "." << station_mac;
                return true;
            } else
                return false;
        }
        return true;
    };

    auto un_station = m_unassociated_stations.get(mac_address);
    bool all_connected_agents =
        tlvf::mac_to_string(agent_mac_addr) == network_utils::ZERO_MAC_STRING;
    if (!un_station) {
        LOG(ERROR) << " unassociated station with mac_addr: " << tlvf::mac_to_string(mac_address)
                   << " is not being monitored!";
        return false;
    }

    if (!all_connected_agents) {
        if (un_station->get_agents().find(agent_mac_addr) != un_station->get_agents().end()) {

            auto result = remove_un_staton_from_dm(tlvf::mac_to_string(agent_mac_addr),
                                                   tlvf::mac_to_string(mac_address));

            m_unassociated_stations.erase(mac_address);
            LOG(DEBUG) << "successfully removed un_station with mac_address:"
                       << tlvf::mac_to_string(mac_address) << " from the database";
            if (result == false) {
                LOG(ERROR) << tlvf::mac_to_string(mac_address)
                           << " was not removed from the datamodel!!";
            }
        } else {
            LOG(ERROR) << "un_station with mac:" << tlvf::mac_to_string(mac_address)
                       << " is not being monitored by " << tlvf::mac_to_string(agent_mac_addr);
            return false;
        }
    } else { // remove it for all connected agents
             // first remove all instance in the datamodel
        for (auto &agent : un_station->get_agents()) {
            auto result = remove_un_staton_from_dm(tlvf::mac_to_string(agent.first),
                                                   tlvf::mac_to_string(mac_address));
            if (result == false) {
                LOG(ERROR) << tlvf::mac_to_string(mac_address)
                           << " not found OR not removed from the datamodel!!";
            }
        }
        if (m_unassociated_stations.erase(mac_address) == 1) {
            LOG(DEBUG) << "db: removed station with mac_address:" << mac_address;

        } else {
            LOG(DEBUG) << "db: failed to remove un_station with mac_address:" << mac_address;
            return false;
        }
    }
    return true;
}

const beerocks::mac_map<UnassociatedStation> &db::get_unassociated_stations() const
{
    return m_unassociated_stations;
}

void db::update_unassociated_station_stats(const sMacAddr &mac_address,
                                           UnassociatedStation::Stats &new_stats,
                                           const std::string &radio_dm_path = std::string())
{
    auto station = m_unassociated_stations.find(mac_address);
    if (station != m_unassociated_stations.end()) {
        station->second->update_stats(new_stats);

        // update  controller DM
        //Example of path : Device.WiFi.DataElements.Network.Device.1.Radio.2.UnassociatedSTA.
        std::string new_station_path;
        if (!radio_dm_path.empty()) {
            std::string unassociated_sta_path = radio_dm_path + ".UnassociatedSTA";
            auto index                        = m_ambiorix_datamodel->get_instance_index(
                unassociated_sta_path + ".[MACAddress == '%s'].", tlvf::mac_to_string(mac_address));
            if (!index) {
                LOG(ERROR) << " UnassociatedSTA with mac " << mac_address
                           << " does not exists under the path " << unassociated_sta_path << " !";

                new_station_path = m_ambiorix_datamodel->add_instance(unassociated_sta_path);
                if (new_station_path.empty()) {
                    LOG(ERROR) << "Failed to add new unassociated station stats with path "
                               << unassociated_sta_path;
                    return;
                } else {
                    new_station_path.append(".");
                    LOG(DEBUG) << "Successfully added object with path : " << new_station_path;
                }
            } else {
                new_station_path.append(".");
                new_station_path.append(std::to_string(index));
            }
            m_ambiorix_datamodel->set(new_station_path, "MACAddress", mac_address);
            m_ambiorix_datamodel->set(new_station_path, " SignalStrength",
                                      new_stats.uplink_rcpi_dbm_enc);
            m_ambiorix_datamodel->set_time(new_station_path, new_stats.time_stamp);
            LOG(DEBUG) << "Setting MACAddress " << mac_address
                       << "SignalStrength: " << new_stats.uplink_rcpi_dbm_enc << " TimeStamp"
                       << new_stats.time_stamp;
        }
    }
    return;
}

std::list<std::pair<std::string, std::shared_ptr<UnassociatedStation::Stats>>>
db::get_unassociated_stations_stats() const
{
    std::list<std::pair<std::string, std::shared_ptr<UnassociatedStation::Stats>>> stats;
    for (auto &station : m_unassociated_stations) {
        auto stat(std::make_shared<UnassociatedStation::Stats>());
        stat->time_stamp          = station.second->get_stats().time_stamp;
        stat->uplink_rcpi_dbm_enc = station.second->get_stats().uplink_rcpi_dbm_enc;
        stats.push_back(std::make_pair(tlvf::mac_to_string(station.first), stat));
    }
    return stats;
}

bool db::link_metrics_data::add_transmitter_link_metric(
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

bool db::link_metrics_data::add_receiver_link_metric(
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

bool db::ap_metrics_data::add_ap_metric_data(std::shared_ptr<wfa_map::tlvApMetrics> ApMetricData)
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

std::shared_ptr<Agent::sEthSwitch> db::get_eth_switch(const sMacAddr &mac)
{
    std::shared_ptr<Agent::sEthSwitch> eth_switch;
    for (const auto &agent : m_agents) {
        eth_switch = agent.second->eth_switches.get(mac);
        if (eth_switch) {
            break;
        }
    }

    return eth_switch;
}
