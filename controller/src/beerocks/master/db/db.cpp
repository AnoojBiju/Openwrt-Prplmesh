/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "db.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/sockets.h>
#include <bcl/son/son_wireless_utils.h>
#include <bpl/bpl_db.h>
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

std::shared_ptr<prplmesh::controller::db::sAgent::sRadio> db::get_radio(const sMacAddr &al_mac,
                                                                        const sMacAddr &radio_uid)
{
    auto agent = m_agents.get(al_mac);
    if (!agent) {
        LOG(ERROR) << "No agent found for al_mac " << al_mac;
        return {};
    }
    auto radio = agent->radios.get(radio_uid);
    return radio;
}

void db::set_log_level_state(const beerocks::eLogLevel &log_level, const bool &new_state)
{
    logger.set_log_level_state(log_level, new_state);
}

// General set/get

bool db::has_node(const sMacAddr &mac)
{
    auto n = get_node(mac);
    return (n != nullptr);
}

bool db::add_virtual_node(const sMacAddr &mac, const sMacAddr &real_node_mac)
{
    //TODO prototype code, untested
    if (mac == network_utils::ZERO_MAC) {
        LOG(ERROR) << "can't insert node with empty mac";
        return false;
    }

    auto real_node = get_node(real_node_mac);

    if (!real_node) {
        LOG(ERROR) << "node " << real_node_mac << " does not exist";
        return false;
    }

    /*
     * TODO
     * the regular add_node() function should take care of a situation where the real node
     * already exists and is moved to a different hierarchy
     * it should be able to find its virtual nodes and move them to the appropriate hierarchy as well
     */

    nodes[real_node->hierarchy].insert(std::make_pair(tlvf::mac_to_string(mac), real_node));
    return true;
}

bool db::add_node(const sMacAddr &mac, const sMacAddr &parent_mac, beerocks::eType type,
                  const sMacAddr &radio_identifier)
{
    if (mac == network_utils::ZERO_MAC) {
        LOG(ERROR) << "can't insert node with empty mac";
        return false;
    }

    auto parent_node = get_node(parent_mac);
    // if parent node does not exist, new_hierarchy will be equal to 0
    int new_hierarchy = get_node_hierarchy(parent_node) + 1;
    if (new_hierarchy >= HIERARCHY_MAX) {
        LOG(ERROR) << "hierarchy too high for node " << mac;
        return false;
    }

    auto n = get_node(mac);
    if (n) { // n is not nullptr
        LOG(DEBUG) << "node with mac " << mac << " already exists, updating";
        n->set_type(type);
        if (n->parent_mac != tlvf::mac_to_string(parent_mac)) {
            n->previous_parent_mac = n->parent_mac;
            n->parent_mac          = tlvf::mac_to_string(parent_mac);
        }
        int old_hierarchy = get_node_hierarchy(n);
        if (old_hierarchy >= 0 && old_hierarchy < HIERARCHY_MAX) {
            nodes[old_hierarchy].erase(tlvf::mac_to_string(mac));
        } else {
            LOG(ERROR) << "old hierarchy " << old_hierarchy << " for node " << mac
                       << " is invalid!!!";
        }
        auto subtree = get_node_subtree(n);
        int offset   = new_hierarchy - old_hierarchy;
        adjust_subtree_hierarchy(subtree, offset);
    } else {
        LOG(DEBUG) << "node with mac " << mac << " being created, the type is " << type;
        n             = std::make_shared<node>(type, tlvf::mac_to_string(mac));
        n->parent_mac = tlvf::mac_to_string(parent_mac);
    }
    n->radio_identifier = tlvf::mac_to_string(radio_identifier);
    n->hierarchy        = new_hierarchy;
    nodes[new_hierarchy].insert(std::make_pair(tlvf::mac_to_string(mac), n));

    if (radio_identifier != network_utils::ZERO_MAC) {
        std::string ruid_key = get_node_key(tlvf::mac_to_string(parent_mac), n->radio_identifier);
        if (ruid_key.empty()) {
            LOG(ERROR) << "can't insert node with empty RUID";
            return false;
        }
        // if already exists set instead of insert
        if (get_node(ruid_key)) {
            nodes[new_hierarchy].erase(ruid_key);
        }
        nodes[new_hierarchy].insert(std::make_pair(ruid_key, n));
    }

    return true;
}

bool db::set_node_data_model_path(const sMacAddr &mac, const std::string &data_model_path)
{
    auto node = get_node(mac);
    if (!node) {
        LOG(ERROR) << "Failed to add set data model path, node " << mac << " does not exist";
        return false;
    }

    node->dm_path = data_model_path;
    return true;
}

std::string db::get_node_data_model_path(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return {};
    }
    return n->dm_path;
}

bool db::add_node_gateway(const sMacAddr &mac, const sMacAddr &radio_identifier)
{
    if (!add_node(mac, network_utils::ZERO_MAC, beerocks::TYPE_GW, radio_identifier)) {
        LOG(ERROR) << "Failed to add gateway node, mac: " << mac;
        return false;
    }

    m_agents.add(mac);

    auto data_model_path = dm_add_device_element(mac);
    if (data_model_path.empty()) {
        LOG(ERROR) << "Failed to add device element for the gateway, mac: " << mac;
        return false;
    }

    set_node_data_model_path(mac, data_model_path);

    if (!dm_set_device_multi_ap_capabilities(tlvf::mac_to_string(mac))) {
        LOG(ERROR) << "Failed to set multi ap capabilities";
        return {};
    }

    return true;
}

bool db::add_node_ire(const sMacAddr &mac, const sMacAddr &parent_mac,
                      const sMacAddr &radio_identifier)
{
    if (!add_node(mac, parent_mac, beerocks::TYPE_IRE, radio_identifier)) {
        LOG(ERROR) << "Failed to add ire node, mac: " << mac;
        return false;
    }

    m_agents.add(mac);

    auto data_model_path = dm_add_device_element(mac);
    if (data_model_path.empty()) {
        LOG(ERROR) << "Failed to add device element for the ire, mac: " << mac;
        return false;
    }

    set_node_data_model_path(mac, data_model_path);

    if (!dm_set_device_multi_ap_capabilities(tlvf::mac_to_string(mac))) {
        LOG(ERROR) << "Failed to set multi ap capabilities";
        return {};
    }

    return true;
}

bool db::add_node_wireless_bh(const sMacAddr &mac, const sMacAddr &parent_mac,
                              const sMacAddr &radio_identifier)
{
    if (!add_node(mac, parent_mac, beerocks::TYPE_IRE_BACKHAUL, radio_identifier)) {
        LOG(ERROR) << "Failed to add wireless_bh node, mac: " << mac;
        return false;
    }

    // TODO: Add instance for Radio.BackhaulSta element from the Data Elements
    return true;
}

bool db::add_node_wired_bh(const sMacAddr &mac, const sMacAddr &parent_mac,
                           const sMacAddr &radio_identifier)
{
    if (!add_node(mac, parent_mac, beerocks::TYPE_ETH_SWITCH, radio_identifier)) {
        LOG(ERROR) << "Failed to add wired_bh node, mac: " << mac;
        return false;
    }

    // TODO: Add node to the controller data model via m_ambiorix_datamodel for Wired BH agent
    return true;
}

std::string db::dm_add_radio_element(const std::string &radio_mac, const std::string &device_mac)
{
    std::string path_to_obj = "Controller.Network.Device.";
    uint32_t index =
        m_ambiorix_datamodel->get_instance_index(path_to_obj + "[ID == '%s'].", device_mac);

    if (!index) {
        LOG(ERROR) << "Failed to get Controller.Network.Device index for mac: " << device_mac;
        return {};
    }

    // Prepare path to the Radio object, like Device.Network.{i}.Radio
    path_to_obj += std::to_string(index) + ".Radio";

    auto radio_instance = m_ambiorix_datamodel->add_instance(path_to_obj);
    if (radio_instance.empty()) {
        LOG(ERROR) << "Failed to add instance " << radio_instance << ". Radio mac: " << radio_mac;
        return {};
    }

    // Prepare path to the Radio object ID, like Device.Network.{i}.Radio.{i}.ID
    if (!m_ambiorix_datamodel->set(radio_instance, "ID", radio_mac)) {
        LOG(ERROR) << "Failed to set " << radio_instance << "ID: " << radio_mac;
        return {};
    }

    return radio_instance;
}

bool db::add_node_radio(const sMacAddr &mac, const sMacAddr &parent_mac,
                        const sMacAddr &radio_identifier)
{
    if (!add_node(mac, parent_mac, beerocks::TYPE_SLAVE, radio_identifier)) {
        LOG(ERROR) << "Failed to add radio node, mac: " << mac;
        return false;
    }

    auto agent = m_agents.get(parent_mac);
    if (!agent) {
        LOG(ERROR) << "While adding radio " << mac << " parent agent " << parent_mac
                   << " not found.";
        return false;
    }
    agent->radios.add(mac);

    auto data_model_path =
        dm_add_radio_element(tlvf::mac_to_string(mac), tlvf::mac_to_string(parent_mac));

    if (data_model_path.empty()) {
        LOG(ERROR) << "Failed to add radio element, mac: " << mac;
        return false;
    }

    set_node_data_model_path(mac, data_model_path);

    return true;
}

bool db::add_node_client(const sMacAddr &mac, const sMacAddr &parent_mac,
                         const sMacAddr &radio_identifier)
{
    if (!add_node(mac, parent_mac, beerocks::TYPE_CLIENT, radio_identifier)) {
        LOG(ERROR) << "Failed to add client node, mac: " << mac;
        return false;
    }

    // Add STA to the controller data model via m_ambiorix_datamodel
    // for connected station (WiFI client)
    auto data_model_path = dm_add_sta_element(parent_mac, mac);
    if (data_model_path.empty()) {
        LOG(ERROR) << "Failed to add client instance, mac: " << mac;
        return false;
    }
    // Add the MAC to the association event */
    if (dm_add_association_event(parent_mac, mac).empty()) {
        LOG(ERROR) << "Failed to add association event, mac: " << mac;
    }

    set_node_data_model_path(mac, data_model_path);

    return true;
}

bool db::remove_node(const sMacAddr &mac)
{
    if (m_agents.erase(mac) != 1) {
        LOG(ERROR) << "remove_node: no agent with mac " << mac << " found";
        // Since the code paths leading up to this are a bit iffy, don't return false in this case.
    }

    int i;
    for (i = 0; i < HIERARCHY_MAX; i++) {
        auto it = nodes[i].find(tlvf::mac_to_string(mac));
        if (it != nodes[i].end()) {
            std::string ruid_key =
                get_node_key(it->second->parent_mac, it->second->radio_identifier);
            std::string node_mac = it->second->mac;

            if (last_accessed_node_mac == tlvf::mac_to_string(mac)) {
                last_accessed_node_mac = std::string();
                last_accessed_node     = nullptr;
            }

            // map may include 2 keys to same node - if so remove other key-node pair from map
            // if removed by mac
            if (tlvf::mac_to_string(mac) == node_mac) {
                it = nodes[i].erase(it);
                // if ruid_key exists for this node
                if (!ruid_key.empty()) {
                    nodes[i].erase(ruid_key);
                }
                // if removed by ruid_key
            } else if (tlvf::mac_to_string(mac) == ruid_key) {
                nodes[i].erase(node_mac);
            }

            auto index = m_ambiorix_datamodel->get_instance_index("Network.Device.[ID == '%s'].",
                                                                  tlvf::mac_to_string(mac));
            if (!index) {
                LOG(ERROR) << "Failed to get Network.Device index for mac: " << mac;
                return false;
            }

            if (!m_ambiorix_datamodel->remove_instance("Network.Device", index)) {
                LOG(ERROR) << "Failed to remove Network.Device." << index << " instance.";
                return false;
            }

            return true;
        }
    }

    return false;
}

bool db::set_node_type(const std::string &mac, beerocks::eType type)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->set_type(type);
    return true;
}

beerocks::eType db::get_node_type(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return beerocks::TYPE_UNDEFINED;
    }
    return n->get_type();
}

bool db::set_local_slave_mac(const std::string &mac)
{
    if (!local_slave_mac.empty()) {
        LOG(WARNING) << "local_slave_mac != empty";
    }
    local_slave_mac = mac;
    return true;
}

std::string db::get_local_slave_mac() { return local_slave_mac; }

bool db::set_node_ipv4(const std::string &mac, const std::string &ipv4)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->ipv4 = ipv4;
    return true;
}

std::string db::get_node_ipv4(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return std::string();
    }
    return n->ipv4;
}

bool db::set_node_manufacturer(const std::string &mac, const std::string &manufacturer)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->manufacturer = manufacturer;
    return true;
}

std::string db::get_node_manufacturer(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return std::string();
    }
    return n->manufacturer;
}

int db::get_node_channel(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return 0;
    }
    return n->channel;
}

int db::get_hostap_operating_class(const sMacAddr &mac)
{
    auto mac_str = tlvf::mac_to_string(mac);
    auto n       = get_node(mac_str);
    if (!n) {
        LOG(WARNING) << "node " << mac_str << " does not exist!";
        return 0;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || !n->hostap) {
        LOG(WARNING) << "node " << mac_str << " is not a valid hostap!";
        return 0;
    }
    return n->hostap->operating_class;
}

bool db::set_node_vap_id(const std::string &mac, int8_t vap_id)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->vap_id = vap_id;
    return true;
}

int8_t db::get_node_vap_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return beerocks::IFACE_ID_INVALID;
    }
    return n->vap_id;
}

bool db::get_cs_op_flag(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    return n->cs_op;
}

bool db::set_cs_op_flag(const std::string &mac, bool flag)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->cs_op = flag;
    return true;
}

bool db::get_cs_lb_flag(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    return n->cs_lb;
}

bool db::set_cs_lb_flag(const std::string &mac, bool flag)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->cs_lb = flag;
    return true;
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

bool db::set_hostap_conf_restricted_channels(const sMacAddr &hostap_mac,
                                             const uint8_t *restricted_channels)
{
    auto n = get_node(hostap_mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << hostap_mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << hostap_mac << " is not a valid hostap!";
        return false;
    } else if (!restricted_channels) {
        LOG(WARNING) << __FUNCTION__ << "node " << hostap_mac << " restricted_channels not valid";
        return false;
    }
    n->hostap->conf_restricted_channels.clear();
    std::copy(restricted_channels, restricted_channels + message::RESTRICTED_CHANNEL_LENGTH,
              std::back_inserter(n->hostap->conf_restricted_channels));
    for (auto elm : n->hostap->conf_restricted_channels) {
        LOG(WARNING) << __FUNCTION__ << " elm = " << int(elm);
    }
    return true;
}

std::vector<uint8_t> db::get_hostap_conf_restricted_channels(const sMacAddr &hostap_mac)
{
    auto n = get_node(hostap_mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << hostap_mac << " does not exist!";
        return std::vector<uint8_t>();
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << hostap_mac << " is not a valid hostap!";
        return std::vector<uint8_t>();
    }
    return n->hostap->conf_restricted_channels;
}

bool db::fill_radio_channel_scan_capabilites(
    const sMacAddr &radio_mac, wfa_map::cRadiosWithScanCapabilities &radio_capabilities)
{
    LOG(DEBUG) << "Fill radio channel scan capabilities for " << radio_mac;
    auto node = get_node(radio_mac);
    if (!node) {
        LOG(WARNING) << __FUNCTION__ << " - node " << radio_mac << " does not exist!";
        return false;
    }

    if (node->get_type() != beerocks::TYPE_SLAVE || node->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << radio_mac << " is not a valid radio!";
        return false;
    }

    node->hostap->scan_capabilities.on_boot_only = radio_capabilities.capabilities().on_boot_only;
    node->hostap->scan_capabilities.scan_impact  = radio_capabilities.capabilities().scan_impact;
    node->hostap->scan_capabilities.minimum_scan_interval =
        radio_capabilities.minimum_scan_interval();

    std::stringstream ss;
    ss << "on_boot_only=" << std::hex << int(node->hostap->scan_capabilities.on_boot_only)
       << std::endl
       << "scan_impact=" << std::oct << int(node->hostap->scan_capabilities.scan_impact)
       << std::endl
       << "minimum_scan_interval=" << int(node->hostap->scan_capabilities.minimum_scan_interval)
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

        //std::vector<beerocks::message::sWifiChannel> channels_list;
        auto &operating_classes = node->hostap->scan_capabilities.operating_classes;
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

            beerocks::message::sWifiChannel wifi_channel;
            wifi_channel.channel = *channel;
            //channels_list.push_back(wifi_channel);
            operating_classes[operating_class].push_back(wifi_channel);
        }
    }

    // Print the received channel scan capabilites
    LOG(DEBUG) << ss.str();

    return true;
}

bool db::set_node_beacon_measurement_support_level(
    const std::string &mac, beerocks::eBeaconMeasurementSupportLevel support_beacon_measurement)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    if (!n->supports_beacon_measurement) { // sticky
        n->supports_beacon_measurement = support_beacon_measurement;
    }
    return true;
}

beerocks::eBeaconMeasurementSupportLevel
db::get_node_beacon_measurement_support_level(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return beerocks::BEACON_MEAS_UNSUPPORTED;
    }
    return n->supports_beacon_measurement;
}

bool db::set_node_name(const std::string &mac, std::string name)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->name = name;
    return true;
}

std::string db::get_node_name(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return std::string();
    }
    return n->name;
}

bool db::set_node_state(const std::string &mac, beerocks::eNodeState state)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->state             = state;
    n->last_state_change = std::chrono::steady_clock::now();
    return true;
}

beerocks::eNodeState db::get_node_state(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::STATE_MAX;
    }
    return n->state;
}

bool db::set_node_operational_state(const std::string &bridge_mac, bool operational)
{
    auto n = get_node(bridge_mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << bridge_mac << " does not exist!";
        return false;
    }

    if (n->get_type() != beerocks::TYPE_GW && n->get_type() != beerocks::TYPE_IRE) {
        LOG(WARNING) << __FUNCTION__ << " - node " << bridge_mac << " is not bridge type ";
        return false;
    }

    n->operational_state = operational;
    return true;
}

int8_t db::get_node_operational_state(const std::string &bridge_mac)
{
    auto n = get_node(bridge_mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << bridge_mac << " does not exist!";
        return -1;
    }

    if (n->get_type() != beerocks::TYPE_GW && n->get_type() != beerocks::TYPE_IRE) {
        LOG(WARNING) << __FUNCTION__ << " - node " << bridge_mac << " is not bridge type";
        return -1;
    }

    return n->operational_state;
}

std::chrono::steady_clock::time_point db::get_last_state_change(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return std::chrono::steady_clock::time_point();
    }
    return n->last_state_change;
}

bool db::set_node_handoff_flag(const std::string &mac, bool handoff)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->handoff = handoff;
    if (n->get_type() == beerocks::TYPE_IRE_BACKHAUL) {
        n->ire_handoff = handoff;
    }
    return true;
}

bool db::get_node_handoff_flag(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }

    if (n->get_type() == beerocks::TYPE_IRE_BACKHAUL) {
        return n->ire_handoff;
    } else {
        return n->handoff;
    }
}

bool db::set_node_confined_flag(const std::string &mac, bool flag)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->confined = flag;
    return true;
}

bool db::get_node_confined_flag(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    return n->confined;
}

bool db::update_node_last_seen(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->last_seen = std::chrono::steady_clock::now();
    return true;
}

std::chrono::steady_clock::time_point db::get_node_last_seen(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::chrono::steady_clock::now();
    }

    return n->last_seen;
}

std::unordered_map<sMacAddr, std::unordered_map<sMacAddr, son::node::link_metrics_data>> &
db::get_link_metric_data_map()
{
    return m_link_metric_data;
}

std::unordered_map<sMacAddr, son::node::ap_metrics_data> &db::get_ap_metric_data_map()
{
    return m_ap_metric_data;
}

bool db::set_hostap_active(const sMacAddr &mac, bool active)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        return false;
    }
    n->hostap->active = active;

    // Enabled variable is a part of Radio data element and
    // need to get path like Controller.Device.{i}.Radio.{i}. for setting Enabled variable
    auto radio_enable_path = n->dm_path;

    if (radio_enable_path.empty()) {
        LOG(ERROR) << "Failed to get path to the Radio with mac: " << mac;
        return false;
    }

    if (!m_ambiorix_datamodel->set(radio_enable_path, "Enabled", active)) {
        LOG(ERROR) << "Failed to set " << radio_enable_path << "Enabled: " << active;
        return false;
    }

    return true;
}

bool db::is_hostap_active(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    return n->hostap->active;
}

bool db::set_hostap_backhaul_manager(const sMacAddr &mac, bool is_backhaul_manager)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        return false;
    }
    n->hostap->is_backhaul_manager = is_backhaul_manager;
    return true;
}

bool db::is_hostap_backhaul_manager(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    return n->hostap->is_backhaul_manager;
}

std::string db::get_hostap_backhaul_manager(const std::string &ire)
{
    auto n = get_node(ire);
    if (!n) {
        LOG(ERROR) << "node " << ire << " does not exist!";
        return std::string();
    } else if (n->get_type() != beerocks::TYPE_IRE && n->get_type() != beerocks::TYPE_GW) {
        LOG(ERROR) << "ire " << ire << " not an IRE or GW";
        return std::string();
    }
    auto ire_hostaps = get_node_children(ire, beerocks::TYPE_SLAVE);
    for (auto &hostap : ire_hostaps) {
        if ((is_hostap_backhaul_manager(tlvf::mac_from_string(hostap))) &&
            get_node_state(hostap) == beerocks::STATE_CONNECTED) {
            return hostap;
        }
    }
    LOG(ERROR) << "ire " << ire << " return empty backhaul";
    return std::string();
}

bool db::is_ap_out_of_band(const std::string &mac, const std::string &sta_mac)
{
    bool client_on_5ghz =
        (wireless_utils::which_freq(get_node_channel(sta_mac)) == eFreqType::FREQ_5G);

    if (((wireless_utils::which_freq(get_node_channel(mac)) == eFreqType::FREQ_24G) &&
         client_on_5ghz) ||
        ((wireless_utils::which_freq(get_node_channel(mac)) == eFreqType::FREQ_5G) &&
         (!client_on_5ghz))) {
        return true;
    }
    return false;
}

bool db::is_node_wireless(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    return utils::is_node_wireless(n->iface_type);
}

std::string db::node_to_string(const std::string &mac)
{
    auto n = get_node(mac);
    std::ostringstream os;
    if (n != nullptr) {
        os << n;
    } else {
        os << "";
    }
    return os.str();
}
//
// DB node functions (get only)
//
int db::get_node_hierarchy(const std::string &mac)
{
    auto n = get_node(mac);
    return get_node_hierarchy(n);
}

std::set<std::string> db::get_nodes(int type)
{
    std::set<std::string> ret;
    for (auto node_map : nodes) {
        for (auto kv : node_map) {
            if ((type < 0 || kv.second->get_type() == type) && (kv.second->mac == kv.first)) {
                ret.insert(kv.first);
            }
        }
    }
    return ret;
}

std::set<std::string> db::get_device_nodes()
{
    std::set<std::string> ret;
    for (auto node_map : nodes) {
        for (auto kv : node_map) {
            if ((kv.second->get_type() != beerocks::TYPE_SLAVE) && (kv.second->mac == kv.first)) {
                ret.insert(kv.first);
            }
        }
    }
    return ret;
}

std::set<std::string> db::get_active_hostaps()
{
    std::set<std::string> ret;
    for (auto node_map : nodes) {
        for (auto kv : node_map) {
            if (kv.second->get_type() == beerocks::TYPE_SLAVE && kv.second->hostap != nullptr &&
                kv.second->state == beerocks::STATE_CONNECTED && kv.first == kv.second->mac &&
                kv.second->hostap->active) {
                ret.insert(kv.first);
            }
        }
    }
    return ret;
}

std::set<std::string> db::get_all_connected_ires()
{
    std::set<std::string> ret;
    for (auto node_map : nodes) {
        for (auto kv : node_map) {
            if (((kv.second->get_type() == beerocks::TYPE_IRE) &&
                 (kv.second->state == beerocks::STATE_CONNECTED)) ||
                (kv.second->get_type() == beerocks::TYPE_GW)) {
                ret.insert(kv.first);
            }
        }
    }
    return ret;
}

std::set<std::string> db::get_all_backhaul_manager_slaves()
{
    std::set<std::string> ret;
    for (auto node_map : nodes) {
        for (auto kv : node_map) {
            if (kv.second->get_type() == beerocks::TYPE_SLAVE && kv.second->hostap != nullptr &&
                kv.first == kv.second->mac && kv.second->hostap->is_backhaul_manager) {
                ret.insert(kv.first);
            }
        }
    }
    return ret;
}

std::set<std::string> db::get_nodes_from_hierarchy(int hierarchy, int type)
{
    std::set<std::string> result;

    if (hierarchy < 0 || hierarchy >= HIERARCHY_MAX) {
        LOG(ERROR) << "invalid hierarchy";
        return result;
    }

    for (auto kv : nodes[hierarchy]) {
        if ((type < 0 || kv.second->get_type() == type) && (kv.second->mac == kv.first)) {
            result.insert(kv.first);
        }
    }

    return result;
}
std::string db::get_gw_mac()
{
    auto gw_container = get_nodes_from_hierarchy(0, beerocks::TYPE_GW);
    if (gw_container.empty()) {
        LOG(ERROR) << "can't get GW node!";
        return std::string();
    }

    auto gw_mac = *gw_container.begin();
    LOG(DEBUG) << "gw_mac = " << gw_mac;
    return gw_mac;
}

std::set<std::string> db::get_node_subtree(const std::string &mac)
{
    std::set<std::string> subtree;

    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << "node " << mac << " does not exist!";
    }
    auto subtree_ = get_node_subtree(n);
    for (auto s : subtree_) {
        subtree.insert(s->mac);
    }
    return subtree;
}

std::string db::get_node_parent(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << "node " << mac << " does not exist!";
        return std::string();
    }
    return n->parent_mac;
}

std::string db::get_node_parent_hostap(const std::string &mac)
{
    std::string parent_backhaul = get_node_parent_backhaul(mac);
    if (is_node_wireless(parent_backhaul)) {
        return get_node_parent(parent_backhaul);
    } else {
        LOG(DEBUG) << "node " << parent_backhaul << " is not connected wirelessly";
        return std::string();
    }
}

std::string db::get_node_parent_backhaul(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::string();
    }

    std::string ire;
    if (n->get_type() == beerocks::TYPE_IRE) {
        ire = mac;
    } else {
        ire = get_node_parent_ire(mac);
    }

    return get_node_parent(ire);
}

std::string db::get_node_parent_ire(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n || n->get_type() == beerocks::TYPE_GW) {
        return std::string();
    }

    std::shared_ptr<node> p;
    do {
        p = get_node(n->parent_mac);
        if (!p) {
            LOG(DEBUG) << "node " << mac << " has no valid parent IRE";
            return std::string();
        }
        n = p;
    } while (p->get_type() != beerocks::TYPE_IRE && p->get_type() != beerocks::TYPE_GW);

    return p->mac;
}

std::string db::get_node_previous_parent(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << "node " << mac << " does not exist!";
        return std::string();
    }
    return n->previous_parent_mac;
}

std::set<std::string> db::get_node_siblings(const std::string &mac, int type)
{
    std::set<std::string> siblings;
    auto n = get_node(mac);

    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist";
        return siblings;
    }

    auto parent = get_node(n->parent_mac);
    if (!parent) {
        LOG(WARNING) << "parent for node " << mac << " does not exist";
        return siblings;
    }

    int hierarchy = get_node_hierarchy(parent) + 1;
    if (hierarchy >= 0 && hierarchy < HIERARCHY_MAX) {
        for (auto &it : nodes[hierarchy]) {
            if (it.first == it.second->mac) {
                auto sib = it.second;
                if ((sib->parent_mac == parent->mac) && (mac != sib->mac) &&
                    (type == beerocks::TYPE_ANY || sib->get_type() == type)) {
                    siblings.insert(sib->mac);
                }
            }
        }
    }
    return siblings;
}

std::set<std::string> db::get_node_children(const std::string &mac, int type, int state)
{
    std::set<std::string> children_macs;
    auto n = get_node(mac);

    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist";
        return children_macs;
    }

    std::set<std::shared_ptr<node>> children_nodes;
    if (n->mac == mac) {
        children_nodes = get_node_children(n, type, state);
    } else {
        children_nodes = get_node_children(n, type, state, mac);
    }
    for (auto c : children_nodes) {
        children_macs.insert(c->mac);
    }
    return children_macs;
}

std::list<sMacAddr> db::get_1905_1_neighbors(const sMacAddr &al_mac)
{
    auto al_mac_str = tlvf::mac_to_string(al_mac);
    std::list<sMacAddr> neighbors_al_macs;
    auto all_al_macs = get_nodes(beerocks::TYPE_IRE);

    // According to IEEE 1905.1 a neighbor is defined as a first circle only, so we need to filter
    // out the childrens from second circle and above.
    for (const auto &al_mac_iter : all_al_macs) {
        if (get_node_parent_ire(al_mac_iter) == al_mac_str) {
            neighbors_al_macs.push_back(tlvf::mac_from_string(al_mac_iter));
        }
    }

    // Add the parent bridge as well to the neighbors list
    auto parent_bridge = get_node_parent_ire(tlvf::mac_to_string(al_mac));
    if (!parent_bridge.empty()) {
        neighbors_al_macs.push_back(tlvf::mac_from_string(parent_bridge));
    }

    // Add siblings Nodes
    auto siblings = get_node_siblings(al_mac_str, beerocks::TYPE_IRE);
    for (const auto &sibling : siblings) {
        neighbors_al_macs.push_back(tlvf::mac_from_string(sibling));
    }

    return neighbors_al_macs;
}

//
// Capabilities
//

bool db::set_ap_vht_capabilities(wfa_map::tlvApVhtCapabilities &vht_caps_tlv)
{
    auto radio_node = get_node(vht_caps_tlv.radio_uid());
    auto flags1     = vht_caps_tlv.flags1();
    auto flags2     = vht_caps_tlv.flags2();
    bool return_val = true;

    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node with mac: " << vht_caps_tlv.radio_uid();
        return false;
    }

    auto path_to_obj = radio_node->dm_path;
    if (path_to_obj.empty()) {
        LOG(ERROR) << "Failed to get path to Radio object";
        return false;
    }

    path_to_obj += ".Capabilities.";
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "VHTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object" << path_to_obj << "VHTCapabilities";
        return false;
    }
    path_to_obj += "VHTCapabilities.";
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_Tx_MCS",
                                   vht_caps_tlv.supported_vht_tx_mcs())) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_Tx_MCS: " << vht_caps_tlv.supported_vht_tx_mcs();
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_Rx_MCS",
                                   vht_caps_tlv.supported_vht_rx_mcs())) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_Rx_MCS: " << vht_caps_tlv.supported_vht_rx_mcs();
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "tx_spatial_streams",
                                   flags1.max_num_of_supported_tx_spatial_streams + 1)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "tx_spatial_streams: " << flags1.max_num_of_supported_tx_spatial_streams + 1;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "rx_spatial_streams",
                                   flags1.max_num_of_supported_rx_spatial_streams + 1)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "rx_spatial_streams: " << flags1.max_num_of_supported_rx_spatial_streams + 1;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_80_MHz",
                                   static_cast<bool>(flags1.short_gi_support_80mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_80_MHz: " << static_cast<bool>(flags1.short_gi_support_80mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(
            path_to_obj, "GI_160_MHz",
            static_cast<bool>(flags1.short_gi_support_160mhz_and_80_80mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "GI_160_MHz: "
                   << static_cast<bool>(flags1.short_gi_support_160mhz_and_80_80mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_80_80_MHz",
                                   static_cast<bool>(flags2.vht_support_80_80mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_80_80_MHz: " << static_cast<bool>(flags2.vht_support_80_80mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_160_MHz",
                                   static_cast<bool>(flags2.vht_support_160mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_160_MHz: " << static_cast<bool>(flags2.vht_support_160mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "SU_beamformer",
                                   static_cast<bool>(flags2.su_beamformer_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "SU_beamformer: " << static_cast<bool>(flags2.su_beamformer_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "MU_beamformer",
                                   static_cast<bool>(flags2.mu_beamformer_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "MU_beamformer: " << static_cast<bool>(flags2.mu_beamformer_capable);
        return_val = false;
    }
    return return_val;
}

bool db::dm_add_ap_operating_classes(const std::string &radio_mac, uint8_t max_tx_power,
                                     uint8_t op_class,
                                     const std::vector<uint8_t> &non_operable_channels)
{
    auto radio_node   = get_node(radio_mac);
    bool return_value = true;

    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio with mac: " << radio_mac;
        return false;
    }

    std::string path_to_obj = radio_node->dm_path;
    if (path_to_obj.empty()) {
        LOG(ERROR) << "Failed to find path to radio with mac: " << radio_mac;
        return false;
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
    auto radio_node = get_node(he_caps_tlv.radio_uid());

    if (!radio_node) {
        LOG(ERROR) << "Fail get radio node, mac:" << he_caps_tlv.radio_uid();
        return false;
    }

    auto path_to_obj = radio_node->dm_path;
    auto flags1      = he_caps_tlv.flags1();
    auto flags2      = he_caps_tlv.flags2();
    bool return_val  = true;

    if (path_to_obj.empty()) {
        LOG(ERROR) << "Failed to get path to object";
        return false;
    }

    path_to_obj += ".Capabilities.";
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "HECapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_obj << "HECapabilities";
        return false;
    }

    path_to_obj += "HECapabilities.";
    if (!m_ambiorix_datamodel->set(path_to_obj, "HE_8080_MHz",
                                   static_cast<bool>(flags1.he_support_80_80mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "HE_8080_MHz: " << static_cast<bool>(flags1.he_support_80_80mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "HE_160_MHz",
                                   static_cast<bool>(flags1.he_support_160mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "HE_160_MHz: " << static_cast<bool>(flags1.he_support_160mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "SU_Beamformer",
                                   static_cast<bool>(flags2.su_beamformer_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "SU_beamformer: " << static_cast<bool>(flags2.su_beamformer_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "MU_Beamformer",
                                   static_cast<bool>(flags2.mu_beamformer_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "MU_Beamformer: " << static_cast<bool>(flags2.mu_beamformer_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "UL_MU_MIMO",
                                   static_cast<bool>(flags2.ul_mu_mimo_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "UL_MU_MIMO: " << static_cast<bool>(flags2.ul_mu_mimo_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "UL_MU_MIMO_OFDMA",
                                   static_cast<bool>(flags2.ul_mu_mimo_and_ofdm_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "UL_MU_MIMO_OFDMA: " << static_cast<bool>(flags2.ul_mu_mimo_and_ofdm_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "DL_MU_MIMO_OFDMA",
                                   static_cast<bool>(flags2.dl_mu_mimo_and_ofdm_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "DL_MU_MIMO_OFDMA: " << static_cast<bool>(flags2.dl_mu_mimo_and_ofdm_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "UL_OFDMA",
                                   static_cast<bool>(flags2.ul_ofdm_capable))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "UL_OFDMA: " << static_cast<bool>(flags2.ul_ofdm_capable);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "tx_spatial_streams",
                                   flags1.max_num_of_supported_tx_spatial_streams + 1)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "tx_spatial_streams: " << flags1.max_num_of_supported_tx_spatial_streams + 1;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "rx_spatial_streams",
                                   flags1.max_num_of_supported_rx_spatial_streams + 1)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "rx_spatial_streams: " << flags1.max_num_of_supported_rx_spatial_streams + 1;
        return_val = false;
    }

    uint8_t supported_he_mcs_length = he_caps_tlv.supported_he_mcs_length();
    path_to_obj += "supported_MCS";
    for (int i = 0; i < supported_he_mcs_length; i++) {
        auto path_to_obj_instance = m_ambiorix_datamodel->add_instance(path_to_obj);
        if (path_to_obj_instance.empty()) {
            LOG(ERROR) << "Failed to add " << path_to_obj;
            return_val = false;
            continue;
        }
        if (!m_ambiorix_datamodel->set(path_to_obj_instance + '.', "MCS",
                                       *he_caps_tlv.supported_he_mcs(i))) {
            LOG(WARNING) << "Failed to set " << path_to_obj_instance
                         << "MCS: " << he_caps_tlv.supported_he_mcs(i);
            return_val = false;
        }
    }
    return return_val;
}

const beerocks::message::sRadioCapabilities *
db::get_station_current_capabilities(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return nullptr;
    }
    return (&n->capabilities);
}

bool db::dm_set_sta_he_capabilities(const std::string &path_to_sta,
                                    const beerocks::message::sRadioCapabilities &sta_cap)
{
    bool return_val = true;

    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_sta, "HECapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_sta << "HECapabilities";
        return false;
    }
    std::string path_to_obj = path_to_sta + "HECapabilities.";
    if (!m_ambiorix_datamodel->set(path_to_obj, "rx_spatial_streams", sta_cap.ht_ss)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "rx_spatial_streams: " << sta_cap.ht_ss;
        return_val = false;
    }
    // To do: find value for tx_spatial_streams PPM-792.
    // Parse the (Re)Association Request frame.
    if (!m_ambiorix_datamodel->set(path_to_obj, "tx_spatial_streams", sta_cap.ht_ss)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "tx_spatial_streams: " << sta_cap.ht_ss;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_80_80_MHz",
                                   BANDWIDTH_80_80 <= sta_cap.vht_bw)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_80_80_MHz: " << (BANDWIDTH_80_80 <= sta_cap.vht_bw);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_160_MHz",
                                   static_cast<bool>(sta_cap.vht_high_bw_short_gi))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_160_MHz: " << static_cast<bool>(sta_cap.vht_high_bw_short_gi);
        return_val = false;
    }
    // To do: For rest of the values need to parse
    // (Re)Association Request frame PPM-792
    if (!m_ambiorix_datamodel->set(path_to_obj, "SU_Beamformer", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "SU_Beamformer: " << false;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "MU_Beamformer", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "MU_Beamformer: " << false;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "UL_MU_MIMO", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "UL_MU_MIMO: " << false;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "UL_MU_MIMO_OFDMA", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "UL_MU_MIMO_OFDMA: " << false;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "DL_MU_MIMO_OFDMA", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "DL_MU_MIMO_OFDMA: " << false;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "UL_OFDMA", false)) {
        LOG(ERROR) << "Failed to set  " << path_to_obj << "UL_OFDMA: " << false;
        return_val = false;
    }
    return return_val;
}

bool db::dm_set_sta_ht_capabilities(const std::string &path_to_sta,
                                    const beerocks::message::sRadioCapabilities &sta_cap)
{
    bool return_val = true;

    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_sta, "HTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_sta << "HTCapabilities";
        return false;
    }
    std::string path_to_obj = path_to_sta + "HTCapabilities.";
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_20_MHz",
                                   static_cast<bool>(sta_cap.ht_low_bw_short_gi))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_20_MHz: " << static_cast<bool>(sta_cap.ht_low_bw_short_gi);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_40_MHz",
                                   static_cast<bool>(sta_cap.ht_high_bw_short_gi))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_40_MHz: " << static_cast<bool>(sta_cap.ht_high_bw_short_gi);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "HT_40_Mhz", static_cast<bool>(sta_cap.ht_bw))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "HT_40_Mhz: " << static_cast<bool>(sta_cap.ht_bw);
        return_val = false;
    }
    // TODO: find value for tx_spatial_streams PPM-792.
    // Parse the (Re)Association Request frame.
    if (!m_ambiorix_datamodel->set(path_to_obj, "tx_spatial_streams", sta_cap.ht_ss)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "tx_spatial_streams: " << sta_cap.ht_ss;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "rx_spatial_streams", sta_cap.ht_ss)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "rx_spatial_streams: " << sta_cap.ht_ss;
        return_val = false;
    }
    return return_val;
}

bool db::dm_set_sta_vht_capabilities(const std::string &path_to_sta,
                                     const beerocks::message::sRadioCapabilities &sta_cap)
{
    bool return_val = true;

    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_sta, "VHTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_sta << "VHTCapabilities";
        return false;
    }
    std::string path_to_obj = path_to_sta + "VHTCapabilities.";
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_Tx_MCS", sta_cap.default_mcs)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "VHT_Tx_MCS: " << sta_cap.default_mcs;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_Rx_MCS", sta_cap.vht_mcs)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "VHT_Rx_MCS: " << sta_cap.vht_mcs;
        return_val = false;
    }
    // TODO: find value for tx_spatial_streams PPM-792.
    // Parse the (Re)Association Request frame.
    if (!m_ambiorix_datamodel->set(path_to_obj, "tx_spatial_streams", sta_cap.vht_ss)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "tx_spatial_streams: " << sta_cap.vht_ss;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "rx_spatial_streams", sta_cap.vht_ss)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "rx_spatial_streams: " << sta_cap.vht_ss;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_80_MHz",
                                   static_cast<bool>(sta_cap.vht_low_bw_short_gi))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_80_MHz: " << static_cast<bool>(sta_cap.vht_low_bw_short_gi);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_160_MHz",
                                   static_cast<bool>(sta_cap.vht_high_bw_short_gi))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_160_MHz: " << static_cast<bool>(sta_cap.vht_high_bw_short_gi);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_80_80_MHz",
                                   (BANDWIDTH_80_80 <= sta_cap.vht_bw))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_80_80_MHz: " << (BANDWIDTH_80_80 <= sta_cap.vht_bw);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "VHT_160_MHz", (BANDWIDTH_160 <= sta_cap.vht_bw))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "VHT_160_MHz: " << (BANDWIDTH_160 <= sta_cap.vht_bw);
        return_val = false;
    }
    // TODO: find value for SU_beamformer and MU_beamformer PPM-792.
    // Parse the (Re)Association Request frame.
    if (!m_ambiorix_datamodel->set(path_to_obj, "SU_beamformer", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "SU_beamformer: " << false;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "MU_beamformer", false)) {
        LOG(ERROR) << "Failed to set " << path_to_obj << "MU_beamformer: " << false;
        return_val = false;
    }
    return return_val;
}

bool db::set_station_capabilities(const std::string &client_mac,
                                  const beerocks::message::sRadioCapabilities &sta_cap)
{
    auto n = get_node(client_mac);

    if (!n) {
        LOG(ERROR) << "client node not found " << client_mac;
        return false;
    }

    auto parent_radio = get_node_parent_radio(client_mac);

    if (parent_radio.empty()) {
        LOG(ERROR) << "parent radio node found for client " << client_mac;
        return false;
    }

    if (is_node_5ghz(parent_radio)) {
        n->m_sta_5ghz_capabilities       = sta_cap;
        n->m_sta_5ghz_capabilities.valid = true;
        n->capabilities                  = n->m_sta_5ghz_capabilities;

    } else {
        n->m_sta_24ghz_capabilities       = sta_cap;
        n->m_sta_24ghz_capabilities.valid = true;
        n->capabilities                   = n->m_sta_24ghz_capabilities;
    }

    // Prepare path to the STA
    // Example: Controller.Network.Device.1.Radio.1.BSS.1.STA.1
    std::string path_to_sta = n->dm_path;

    if (path_to_sta.empty()) {
        return true;
    }

    path_to_sta += '.';
    // Remove previous capabilities objects, if they exist
    m_ambiorix_datamodel->remove_optional_subobject(path_to_sta, "HTCapabilities");
    m_ambiorix_datamodel->remove_optional_subobject(path_to_sta, "VHTCapabilities");

    // TODO: Remove HECapabilities before setting new one.

    if (sta_cap.ht_bw != 0xFF && !dm_set_sta_ht_capabilities(path_to_sta, sta_cap)) {
        LOG(ERROR) << "Failed to set station HT Capabilities";
        return false;
    }
    if (sta_cap.vht_bw != 0xFF && !dm_set_sta_vht_capabilities(path_to_sta, sta_cap)) {
        LOG(ERROR) << "Failed to set station VHT Capabilities";
        return false;
    }

    // TODO: Fill up HE Capabilities for STA, PPM-567

    std::string path_to_eventdata =
        "Controller.Notification.AssociationEvent.AssociationEventData.";
    int index = m_assoc_indx[client_mac].back();

    if (index) {
        path_to_eventdata += std::to_string(index) + '.';
    } else {
        path_to_eventdata = dm_add_association_event(tlvf::mac_from_string(parent_radio),
                                                     tlvf::mac_from_string(client_mac));
        if (path_to_eventdata.empty()) {
            return false;
        }
    }

    // Remove previous entry
    m_ambiorix_datamodel->remove_optional_subobject(path_to_eventdata, "HTCapabilities");
    m_ambiorix_datamodel->remove_optional_subobject(path_to_eventdata, "VHTCapabilities");
    // TODO: Remove HECapabilities before setting new one.

    // Fill up HT Capabilities for Controller.Notification.AssociationEvent.AssociationEventData.1
    if (sta_cap.ht_bw != 0xFF && !dm_set_sta_ht_capabilities(path_to_eventdata, sta_cap)) {
        LOG(ERROR) << "Failed to set station HT Capabilities into " << path_to_eventdata;
        return false;
    }
    // Fill up VHT Capabilities for Controller.Notification.AssociationEvent.AssociationEventData.1
    if (sta_cap.vht_bw != 0xFF && !dm_set_sta_vht_capabilities(path_to_eventdata, sta_cap)) {
        LOG(ERROR) << "Failed to set station VHT Capabilities into " << path_to_eventdata;
        return false;
    }

    // TODO: Fill up HE Capabilities for Controller.Notification.AssociationEvent, PPM-567

    return true;
}

const beerocks::message::sRadioCapabilities *
db::get_station_capabilities(const std::string &client_mac, bool is_bandtype_5ghz)
{
    std::shared_ptr<node> n = get_node(client_mac);

    if (!n) {
        LOG(ERROR) << "Gateway node not found.... ";
        return nullptr;
    }

    if (is_bandtype_5ghz) {
        if (n->m_sta_5ghz_capabilities.valid == true) {
            return &n->m_sta_5ghz_capabilities;
        } else {
            return nullptr;
        }
    } else {
        if (n->m_sta_24ghz_capabilities.valid == true) {
            return &n->m_sta_24ghz_capabilities;
        } else {
            return nullptr;
        }
    }
}

bool db::set_hostap_ant_num(const sMacAddr &mac, beerocks::eWiFiAntNum ant_num)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    n->capabilities.ant_num = ant_num;
    return true;
}

beerocks::eWiFiAntNum db::get_hostap_ant_num(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::ANT_NONE;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return beerocks::ANT_NONE;
    }
    return beerocks::eWiFiAntNum(n->capabilities.ant_num);
}

bool db::set_hostap_ant_gain(const sMacAddr &mac, int ant_gain)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->ant_gain = ant_gain;
    return true;
}

int db::get_hostap_ant_gain(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->ant_gain;
}

bool db::set_hostap_tx_power(const sMacAddr &mac, int tx_power)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->tx_power = tx_power;
    return true;
}

int db::get_hostap_tx_power(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->tx_power;
}

bool db::set_hostap_supported_channels(const sMacAddr &mac,
                                       beerocks::message::sWifiChannel *channels, int length)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    std::vector<beerocks::message::sWifiChannel> supported_channels_(channels, channels + length);
    n->hostap->supported_channels = supported_channels_;

    if (n->hostap->supported_channels.size() == 0) {
        LOG(ERROR) << "No supported channels";
        return false;
    }

    if (wireless_utils::which_freq(n->hostap->supported_channels[0].channel) ==
        eFreqType::FREQ_5G) {
        n->supports_5ghz = true;
    } else if (wireless_utils::which_freq(n->hostap->supported_channels[0].channel) ==
               eFreqType::FREQ_24G) {
        n->supports_24ghz = true;
    } else {
        LOG(ERROR) << "unknown frequency! channel:"
                   << int(n->hostap->supported_channels[0].channel);
        return false;
    }

    return true;
}

std::vector<beerocks::message::sWifiChannel> db::get_hostap_supported_channels(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::vector<beerocks::message::sWifiChannel>();
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return std::vector<beerocks::message::sWifiChannel>();
    }
    return n->hostap->supported_channels;
}

std::string db::get_hostap_supported_channels_string(const sMacAddr &radio_mac)
{
    std::ostringstream os;
    auto supported_channels = get_hostap_supported_channels(radio_mac);
    for (const auto &val : supported_channels) {
        if (val.channel > 0) {
            os << " ch = " << int(val.channel) << " | dfs = " << int(val.is_dfs_channel)
               << " | bw = " << int(val.channel_bandwidth) << " | tx_pow = " << int(val.tx_pow)
               << " | noise = " << int(val.noise) << " [dbm]"
               << " | bss_overlap = " << int(val.bss_overlap) << std::endl;
        }
    }

    return os.str();
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
    auto supported_channels = get_hostap_supported_channels(radio_mac);
    auto channel_set        = wireless_utils::operating_class_to_channel_set(operating_class);
    auto class_bw           = wireless_utils::operating_class_to_bandwidth(operating_class);
    // Update current channels
    for (auto c : channel_set) {
        auto channel = std::find_if(
            supported_channels.begin(), supported_channels.end(),
            [&c](const beerocks::message::sWifiChannel &ch) { return ch.channel == c; });
        if (channel != supported_channels.end()) {
            channel->tx_pow            = tx_power;
            channel->channel_bandwidth = class_bw;
        } else {
            beerocks::message::sWifiChannel ch;
            ch.channel           = c;
            ch.tx_pow            = tx_power;
            ch.channel_bandwidth = class_bw;
            supported_channels.push_back(ch);
        }
    }

    // Delete non-operable channels
    for (auto c : non_operable_channels) {
        auto channel = std::find_if(
            supported_channels.begin(), supported_channels.end(),
            [&c](const beerocks::message::sWifiChannel &ch) { return ch.channel == c; });
        if (channel != supported_channels.end())
            supported_channels.erase(channel);
    }

    // Set values for Controller.Network.Device.Radio.Capabilities.OperatingClasses
    dm_add_ap_operating_classes(tlvf::mac_to_string(radio_mac), tx_power, operating_class,
                                non_operable_channels);

    set_hostap_supported_channels(radio_mac, &supported_channels[0], supported_channels.size());
    // dump new supported channels state
    // LOG(DEBUG) << "New supported channels for hostap" << radio_mac << " operating class "
    //            << int(operating_class) << std::endl
    //            << get_hostap_supported_channels_string(radio_mac);

    return true;
}

bool db::set_hostap_band_capability(const sMacAddr &mac, beerocks::eRadioBandCapability capability)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->capability = capability;
    return true;
}

beerocks::eRadioBandCapability db::get_hostap_band_capability(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::SUBBAND_CAPABILITY_UNKNOWN;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return beerocks::SUBBAND_CAPABILITY_UNKNOWN;
    }
    return n->hostap->capability;
}

bool db::capability_check(const std::string &mac, int channel)
{
    auto band       = wireless_utils::which_subband(channel);
    auto capability = get_hostap_band_capability(tlvf::mac_from_string(mac));
    if (band == beerocks::SUBBAND_UNKNOWN || capability == beerocks::SUBBAND_CAPABILITY_UNKNOWN) {
        LOG(ERROR) << "band or capability unknown!!";
        return false;
    } else if (int(band) == int(capability) || capability == beerocks::BOTH_SUBBAND) {
        return true;
    }
    return false;
}

bool db::get_node_5ghz_support(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    return n->supports_5ghz;
}

bool db::get_node_24ghz_support(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    return n->supports_24ghz;
}

bool db::is_node_24ghz(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(ERROR) << "node " << mac << " does not exist! return false as default";
        return false;
    }
    if (wireless_utils::which_freq(n->channel) == eFreqType::FREQ_24G) {
        return true;
    }
    return false;
}

bool db::is_node_5ghz(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(ERROR) << "node " << mac << " does not exist! return false as default";
        return false;
    }
    if (wireless_utils::which_freq(n->channel) == eFreqType::FREQ_5G) {
        return true;
    }
    return false;
}

bool db::update_node_failed_5ghz_steer_attempt(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }

    if (++n->failed_5ghz_steer_attemps >= config.roaming_5ghz_failed_attemps_threshold) {
        n->supports_5ghz = false;
    }
    return true;
}

bool db::update_node_failed_24ghz_steer_attempt(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }

    if (++n->failed_24ghz_steer_attemps >= config.roaming_24ghz_failed_attemps_threshold) {
        n->supports_24ghz = false;
    }
    return true;
}

bool db::can_start_client_steering(const std::string &sta_mac, const std::string &target_bssid)
{
    auto sta        = get_node(sta_mac);
    auto target_bss = get_node(target_bssid);

    if (!sta || get_node_type(sta_mac) != TYPE_CLIENT) {
        LOG(ERROR) << "Device with mac " << sta_mac << " is not a station.";
        return false;
    }
    if (!target_bss || !is_hostap_active(tlvf::mac_from_string(target_bssid))) {
        LOG(ERROR) << "Invalid or inactive BSS " << target_bssid;
        return false;
    }

    bool hostap_is_5ghz = is_node_5ghz(target_bssid);

    if ((hostap_is_5ghz && !get_node_5ghz_support(sta_mac))) {
        LOG(DEBUG) << "Sta " << sta_mac << " can't steer to hostap " << target_bssid << std::endl
                   << "  hostap_is_5ghz = " << hostap_is_5ghz << std::endl
                   << "  sta_is_5ghz = " << is_node_5ghz(sta_mac) << std::endl;
        return false;
    }
    if (!hostap_is_5ghz && !get_node_24ghz_support(sta_mac)) {
        LOG(DEBUG) << "Sta " << sta_mac << " can't steer to hostap " << target_bssid << std::endl
                   << "  node_5ghz_support = " << get_node_5ghz_support(sta_mac) << std::endl
                   << "  node_24ghz_support = " << get_node_24ghz_support(sta_mac) << std::endl;
        return false;
    }
    return true;
}

bool db::update_node_11v_responsiveness(const std::string &mac, bool success)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }

    if (success) {
        LOG(DEBUG) << "updating node " << mac << " as supporting 11v";
        n->failed_11v_request_count = 0;
        n->supports_11v             = true;
    } else {
        if (++n->failed_11v_request_count >= config.roaming_11v_failed_attemps_threshold) {
            LOG(DEBUG) << "node " << mac
                       << " exceeded maximum 11v failed attempts, updating as not supporting 11v";
            n->supports_11v = false;
        }
    }

    return true;
}

bool db::get_node_11v_capability(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    return n->supports_11v;
}

bool db::set_hostap_iface_id(const sMacAddr &mac, int8_t iface_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->iface_id = iface_id;
    return true;
}

int8_t db::get_hostap_iface_id(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    }
    return n->hostap->iface_id;
}

bool db::set_hostap_vap_list(const sMacAddr &mac,
                             const std::unordered_map<int8_t, sVapElement> &vap_list)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->vaps_info = vap_list;
    return true;
}

std::unordered_map<int8_t, sVapElement> &db::get_hostap_vap_list(const sMacAddr &mac)
{
    static std::unordered_map<int8_t, sVapElement> invalid_vap_list;
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return invalid_vap_list;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " is not a valid hostap!";
        return invalid_vap_list;
    }

    return n->hostap->vaps_info;
}

bool db::remove_vap(const std::string &radio_mac, int vap_id)
{

    auto radio_node = get_node(tlvf::mac_from_string(radio_mac));
    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node, mac: " << radio_mac;
        return false;
    }

    auto vap_list = get_hostap_vap_list(tlvf::mac_from_string(radio_mac));
    auto vap      = vap_list.find(vap_id);

    if (vap == vap_list.end()) {
        LOG(ERROR) << "Failed to get correct vap from the list.";
        return false;
    }

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    /*
        Prepare path to the BSS instance.
        Example: Controller.Network.Device.1.Radio.1.BSS.
    */
    auto bss_path = radio_path + ".BSS.";

    auto bss_index =
        m_ambiorix_datamodel->get_instance_index(bss_path + "[BSSID == '%s'].", vap->second.mac);
    if (!bss_index) {
        LOG(ERROR) << "Failed to get BSS instance index.";
        return false;
    }

    if (!m_ambiorix_datamodel->remove_instance(bss_path, bss_index)) {
        LOG(ERROR) << "Failed to remove " << bss_path << bss_index << " instance.";
        return false;
    }

    if (!vap_list.erase(vap_id)) {
        LOG(ERROR) << "Failed to remove VAP, id: " << vap_id << "bssid: " << vap->second.mac;
        return false;
    }

    return true;
}

bool db::add_vap(const std::string &radio_mac, int vap_id, const std::string &bssid,
                 const std::string &ssid, bool backhual)
{
    if (!has_node(tlvf::mac_from_string(bssid)) &&
        !add_virtual_node(tlvf::mac_from_string(bssid), tlvf::mac_from_string(radio_mac))) {
        return false;
    }

    auto &vaps_info                = get_hostap_vap_list(tlvf::mac_from_string(radio_mac));
    vaps_info[vap_id].mac          = bssid;
    vaps_info[vap_id].ssid         = ssid;
    vaps_info[vap_id].backhaul_vap = backhual;

    return dm_set_radio_bss(tlvf::mac_from_string(radio_mac), tlvf::mac_from_string(bssid), ssid);
}

bool db::update_vap(const sMacAddr &radio_mac, const sMacAddr &bssid, const std::string &ssid,
                    bool backhaul)
{
    if (!has_node(bssid) && !add_virtual_node(bssid, radio_mac)) {
        return false;
    }

    auto &vaps_info = get_hostap_vap_list(radio_mac);
    auto it         = std::find_if(vaps_info.begin(), vaps_info.end(),
                           [&](const std::pair<int8_t, sVapElement> &vap) {
                               return vap.second.mac == tlvf::mac_to_string(bssid);
                           });
    if (it == vaps_info.end()) {
        LOG(DEBUG) << "update_vap: creating new VAP for " << bssid;

        // Need to create a new VAP, which means creating a new vap_id
        auto max_vap_it = std::max_element(
            vaps_info.begin(), vaps_info.end(),
            [](const std::pair<int8_t, sVapElement> &a, const std::pair<int8_t, sVapElement> &b) {
                return a.first < b.first;
            });
        int8_t new_vap_id = (max_vap_it == vaps_info.end()) ? 0 : max_vap_it->first + 1;
        return add_vap(tlvf::mac_to_string(radio_mac), new_vap_id, tlvf::mac_to_string(bssid), ssid,
                       backhaul);
    }
    it->second.ssid         = ssid;
    it->second.backhaul_vap = backhaul;
    return dm_set_radio_bss(radio_mac, bssid, ssid);
}

std::set<std::string> db::get_hostap_vaps_bssids(const std::string &mac)
{
    std::set<std::string> bssid_set;
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return bssid_set;
    }

    if (n->get_type() != beerocks::TYPE_SLAVE) {
        // Only slaves have vap's
        return bssid_set;
    }
    auto vap_list = get_hostap_vap_list(tlvf::mac_from_string(mac));
    for (auto &vap : vap_list) {
        bssid_set.insert(vap.second.mac);
    }
    return bssid_set;
}

std::string db::get_hostap_ssid(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::string();
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return std::string();
    }
    for (auto const &it : n->hostap->vaps_info) {
        if (it.second.mac == mac) {
            return it.second.ssid;
        }
    }
    return std::string();
}

bool db::is_vap_on_steer_list(const std::string &bssid)
{
    if (config.load_steer_on_vaps.empty()) {
        return true;
    }

    auto vap_name = get_hostap_iface_name(bssid);
    if (vap_name == "INVALID") {
        LOG(ERROR) << "vap name is invalid for bssid " << bssid;
        return false;
    }

    auto vap_id = get_hostap_vap_id(bssid);
    if (vap_id == IFACE_ID_INVALID) {
        LOG(ERROR) << "vap id is invalid for bssid " << bssid;
        return false;
    }

    vap_name         = utils::get_iface_string_from_iface_vap_ids(vap_name, vap_id);
    auto &steer_vaps = config.load_steer_on_vaps;
    if (steer_vaps.find(vap_name) == std::string::npos) {
        return false;
    }
    return true;
}

std::string db::get_hostap_vap_with_ssid(const std::string &mac, const std::string &ssid)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::string();
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return std::string();
    }

    auto it = std::find_if(
        n->hostap->vaps_info.begin(), n->hostap->vaps_info.end(),
        [&](const std::pair<int8_t, sVapElement> &vap) { return vap.second.ssid == ssid; });

    if (it == n->hostap->vaps_info.end()) {
        // no vap with same ssid is found
        return std::string();
    }
    return it->second.mac;
}

std::string db::get_hostap_vap_mac(const sMacAddr &mac, int vap_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::string();
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return std::string();
    }

    auto it = n->hostap->vaps_info.find(vap_id);
    return (it != n->hostap->vaps_info.end()) ? it->second.mac : std::string();
}

std::string db::get_node_parent_radio(const std::string &mac)
{
    // if mac is a client mac, get_node_parent will return vap bssid.
    // If the mac is Vap bssid, get_node will return a radio node.
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return std::string();
    }
    if (n->get_type() == beerocks::TYPE_CLIENT) {
        const auto parent_bssid = get_node_parent(mac);
        n                       = get_node(parent_bssid);
        if (!n) {
            LOG(WARNING) << __FUNCTION__ << " - node " << parent_bssid << " does not exist!";
            return std::string();
        }
    }
    return n->mac;
}

std::string db::get_node_data_model_path(const sMacAddr &mac)
{
    return get_node_data_model_path(tlvf::mac_to_string(mac));
}

int8_t db::get_hostap_vap_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return IFACE_ID_INVALID;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return IFACE_ID_INVALID;
    }

    for (auto const &it : n->hostap->vaps_info) {
        if (it.second.mac == mac) {
            return it.first;
        }
    }
    return IFACE_ID_INVALID;
}

bool db::get_hostap_repeater_mode_flag(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    return n->hostap->enable_repeater_mode;
}

bool db::set_hostap_repeater_mode_flag(const sMacAddr &mac, bool flag)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->enable_repeater_mode = flag;
    return true;
}

bool db::set_hostap_iface_name(const sMacAddr &mac, const std::string &iface_name)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    n->hostap->iface_name = iface_name;
    return true;
}

std::string db::get_hostap_iface_name(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return "INVALID";
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return "INVALID";
    }

    return n->hostap->iface_name;
}

bool db::set_hostap_iface_type(const sMacAddr &mac, beerocks::eIfaceType iface_type)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->iface_type = iface_type;
    return true;
}

beerocks::eIfaceType db::get_hostap_iface_type(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    }
    return n->hostap->iface_type;
}

bool db::set_node_backhaul_iface_type(const std::string &mac, beerocks::eIfaceType iface_type)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    if (is_node_wireless(mac) && (iface_type > beerocks::IFACE_TYPE_WIFI_END ||
                                  iface_type == beerocks::IFACE_TYPE_UNSUPPORTED)) {
        LOG(ERROR) << "this should not happend!";
        return false;
    }
    n->iface_type = iface_type;
    return true;
}

bool db::set_hostap_driver_version(const sMacAddr &mac, const std::string &version)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    n->hostap->driver_version = version;
    return true;
}

std::string db::get_hostap_driver_version(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return "INVALID";
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return "INVALID";
    }

    return n->hostap->driver_version;
}

beerocks::eIfaceType db::get_node_backhaul_iface_type(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::IFACE_TYPE_UNSUPPORTED;
    }
    return n->iface_type;
}

std::string db::get_5ghz_sibling_hostap(const std::string &mac)
{
    auto siblings = get_node_siblings(mac, beerocks::TYPE_SLAVE);
    for (auto &hostap : siblings) {
        if (get_node_5ghz_support(hostap)) {
            auto n = get_node(hostap);
            if (!n) {
                LOG(ERROR) << "node " << hostap << " does not exist";
                return std::string();
            }
            return hostap;
        }
    }
    return std::string();
}

bool db::set_hostap_activity_mode(const std::string &mac, eApActiveMode ap_activity_mode)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(ERROR) << "node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        return false;
    }
    n->hostap->ap_activity_mode = ap_activity_mode;
    return true;
}

beerocks::eApActiveMode db::get_hostap_activity_mode(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(ERROR) << "node " << mac << " does not exist!";
        return AP_INVALID_MODE;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        return AP_INVALID_MODE;
    }
    return n->hostap->ap_activity_mode;
}

bool db::set_radar_hit_stats(const sMacAddr &mac, uint8_t channel, uint8_t bw, bool is_csa_entry)
{
    std::shared_ptr<node> n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    sWifiChannelRadarStats radar_statistics = {
        .channel = channel, .bandwidth = bw, .channel_ext_above_secondary = 0};

    //CSA enter channel
    if (is_csa_entry) {
        if (n->hostap->Radar_stats.size() == RADAR_STATS_LIST_MAX) {
            n->hostap->Radar_stats.pop_back();
        }
        auto now                             = std::chrono::steady_clock::now();
        radar_statistics.csa_enter_timestamp = now;
        radar_statistics.csa_exit_timestamp  = now;
        n->hostap->Radar_stats.push_front(radar_statistics);
        // for_each(begin(n.hostap->Radar_stats) , end(n.hostap->Radar_stats), [&](sWifiChannelRadarStats radar_stat){
        for (auto &radar_stat : n->hostap->Radar_stats) {
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
    n->hostap->Radar_stats.front().csa_exit_timestamp = std::chrono::steady_clock::now();

    return true;
}

bool db::set_supported_channel_radar_affected(const sMacAddr &mac,
                                              const std::vector<uint8_t> &channels, bool affected)
{
    std::shared_ptr<node> n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    auto channels_count = channels.size();
    LOG(DEBUG) << " channels_count = " << int(channels_count);
    if (channels_count < 1) {
        LOG(ERROR) << "the given channel list must contain at least one value";
        return false;
    }
    auto it =
        find_if(std::begin(n->hostap->supported_channels), std::end(n->hostap->supported_channels),
                [&](beerocks::message::sWifiChannel supported_channel) {
                    return supported_channel.channel == *channels.begin();
                });

    if (it == std::end(n->hostap->supported_channels)) {
        LOG(ERROR) << "channels not found ,not suppose to happen!!";
        return false;
    }
    std::for_each(it, std::next(it, channels_count),
                  [&](beerocks::message::sWifiChannel &supported_channel) {
                      LOG(DEBUG) << " supported_channel = " << int(supported_channel.channel)
                                 << " affected = " << int(affected);
                      supported_channel.radar_affected = affected;
                  });

    // for(auto supported_channel : n->hostap->supported_channels) {
    //     if(supported_channel.channel > 0) {
    //         LOG(DEBUG) <<" supported_channel = " << int(supported_channel.channel) << " affected = " << int(supported_channel.radar_affected);
    //     }
    // }

    return true;
}

bool db::set_hostap_is_dfs(const sMacAddr &mac, bool enable)
{
    std::shared_ptr<node> n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->is_dfs = enable;
    return true;
}

bool db::get_hostap_is_dfs(const sMacAddr &mac)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    return n->hostap->is_dfs;
}

bool db::set_hostap_cac_completed(const std::string &mac, bool enable)
{
    std::shared_ptr<node> n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    n->hostap->cac_completed = enable;
    return true;
}

bool db::get_hostap_cac_completed(const sMacAddr &mac)
{
    std::shared_ptr<node> n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    return n->hostap->cac_completed;
}

bool db::set_hostap_on_dfs_reentry(const sMacAddr &mac, bool enable)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    n->hostap->on_dfs_reentry = enable;
    return true;
}

bool db::get_hostap_on_dfs_reentry(const sMacAddr &mac)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    return n->hostap->on_dfs_reentry;
}

bool db::set_hostap_dfs_reentry_clients(const std::string &mac,
                                        const std::set<std::string> &dfs_reentry_clients)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    n->hostap->dfs_reentry_clients = dfs_reentry_clients;
    for_each(begin(n->hostap->dfs_reentry_clients), end(n->hostap->dfs_reentry_clients),
             [&](const std::string &dfs_reentry_client) {
                 LOG(DEBUG) << "dfs_reentry_client = " << dfs_reentry_client;
             });
    return true;
}

std::set<std::string> db::get_hostap_dfs_reentry_clients(const std::string &mac)
{
    auto n = get_node(mac);

    std::set<std::string> ret;
    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return ret;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return ret;
    }
    for_each(begin(n->hostap->dfs_reentry_clients), end(n->hostap->dfs_reentry_clients),
             [&](const std::string &dfs_reentry_client) {
                 LOG(DEBUG) << "dfs_reentry_client = " << dfs_reentry_client;
             });
    return n->hostap->dfs_reentry_clients;
}

bool db::clear_hostap_dfs_reentry_clients(const sMacAddr &mac)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }

    n->hostap->dfs_reentry_clients.clear();
    return true;
}

bool db::set_hostap_is_acs_enabled(const sMacAddr &mac, bool enable)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    LOG(DEBUG) << __FUNCTION__ << ", enable = " << int(enable);
    n->hostap->is_acs_enabled = enable;
    return true;
}

bool db::get_hostap_is_acs_enabled(const sMacAddr &mac)
{
    auto n = get_node(mac);

    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    LOG(DEBUG) << __FUNCTION__ << "n->hostap->is_acs_enabled = " << int(n->hostap->is_acs_enabled);
    return n->hostap->is_acs_enabled;
}

//
// Channel Scan
//
bool db::set_channel_scan_is_enabled(const sMacAddr &mac, bool enable)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    hostap->continuous_scan_config.is_enabled = enable;
    return true;
}

bool db::get_channel_scan_is_enabled(const sMacAddr &mac)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    return hostap->continuous_scan_config.is_enabled;
}

bool db::set_channel_scan_interval_sec(const sMacAddr &mac, int interval_sec)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    hostap->continuous_scan_config.interval_sec = interval_sec;
    return true;
}

int db::get_channel_scan_interval_sec(const sMacAddr &mac)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    return hostap->continuous_scan_config.interval_sec;
}

bool db::set_channel_scan_is_pending(const sMacAddr &mac, bool scan_is_pending)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "Failed to get hostap";
        return false;
    }

    hostap->single_scan_status.scan_is_pending = scan_is_pending;

    return true;
}

bool db::set_channel_scan_in_progress(const sMacAddr &mac, bool scan_in_progress, bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    LOG(DEBUG) << (single_scan ? "single" : "continuous") << " scan "
               << (scan_in_progress ? "is" : "isn't") << " in progress.";
    (single_scan ? hostap->single_scan_status : hostap->continuous_scan_status).scan_in_progress =
        scan_in_progress;

    return true;
}

bool db::get_channel_scan_in_progress(const sMacAddr &mac, bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }
    if (single_scan) {
        return (hostap->single_scan_status.scan_in_progress ||
                hostap->single_scan_status.scan_is_pending);
    } else {
        return hostap->continuous_scan_status.scan_in_progress;
    }
}

bool db::set_channel_scan_results_status(const sMacAddr &mac,
                                         beerocks::eChannelScanStatusCode error_code,
                                         bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    LOG(DEBUG) << (single_scan ? "single" : "continuous")
               << " scan, last scan error code = " << int(error_code);

    (single_scan ? hostap->single_scan_status : hostap->continuous_scan_status)
        .last_scan_error_code = error_code;

    return true;
}

beerocks::eChannelScanStatusCode db::get_channel_scan_results_status(const sMacAddr &mac,
                                                                     bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return beerocks::eChannelScanStatusCode::INTERNAL_FAILURE;
    }

    return (single_scan ? hostap->single_scan_status : hostap->continuous_scan_status)
        .last_scan_error_code;
}

bool db::set_channel_scan_dwell_time_msec(const sMacAddr &mac, int dwell_time_msec,
                                          bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    LOG(DEBUG) << (single_scan ? "single" : "continuous")
               << ", dwell time msec = " << dwell_time_msec;

    if (dwell_time_msec < 0) {
        LOG(ERROR) << "Invalid dwell time: " << dwell_time_msec
                   << ". Only positive values are supported!";
        return false;
    }

    (single_scan ? hostap->single_scan_config : hostap->continuous_scan_config).dwell_time_msec =
        dwell_time_msec;

    return true;
}

int db::get_channel_scan_dwell_time_msec(const sMacAddr &mac, bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    return (single_scan ? hostap->single_scan_config : hostap->continuous_scan_config)
        .dwell_time_msec;
}

bool db::is_channel_scan_pool_supported(const sMacAddr &mac,
                                        const std::unordered_set<uint8_t> &channel_pool)
{
    auto supported_channels = get_hostap_supported_channels(mac);
    for (const auto &channel : channel_pool) {
        auto found_channel =
            std::find_if(supported_channels.begin(), supported_channels.end(),
                         [&channel](const beerocks::message::sWifiChannel &supported_channel) {
                             return supported_channel.channel == channel;
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
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    if (!is_channel_scan_pool_supported(mac, channel_pool)) {
        LOG(ERROR) << "setting channel pool failed, one of the channels is not supported!";
        return false;
    }

    (single_scan ? hostap->single_scan_config : hostap->continuous_scan_config).channel_pool =
        channel_pool;

    LOG(DEBUG) << (single_scan ? "single" : "continuous")
               << " scan, setting channel pool succeeded!";

    return true;
}

const std::unordered_set<uint8_t> &db::get_channel_scan_pool(const sMacAddr &mac, bool single_scan)
{
    static std::unordered_set<uint8_t> empty;

    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return empty;
    }

    return (single_scan ? hostap->single_scan_config : hostap->continuous_scan_config).channel_pool;
}

bool db::is_channel_in_pool(const sMacAddr &mac, uint8_t channel, bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    auto &pool =
        (single_scan ? hostap->single_scan_config : hostap->continuous_scan_config).channel_pool;
    return pool.find(channel) != pool.end();
}

bool db::clear_channel_scan_results(const sMacAddr &mac, bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    (single_scan ? hostap->single_scan_results : hostap->continuous_scan_results).clear();

    return true;
}

bool db::add_channel_scan_results(const sMacAddr &mac, const sChannelScanResults &scan_result,
                                  bool single_scan)
{
    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }

    (single_scan ? hostap->single_scan_results : hostap->continuous_scan_results)
        .push_back(scan_result);

    return true;
}

const std::list<sChannelScanResults> &db::get_channel_scan_results(const sMacAddr &mac,
                                                                   bool single_scan)
{
    static std::list<sChannelScanResults> empty;

    auto hostap = get_hostap_by_mac(mac);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return empty;
    }

    return (single_scan ? hostap->single_scan_results : hostap->continuous_scan_results);
}

bool db::has_channel_report_record(const std::string &ISO_8601_timestamp)
{
    return m_channel_scan_report_records.find(ISO_8601_timestamp) !=
           m_channel_scan_report_records.end();
}

int db::get_channel_report_record_mid(const std::string &ISO_8601_timestamp)
{
    auto report_record_iter = m_channel_scan_report_records.find(ISO_8601_timestamp);
    if (report_record_iter == m_channel_scan_report_records.end()) {
        return -1;
    }
    return report_record_iter->second;
}

bool db::set_channel_report_record_mid(const std::string &ISO_8601_timestamp, int mid)
{
    if (mid) {
        LOG(ERROR) << "Cannot associate mid = 0";
        return false;
    }
    m_channel_scan_report_records[ISO_8601_timestamp] = mid;
    return true;
}

bool db::clear_channel_report_record(const std::string &ISO_8601_timestamp)
{
    // unordered_map::erase(const key_type& k) returns the number of elements erased
    return m_channel_scan_report_records.erase(ISO_8601_timestamp) == 1;
}

bool db::add_channel_report(const sMacAddr &RUID, const uint8_t &operating_class,
                            const uint8_t &channel,
                            const std::vector<wfa_map::cNeighbors> &neighbors, uint8_t avg_noise,
                            uint8_t avg_utilization, bool override_existing_data)
{
    auto hostap = get_hostap_by_mac(RUID);
    if (!hostap) {
        LOG(ERROR) << "unable to get hostap";
        return false;
    }
    const auto &key = std::make_pair(operating_class, channel);
    // Get report as reference.
    // if not report exist of the given key, this will create a new report.
    auto &db_report = hostap->scan_report[key];
    if (override_existing_data) {
        // Clear neighbors if Override flag is set.
        db_report.neighbors.clear();
    }
    std::copy(neighbors.begin(), neighbors.end(), std::back_inserter(db_report.neighbors));
    db_report.noise       = avg_noise;
    db_report.utilization = avg_utilization;

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
                       << "from persistent db (due to full persistent db)";
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

std::chrono::system_clock::time_point db::get_client_parameters_last_edit(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return std::chrono::system_clock::time_point::min();
    }

    return node->client_parameters_last_edit;
}

bool db::set_client_time_life_delay(const sMacAddr &mac,
                                    const std::chrono::minutes &time_life_delay_minutes,
                                    bool save_to_persistent_db)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return false;
    }

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
            if (!update_client_entry_in_persistent_db(mac, values_map)) {
                LOG(ERROR) << "failed to update client entry in persistent-db to for " << mac;
                return false;
            }
        }
    }

    node->client_time_life_delay_minutes = time_life_delay_minutes;
    node->client_parameters_last_edit    = timestamp;

    return true;
}

std::chrono::minutes db::get_client_time_life_delay(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return std::chrono::minutes::zero();
    }

    return node->client_time_life_delay_minutes;
}

bool db::set_client_stay_on_initial_radio(const sMacAddr &mac, bool stay_on_initial_radio,
                                          bool save_to_persistent_db)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return false;
    }

    LOG(DEBUG) << "stay_on_initial_radio=" << stay_on_initial_radio;

    auto is_client_connected = (node->state == STATE_CONNECTED);
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
                auto bssid            = node->parent_mac;
                auto parent_radio_mac = get_node_parent_radio(bssid);
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

    node->client_stay_on_initial_radio =
        (stay_on_initial_radio) ? eTriStateBool::TRUE : eTriStateBool::FALSE;
    // clear initial-radio data on disabling of stay_on_initial_radio
    if (!stay_on_initial_radio) {
        LOG(DEBUG) << "Clearing initial_radio in runtime DB";
        node->client_initial_radio = network_utils::ZERO_MAC;
        // if enabling stay-on-initial-radio and client is already connected, update the initial_radio as well
    } else if (is_client_connected) {
        auto bssid                 = node->parent_mac;
        auto parent_radio_mac      = get_node_parent_radio(bssid);
        node->client_initial_radio = tlvf::mac_from_string(parent_radio_mac);
        LOG(DEBUG) << "Setting client " << mac << " initial-radio to "
                   << node->client_initial_radio;
    }
    node->client_parameters_last_edit = timestamp;

    return true;
}

eTriStateBool db::get_client_stay_on_initial_radio(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "Client node not found for mac " << mac;
        return eTriStateBool::NOT_CONFIGURED;
    }

    return node->client_stay_on_initial_radio;
}

bool db::set_client_initial_radio(const sMacAddr &mac, const sMacAddr &initial_radio_mac,
                                  bool save_to_persistent_db)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "Client node not found for mac " << mac;
        return false;
    }

    LOG(DEBUG) << "initial_radio=" << initial_radio_mac;

    // Since the initial radio is an internal parameter (not configured by the user), its value
    // is only relevant if the stay_on_initial_radio is set and although we want its value to be
    // persistent, we don't want it to affect the client's aging.
    // This means:
    // 1. We do not update the timestamp when we update only the initial_radio.
    // 2. We only set the initial_radio if the stay_on_initial_radio is set.
    if (node->client_stay_on_initial_radio == eTriStateBool::NOT_CONFIGURED) {
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

    node->client_initial_radio = initial_radio_mac;

    return true;
}

sMacAddr db::get_client_initial_radio(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return network_utils::ZERO_MAC;
    }

    return node->client_initial_radio;
}

bool db::set_client_selected_bands(const sMacAddr &mac, int8_t selected_bands,
                                   bool save_to_persistent_db)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
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

    node->client_selected_bands       = selected_bands;
    node->client_parameters_last_edit = timestamp;

    return true;
}

int8_t db::get_client_selected_bands(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return PARAMETER_NOT_CONFIGURED;
    }

    return node->client_selected_bands;
}

bool db::set_client_is_unfriendly(const sMacAddr &mac, bool client_is_unfriendly,
                                  bool save_to_persistent_db)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return false;
    }

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

    node->client_is_unfriendly = client_is_unfriendly ? eTriStateBool::TRUE : eTriStateBool::FALSE;

    return true;
}

eTriStateBool db::get_client_is_unfriendly(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        // Clients are assumed friendly unless proven otherwise
        return eTriStateBool::NOT_CONFIGURED;
    }

    return node->client_is_unfriendly;
}

bool db::clear_client_persistent_db(const sMacAddr &mac)
{
    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "client node not found for mac " << mac;
        return false;
    }

    LOG(DEBUG) << "setting client " << mac << " runtime info to default values";

    node->client_parameters_last_edit    = std::chrono::system_clock::time_point::min();
    node->client_time_life_delay_minutes = std::chrono::minutes(PARAMETER_NOT_CONFIGURED);
    node->client_stay_on_initial_radio   = eTriStateBool::NOT_CONFIGURED;
    node->client_initial_radio           = network_utils::ZERO_MAC;
    node->client_selected_bands          = PARAMETER_NOT_CONFIGURED;
    node->client_is_unfriendly           = eTriStateBool::NOT_CONFIGURED;

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

bool db::is_hostap_on_client_selected_bands(const sMacAddr &client, const sMacAddr &hostap)
{
    auto hostap_band    = wireless_utils::which_freq(get_node_channel(tlvf::mac_to_string(hostap)));
    auto selected_bands = get_client_selected_bands(client);

    if (selected_bands == PARAMETER_NOT_CONFIGURED) {
        LOG(WARNING) << "the frequency type that's used by the client is not supported";
        return false;
    }

    switch (hostap_band) {
    case beerocks::eFreqType::FREQ_24G:
        return (selected_bands & eClientSelectedBands::eSelectedBands_24G);
    case beerocks::eFreqType::FREQ_5G:
        return (selected_bands & eClientSelectedBands::eSelectedBands_5G);
    default:
        LOG(WARNING) << "hostap band " << hostap_band << " is not supported by client";
        return false;
    }
}

bool db::update_client_persistent_db(const sMacAddr &mac)
{
    // if persistent db is disabled
    if (!config.persistent_db) {
        LOG(ERROR) << "Persistent db is disabled";
        return false;
    }

    auto node = get_node_verify_type(mac, beerocks::TYPE_CLIENT);
    if (!node) {
        LOG(ERROR) << "Client node not found for mac " << mac;
        return false;
    }

    // any persistent parameter update also sets the last-edit timestamp
    // if it is with default value - no other persistent configuration was performed
    if (node->client_parameters_last_edit == std::chrono::system_clock::time_point::min()) {
        LOG(DEBUG) << "Persistent client parameters are empty for " << mac
                   << ", no need to update persistent-db";
        return true;
    }

    ValuesMap values_map;

    // fill values map of client persistent params
    values_map[TIMESTAMP_STR] = timestamp_to_string_seconds(node->client_parameters_last_edit);

    if (node->client_time_life_delay_minutes != std::chrono::minutes(PARAMETER_NOT_CONFIGURED)) {
        LOG(DEBUG) << "Setting client time-life-delay in persistent-db to "
                   << node->client_time_life_delay_minutes.count() << " for " << mac;
        values_map[TIMELIFE_DELAY_STR] =
            std::to_string(node->client_time_life_delay_minutes.count());
    }

    if (node->client_stay_on_initial_radio != eTriStateBool::NOT_CONFIGURED) {
        auto enable = (node->client_stay_on_initial_radio == eTriStateBool::TRUE);
        LOG(DEBUG) << "Setting client stay-on-initial-radio in persistent-db to " << enable
                   << " for " << mac;
        values_map[INITIAL_RADIO_ENABLE_STR] = std::to_string(enable);
        // initial radio should be configured only if the stay_on_initial_radio is set
        if (node->client_initial_radio != network_utils::ZERO_MAC) {
            LOG(DEBUG) << "Setting client initial-radio in persistent-db to "
                       << node->client_initial_radio << " for " << mac;
            values_map[INITIAL_RADIO_STR] = tlvf::mac_to_string(node->client_initial_radio);
        }
    }

    if (node->client_selected_bands != PARAMETER_NOT_CONFIGURED) {
        LOG(DEBUG) << "Setting client selected-bands in persistent-db to "
                   << node->client_selected_bands << " for " << mac;
        values_map[SELECTED_BANDS_STR] = std::to_string(node->client_selected_bands);
    }

    if (node->client_is_unfriendly != eTriStateBool::NOT_CONFIGURED) {
        auto is_unfriendly = (node->client_is_unfriendly == eTriStateBool::TRUE);
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
        // Send results to add_node_from_data and return to increment
        // the local variable declared previously
        std::pair<uint16_t, uint16_t> result = std::make_pair(0, 0);

        db::add_node_from_data(client.first, client.second, result);

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
    for (auto node_map : nodes) {
        for (auto kv : node_map) {
            if ((kv.second->get_type() == eType::TYPE_CLIENT) && (kv.second->mac == kv.first) &&
                (kv.second->client_parameters_last_edit !=
                 std::chrono::system_clock::time_point::min())) {
                configured_clients.push_back(tlvf::mac_from_string(kv.first));
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
    bool listener_exist;
    for (const auto &listener : bml_listeners_sockets) {
        listener_exist = listener.map_updates || listener.stats_updates ||
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

bool db::set_node_beacon_measurement(const std::string &sta_mac, const std::string &ap_mac,
                                     int8_t rcpi, uint8_t rsni)
{
    auto sta = get_node(sta_mac);
    if (sta == nullptr) {
        LOG(WARNING) << __FUNCTION__ << " - node " << sta_mac << " does not exist!";
        return false;
    }
    sta->set_beacon_measurement(ap_mac, rcpi, rsni);
    return true;
}

bool db::get_node_beacon_measurement(const std::string &sta_mac, const std::string &ap_mac,
                                     int8_t &rcpi, uint8_t &rsni)
{
    auto sta = get_node(sta_mac);
    if (sta == nullptr) {
        LOG(WARNING) << __FUNCTION__ << " - node " << sta_mac << " does not exist!";
        rcpi = beerocks::RSSI_INVALID;
        rsni = 0;
        return false;
    }
    return sta->get_beacon_measurement(ap_mac, rcpi, rsni);
}

bool db::set_node_cross_rx_rssi(const std::string &sta_mac, const std::string &ap_mac, int8_t rssi,
                                int8_t rx_packets)
{
    auto sta = get_node(sta_mac);
    if (sta == nullptr) {
        return false;
    }
    sta->set_cross_rx_rssi(ap_mac, rssi, rx_packets);
    return true;
}

bool db::get_node_cross_rx_rssi(const std::string &sta_mac, const std::string &ap_mac, int8_t &rssi,
                                int8_t &rx_packets)
{
    auto sta = get_node(sta_mac);
    if (sta == nullptr) {
        rssi       = beerocks::RSSI_INVALID;
        rx_packets = 0;
        return false;
    }
    return sta->get_cross_rx_rssi(ap_mac, rssi, rx_packets);
}

bool db::set_node_cross_rx_phy_rate_100kb(const std::string &mac, uint16_t rx_phy_rate_100kb)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->cross_rx_phy_rate_100kb = rx_phy_rate_100kb;
    return true;
}

bool db::set_node_cross_tx_phy_rate_100kb(const std::string &mac, uint16_t tx_phy_rate_100kb)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->cross_tx_phy_rate_100kb = tx_phy_rate_100kb;
    return true;
}

uint16_t db::get_node_cross_rx_phy_rate_100kb(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->cross_rx_phy_rate_100kb;
}

uint16_t db::get_node_cross_tx_phy_rate_100kb(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->cross_tx_phy_rate_100kb;
}

bool db::clear_node_cross_rssi(const std::string &sta_mac)
{
    auto sta = get_node(sta_mac);
    if (sta == nullptr) {
        return false;
    }
    sta->clear_cross_rssi();
    return true;
}

bool db::set_node_cross_estimated_tx_phy_rate(const std::string &mac, double phy_rate)
{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    n->cross_estimated_tx_phy_rate = phy_rate;
    return true;
}

double db::get_node_cross_estimated_tx_phy_rate(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->cross_estimated_tx_phy_rate;
}

bool db::set_hostap_stats_info(const sMacAddr &mac, const beerocks_message::sApStatsParams *params)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return false;
    }
    if (params == nullptr) { // clear stats
        n->clear_hostap_stats_info();
    } else {
        auto p                          = n->hostap->stats_info;
        p->active_sta_count             = params->active_client_count;
        p->rx_packets                   = params->rx_packets;
        p->tx_packets                   = params->tx_packets;
        p->rx_bytes                     = params->rx_bytes;
        p->tx_bytes                     = params->tx_bytes;
        p->errors_sent                  = params->errors_sent;
        p->errors_received              = params->errors_received;
        p->retrans_count                = params->retrans_count;
        p->noise                        = params->noise;
        p->channel_load_percent         = params->channel_load_percent;
        p->total_client_tx_load_percent = params->client_tx_load_percent;
        p->total_client_rx_load_percent = params->client_rx_load_percent;
        p->stats_delta_ms               = params->stats_delta_ms;
        p->timestamp                    = std::chrono::steady_clock::now();

        auto radio_path = n->dm_path;

        if (radio_path.empty()) {
            return true;
        }
    }

    return true;
}

void db::clear_hostap_stats_info(const sMacAddr &mac) { set_hostap_stats_info(mac, nullptr); }

bool db::notify_disconnection(const std::string &client_mac)
{
    auto n = get_node(client_mac);
    if (!n) {
        return false;
    }

    std::string path_to_disassoc_event_data =
        "Controller.Notification.DisassociationEvent.DisassociationEventData";

    while (MAX_EVENT_HISTORY_SIZE <= m_disassoc_events.size()) {
        uint32_t indx = m_disassoc_events.front();

        if (!m_ambiorix_datamodel->remove_instance(path_to_disassoc_event_data, indx)) {
            LOG(ERROR) << "Failed to remove " << path_to_disassoc_event_data << indx
                       << " instance.";
        }
        m_disassoc_events.pop();
    }

    std::string path_to_eventdata = m_ambiorix_datamodel->add_instance(path_to_disassoc_event_data);

    if (path_to_eventdata.empty()) {
        return false;
    }
    auto index = get_dm_index_from_path(path_to_eventdata);

    if (index.second) {
        m_disassoc_events.push(index.second);
    }
    if (!m_ambiorix_datamodel->set(path_to_eventdata, "BSSID", n->parent_mac)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata << ".BSSID: " << n->parent_mac;
        return false;
    }
    if (!m_ambiorix_datamodel->set(path_to_eventdata, "MACAddress", client_mac)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata << ".MACAddress: " << client_mac;
        return false;
    }

    /*
      TODO: Reason code should come from Client Disassociation Stats message in
            reason Code TLV but since we do not have this data Reason Code
            set to 1 (UNSPECIFIED_REASON - IEEE802.11-16, Table 9.45).
            Should be fixed after PPM-864.
    */
    if (!m_ambiorix_datamodel->set(path_to_eventdata, "ReasonCode", static_cast<uint32_t>(1))) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".ReasonCode: " << static_cast<uint32_t>(1);
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_eventdata, "BytesSent", n->stats_info->tx_bytes)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".BytesSent: " << n->stats_info->tx_bytes;
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_eventdata, "BytesReceived", n->stats_info->rx_bytes)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".BytesReceived: " << n->stats_info->rx_bytes;
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_eventdata, "PacketsSent", n->stats_info->tx_packets)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".PacketsSent: " << n->stats_info->tx_packets;
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_eventdata, "PacketsReceived",
                                   n->stats_info->rx_packets)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".PacketsReceived: " << n->stats_info->rx_packets;
        return false;
    }

    /*
        ErrorsSent and ErrorsReceived are not available yet on stats_info
    */
    if (!m_ambiorix_datamodel->set(path_to_eventdata, "ErrorsSent", static_cast<uint32_t>(0))) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".ErrorsSent: " << static_cast<uint32_t>(0);
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_eventdata, "ErrorsReceived", static_cast<uint32_t>(0))) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".ErrorsReceived: " << static_cast<uint32_t>(0);
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_eventdata, "RetransCount",
                                   n->stats_info->retrans_count)) {
        LOG(ERROR) << "Failed to set " << path_to_eventdata
                   << ".RetransCount: " << n->stats_info->retrans_count;
        return false;
    }
    m_ambiorix_datamodel->set_current_time(path_to_eventdata);
    return true;
}

bool db::set_node_stats_info(const sMacAddr &mac, const beerocks_message::sStaStatsParams *params)

{
    auto n = get_node(mac);
    if (!n) {
        return false;
    }
    if (params == nullptr) { // clear stats
        n->clear_node_stats_info();
    } else {
        auto p               = n->stats_info;
        p->rx_packets        = params->rx_packets;
        p->tx_packets        = params->tx_packets;
        p->tx_bytes          = params->tx_bytes;
        p->rx_bytes          = params->rx_bytes;
        p->retrans_count     = params->retrans_count;
        p->tx_phy_rate_100kb = params->tx_phy_rate_100kb;
        p->rx_phy_rate_100kb = params->rx_phy_rate_100kb;
        p->tx_load_percent   = params->tx_load_percent;
        p->rx_load_percent   = params->rx_load_percent;
        p->stats_delta_ms    = params->stats_delta_ms;
        p->rx_rssi           = params->rx_rssi;
        p->timestamp         = std::chrono::steady_clock::now();
    }
    return true;
}

void db::clear_node_stats_info(const sMacAddr &mac) { set_node_stats_info(mac, nullptr); }

bool db::set_vap_stats_info(const std::string &bssid, uint32_t uc_tx_bytes, uint32_t uc_rx_bytes,
                            uint32_t mc_tx_bytes, uint32_t mc_rx_bytes, uint32_t bc_tx_bytes,
                            uint32_t bc_rx_bytes)
{
    /*
        ToDo: This method should be called in the handler for AP Extended Metrics TLV (WFA EasyMesh R2)
    */

    /*
        Prepare path with correct BSS instance.
        Example: Controller.Network.Device.1.Radio.1.BSS.1
    */
    auto bss_path = dm_get_path_to_bss(tlvf::mac_from_string(bssid));
    if (bss_path.empty()) {
        LOG(ERROR) << "Failed to get BSS path with mac: " << bssid;
        return false;
    }

    /*
        Set value for UnicastBytesSent variable
        Example: Controller.Network.Device.1.Radio.1.BSS.1.UnicastBytesSent
    */
    if (!m_ambiorix_datamodel->set(bss_path, "UnicastBytesSent", uc_tx_bytes)) {
        LOG(ERROR) << "Failed to set " << bss_path << ".UnicastBytesSent";
        return false;
    }

    /*
        Set value for UnicastBytesReceived variable
        Example: Controller.Network.Device.1.Radio.1.BSS.1.UnicastBytesReceived
    */
    if (!m_ambiorix_datamodel->set(bss_path, "UnicastBytesReceived", uc_rx_bytes)) {
        LOG(ERROR) << "Failed to set " << bss_path << ".UnicastBytesReceived";
        return false;
    }

    return true;
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

int db::get_hostap_stats_measurement_duration(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->stats_info->stats_delta_ms;
}

std::chrono::steady_clock::time_point db::get_node_stats_info_timestamp(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return std::chrono::steady_clock::time_point();
    }
    return n->stats_info->timestamp;
}

std::chrono::steady_clock::time_point db::get_hostap_stats_info_timestamp(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        std::chrono::steady_clock::time_point();
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        std::chrono::steady_clock::time_point();
    }
    return n->hostap->stats_info->timestamp;
}

uint32_t db::get_node_rx_bytes(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->rx_bytes;
}

uint32_t db::get_node_tx_bytes(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->tx_bytes;
}

uint32_t db::get_hostap_total_sta_rx_bytes(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->stats_info->rx_bytes;
}

uint32_t db::get_hostap_total_sta_tx_bytes(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->stats_info->tx_bytes;
}

double db::get_node_rx_bitrate(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return (1000 * 8 * double(n->stats_info->rx_bytes) / n->stats_info->stats_delta_ms) / 1e+6;
}

double db::get_node_tx_bitrate(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return (1000 * 8 * double(n->stats_info->tx_bytes) / n->stats_info->stats_delta_ms) / 1e+6;
}

uint16_t db::get_node_rx_phy_rate_100kb(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->rx_phy_rate_100kb;
}

uint16_t db::get_node_tx_phy_rate_100kb(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->tx_phy_rate_100kb;
}

int db::get_hostap_channel_load_percent(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->stats_info->channel_load_percent;
}

int db::get_hostap_total_client_tx_load_percent(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->stats_info->total_client_tx_load_percent;
}

int db::get_hostap_total_client_rx_load_percent(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->stats_info->total_client_rx_load_percent;
}

int db::get_node_rx_load_percent(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->rx_load_percent;
}

int db::get_node_tx_load_percent(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->tx_load_percent;
}

int8_t db::get_load_rx_rssi(const std::string &sta_mac)
{
    auto n = get_node(sta_mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->rx_rssi;
}

uint16_t db::get_load_rx_phy_rate_100kb(const std::string &sta_mac)
{
    auto n = get_node(sta_mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->rx_phy_rate_100kb;
}

uint16_t db::get_load_tx_phy_rate_100kb(const std::string &sta_mac)
{
    auto n = get_node(sta_mac);
    if (!n) {
        return -1;
    }
    return n->stats_info->tx_phy_rate_100kb;
}

bool db::set_measurement_delay(const std::string &mac, int measurement_delay)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return false;
    }
    n->measurement_delay = measurement_delay;
    LOG(DEBUG) << "set_measurement_delay: mac " << mac
               << " n->measurement_delay = " << int(n->measurement_delay);
    return true;
}

int db::get_measurement_delay(const std::string &mac)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return -1;
    }
    //LOG(DEBUG) << "get_measurement_delay: mac " << mac << " n->measurement_delay = " << int(n->measurement_delay);
    return n->measurement_delay;
}

std::chrono::steady_clock::time_point db::get_measurement_sent_timestamp(const std::string &mac)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return std::chrono::steady_clock::time_point();
    }
    //LOG(DEBUG) << "get_measurement_dry_run: mac " << mac << " n->measurement_dry_run" ;
    return n->measurement_sent_timestamp;
}

bool db::set_measurement_sent_timestamp(const std::string &mac)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return false;
    }
    n->measurement_sent_timestamp = std::chrono::steady_clock::now();
    LOG(DEBUG) << "set_measurement_sent_timestamp: mac " << mac;
    return true;
}

int db::get_measurement_recv_delta(const std::string &mac)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return -1;
    }
    LOG(DEBUG) << "get_measurement_recv_delta: mac " << mac
               << " n->measurement_recv_delta = " << int(n->measurement_recv_delta)
               << " actual delay = " << int((n->measurement_recv_delta / 2));
    return n->measurement_recv_delta;
}

bool db::set_measurement_recv_delta(const std::string &mac)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return false;
    }
    auto measurement_recv_timestamp = std::chrono::steady_clock::now();
    n->measurement_recv_delta       = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    measurement_recv_timestamp - n->measurement_sent_timestamp)
                                    .count();
    //LOG(DEBUG) << "set_measurement_recv_delta: mac " << mac << " n->measurement_recv_delta = " << int(n->measurement_recv_delta);
    return true;
}

int db::get_measurement_window_size(const std::string &mac)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return -1;
    }
    return n->measurement_window_size;
}

bool db::set_measurement_window_size(const std::string &mac, int window_size)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        return false;
    }
    n->measurement_window_size = window_size;
    return true;
}

bool db::set_node_channel_bw(const std::string &mac, int channel, beerocks::eWiFiBandwidth bw,
                             bool channel_ext_above_secondary, int8_t channel_ext_above_primary,
                             uint16_t vht_center_frequency)
{
    std::shared_ptr<node> n = get_node(mac);
    if (!n) {
        LOG(ERROR) << "node " << mac << "does not exist ";
        return false;
    }
    if (n->get_type() == beerocks::TYPE_SLAVE) {
        if (n->hostap != nullptr) {
            n->hostap->channel_ext_above_primary = channel_ext_above_primary;
            n->hostap->vht_center_frequency      = vht_center_frequency;
            auto is_dfs                          = wireless_utils::is_dfs_channel(channel);
            set_hostap_is_dfs(tlvf::mac_from_string(mac), is_dfs);
            if (channel >= 1 && channel <= 13) {
                n->hostap->operating_class = 81;
            } else if (channel == 14) {
                n->hostap->operating_class = 82;
            } else if (channel >= 36 && channel <= 48) {
                n->hostap->operating_class = 115;
            } else if (channel >= 52 && channel <= 64) {
                n->hostap->operating_class = 118;
            } else if (channel >= 100 && channel <= 140) {
                n->hostap->operating_class = 121;
            } else if (channel >= 149 && channel <= 169) {
                n->hostap->operating_class = 125;
            } else {
                LOG(ERROR) << "Unsupported Operating Class for channel=" << channel;
            }
        } else {
            LOG(ERROR) << __FUNCTION__ << " - node " << mac << " is null!";
            return false;
        }
    }

    LOG(INFO) << "set node " << mac << " to channel=" << channel << ", bw=" << int(bw)
              << ", channel_ext_above_secondary=" << int(channel_ext_above_secondary)
              << ", channel_ext_above_primary=" << int(channel_ext_above_primary)
              << ", vht_center_frequency=" << int(vht_center_frequency);

    n->channel                     = channel;
    n->bandwidth                   = bw;
    n->channel_ext_above_secondary = channel_ext_above_secondary;
    if (wireless_utils::which_freq(channel) == eFreqType::FREQ_24G) { //2.4G
        n->supports_24ghz             = true;
        n->failed_24ghz_steer_attemps = 0;
    } else if (wireless_utils::which_freq(channel) == eFreqType::FREQ_5G) {
        n->supports_5ghz             = true;
        n->failed_5ghz_steer_attemps = 0;
    } else {
        LOG(ERROR) << "frequency type unknown, channel=" << int(channel);
    }

    auto children = get_node_children(n);
    for (auto child : children) {
        child->channel                     = channel;
        child->bandwidth                   = bw;
        child->channel_ext_above_secondary = channel_ext_above_secondary;
    }
    return true;
}

beerocks::eWiFiBandwidth db::get_node_bw(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return beerocks::BANDWIDTH_MAX;
    }
    return n->bandwidth;
}

bool db::get_node_channel_ext_above_secondary(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    return n->channel_ext_above_secondary;
}

bool db::get_hostap_channel_ext_above_primary(const sMacAddr &hostap_mac)
{
    auto n = get_node(hostap_mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << hostap_mac << " does not exist!";
        return -1;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(WARNING) << __FUNCTION__ << "node " << hostap_mac << " is not a valid hostap!";
        return -1;
    }
    return n->hostap->channel_ext_above_primary;
}

int db::get_node_bw_int(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return 0;
    }
    return get_node_bw_int(n);
}

std::string db::get_node_key(const std::string &al_mac, const std::string &ruid)
{

    if (al_mac.empty() || ruid.empty()) {
        return std::string();
    }

    return al_mac + "_" + ruid;
}

uint16_t db::get_hostap_vht_center_frequency(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return 0;
    } else if (n->get_type() != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        return 0;
    }
    return n->hostap->vht_center_frequency;
}

//
// tasks
//

bool db::assign_association_handling_task_id(const std::string &mac, int new_task_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->association_handling_task_id = new_task_id;
    return true;
}

int db::get_association_handling_task_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return n->association_handling_task_id;
}

bool db::assign_steering_task_id(const std::string &mac, int new_task_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->steering_task_id = new_task_id;
    return true;
}

int db::get_steering_task_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return n->steering_task_id;
}

bool db::assign_roaming_task_id(const std::string &mac, int new_task_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->roaming_task_id = new_task_id;
    return true;
}

int db::get_roaming_task_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return n->roaming_task_id;
}

bool db::assign_load_balancer_task_id(const std::string &mac, int new_task_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->load_balancer_task_id = new_task_id;
    return true;
}

int db::get_load_balancer_task_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return n->load_balancer_task_id;
}

bool db::assign_client_locating_task_id(const std::string &mac, int new_task_id,
                                        bool new_connection)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    if (new_connection) {
        n->client_locating_task_id_new_connection = new_task_id;
    } else {
        n->client_locating_task_id_exist_connection = new_task_id;
    }
    return true;
}

int db::get_client_locating_task_id(const std::string &mac, bool new_connection)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    if (new_connection) {
        return n->client_locating_task_id_new_connection;
    }
    return n->client_locating_task_id_exist_connection;
}

bool db::assign_ire_4addr_mode_transition_task_id(const std::string &mac, int new_task_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return false;
    }
    n->ire_4addr_mode_transition_task_id = new_task_id;
    return true;
}

int db::get_ire_4addr_mode_transition_task_id(const std::string &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << mac << " does not exist!";
        return -1;
    }
    return n->ire_4addr_mode_transition_task_id;
}

bool db::assign_channel_selection_task_id(int new_task_id)
{
    channel_selection_task_id = new_task_id;
    return true;
}

int db::get_channel_selection_task_id() { return channel_selection_task_id; }

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

bool db::assign_rdkb_wlan_task_id(int new_task_id)
{
    rdkb_wlan_task_id = new_task_id;
    return true;
}

int db::get_rdkb_wlan_task_id() { return rdkb_wlan_task_id; }

bool db::assign_dynamic_channel_selection_task_id(const sMacAddr &mac, int new_task_id)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << tlvf::mac_to_string(mac)
                     << " does not exist!";
        return false;
    }
    n->dynamic_channel_selection_task_id = new_task_id;
    return true;
}

int db::get_dynamic_channel_selection_task_id(const sMacAddr &mac)
{
    auto n = get_node(mac);
    if (!n) {
        LOG(WARNING) << __FUNCTION__ << " - node " << tlvf::mac_to_string(mac)
                     << " does not exist!";
        return -1;
    }
    return n->dynamic_channel_selection_task_id;
}

bool db::assign_dynamic_channel_selection_r2_task_id(int new_task_id)
{
    dynamic_channel_selection_r2_task_id = new_task_id;
    return true;
}

int db::get_dynamic_channel_selection_r2_task_id() { return dynamic_channel_selection_r2_task_id; }

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

void db::clear_bss_info_configuration()
{
    bss_infos.clear();
    bss_infos_global.clear();
}

void db::clear_bss_info_configuration(const sMacAddr &al_mac) { bss_infos[al_mac].clear(); }

void db::add_traffic_separataion_configuration(const sMacAddr &al_mac,
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
db::get_traffic_separataion_configuration(const sMacAddr &al_mac)
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
}

bool db::dm_set_sta_link_metrics(const sMacAddr &sta_mac, uint32_t downlink_est_mac_data_rate,
                                 uint32_t uplink_est_mac_data_rate, uint8_t signal_strength)
{
    auto sta_node = get_node(sta_mac);

    if (!sta_node || sta_node->get_type() != TYPE_CLIENT) {
        LOG(ERROR) << "Fail to get station node with mac: " << sta_mac;
        return {};
    }

    std::string path_to_sta = sta_node->dm_path;
    bool return_val         = true;

    if (path_to_sta.empty()) {
        return true;
    }

    if (!m_ambiorix_datamodel->set(path_to_sta, "EstMACDataRateDownlink",
                                   downlink_est_mac_data_rate)) {
        LOG(ERROR) << "Failed to set" << path_to_sta
                   << ".EstMACDataRateDownlink: " << downlink_est_mac_data_rate;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_sta, "EstMACDataRateUplink", uplink_est_mac_data_rate)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".EstMACDataRateUplink: " << uplink_est_mac_data_rate;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_sta, "SignalStrength", signal_strength)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".SignalStrength: " << signal_strength;
        return_val = false;
    }
    return return_val;
}

//
// PRIVATE FUNCTIONS
//   must be used from a thread safe context
//
int db::get_node_hierarchy(std::shared_ptr<node> n)
{
    if (!n) {
        return -1;
    }
    //redundant but more efficient this way
    return n->hierarchy;
}

std::shared_ptr<node> db::get_node(const std::string &key)
{
    if (key == last_accessed_node_mac) {
        return last_accessed_node;
    }

    for (int i = 0; i < HIERARCHY_MAX; i++) {
        auto it = nodes[i].find(key);
        if (it != nodes[i].end()) {
            last_accessed_node_mac = key;
            last_accessed_node     = it->second;
            return it->second;
        }
    }
    return nullptr;
}

std::shared_ptr<node> db::get_node(const sMacAddr &mac)
{
    std::string key = mac == network_utils::ZERO_MAC ? std::string() : tlvf::mac_to_string(mac);
    return get_node(key);
}

std::shared_ptr<node> db::get_node(const sMacAddr &al_mac, const sMacAddr &ruid)
{
    std::string key = std::string();
    if (al_mac != network_utils::ZERO_MAC && ruid != network_utils::ZERO_MAC)
        key = tlvf::mac_to_string(al_mac) + tlvf::mac_to_string(ruid);

    return get_node(key);
}

std::shared_ptr<node> db::get_node_verify_type(const sMacAddr &mac, beerocks::eType type)
{
    auto node = get_node(mac);
    if (!node) {
        LOG(ERROR) << "node not found for mac " << mac;
        return nullptr;
    } else if (node->get_type() != type) {
        LOG(ERROR) << "node " << mac << " type(" << node->get_type() << ") != requested-type("
                   << type << ")";
        return nullptr;
    }

    return node;
}

std::shared_ptr<node::radio> db::get_hostap_by_mac(const sMacAddr &mac)
{
    auto n = get_node(mac);
    beerocks::eType t;
    if (!n) {
        LOG(ERROR) << "node not found.... ";
        return nullptr;
    } else if ((t = n->get_type()) != beerocks::TYPE_SLAVE || n->hostap == nullptr) {
        LOG(ERROR) << "node " << tlvf::mac_to_string(mac) << " type is #" << (int)t;
        LOG(ERROR) << "node " << tlvf::mac_to_string(mac) << " is not a valid hostap!";
        return nullptr;
    }

    return n->hostap;
}

std::set<std::shared_ptr<node>> db::get_node_subtree(std::shared_ptr<node> n)
{
    std::set<std::shared_ptr<node>> subtree;

    if (!n) {
        LOG(ERROR) << "node is nullptr!";
        return subtree;
    }

    int i = get_node_hierarchy(n) + 1;

    if (i >= HIERARCHY_MAX) {
        return subtree;
    }

    for (auto &node_element : nodes[i]) {
        if (node_element.first == node_element.second->mac) {
            auto subtree_node = node_element.second;
            if (subtree_node->parent_mac == n->mac) {
                subtree.insert(subtree_node);
                std::set<std::shared_ptr<node>> sub_subtree = get_node_subtree(subtree_node);
                subtree.insert(sub_subtree.begin(), sub_subtree.end());
            }
        }
    }
    return subtree;
}

std::set<std::shared_ptr<node>> db::get_node_children(std::shared_ptr<node> n, int type, int state,
                                                      std::string parent_mac)
{
    std::set<std::shared_ptr<node>> children;

    if (!n) {
        LOG(ERROR) << "node is nullptr!";
        return children;
    }

    auto bssids = get_hostap_vaps_bssids(n->mac);
    bssids.insert(n->mac);

    int hierarchy = get_node_hierarchy(n) + 1;

    if (hierarchy >= 0 && hierarchy < HIERARCHY_MAX) {
        for (auto &node_element : nodes[hierarchy]) {
            auto child = node_element.second;
            if ((child->mac == node_element.first) &&
                (bssids.find(child->parent_mac) != bssids.end() &&
                 (type == beerocks::TYPE_ANY || child->get_type() == type) &&
                 (state == beerocks::STATE_ANY || child->state == state) &&
                 (parent_mac.empty() || child->parent_mac == parent_mac))) {
                children.insert(child);
            }
        }
    }
    return children;
}

void db::adjust_subtree_hierarchy(std::shared_ptr<node> n)
{
    if (!n) {
        LOG(ERROR) << "node is nullptr!";
        return;
    }

    int hierarchy = get_node_hierarchy(n);

    for (int i = 0; i < HIERARCHY_MAX; ++i) {
        for (auto it = nodes[i].begin(); it != nodes[i].end();) {
            auto subtree_node = it->second;
            if (subtree_node->parent_mac == n->mac) {
                int new_hierarchy = hierarchy + 1;
                if (new_hierarchy >= HIERARCHY_MAX) {
                    LOG(ERROR) << "new hierarchy is too high!";
                    return;
                }
                it = nodes[i].erase(it);
                nodes[new_hierarchy].insert(std::make_pair(subtree_node->mac, subtree_node));
                subtree_node->hierarchy = new_hierarchy;
                adjust_subtree_hierarchy(subtree_node);
            } else {
                ++it;
            }
        }
    }
}

void db::adjust_subtree_hierarchy(std::set<std::shared_ptr<node>> subtree, int offset)
{
    for (auto s : subtree) {
        int new_hierarchy = s->hierarchy + offset;
        if (new_hierarchy >= HIERARCHY_MAX || new_hierarchy < 0) {
            LOG(ERROR) << "invalid new_hierarchy=" << new_hierarchy << " for node " << s->mac;
            continue;
        }
        nodes[s->hierarchy].erase(s->mac);
        nodes[new_hierarchy].insert({s->mac, s});
        s->hierarchy = new_hierarchy;
    }
}

void db::rewind()
{
    current_hierarchy = 0;
    db_it             = nodes[current_hierarchy].begin();
}

bool db::get_next_node(std::shared_ptr<node> &n, int &hierarchy)
{
    bool last = false;

    if (db_it != nodes[current_hierarchy].end()) {
        n         = db_it->second;
        hierarchy = current_hierarchy;
        ++db_it;
    }

    if (db_it == nodes[current_hierarchy].end()) {
        current_hierarchy++;
        if (current_hierarchy >= HIERARCHY_MAX) {
            current_hierarchy = 0;
            last              = true;
        }
        db_it = nodes[current_hierarchy].begin();
    }
    return last;
}

bool db::get_next_node(std::shared_ptr<node> &n)
{
    bool last = false;

    if (db_it != nodes[current_hierarchy].end()) {
        n = db_it->second;
        ++db_it;
    }

    if (db_it == nodes[current_hierarchy].end()) {
        current_hierarchy++;
        if (current_hierarchy >= HIERARCHY_MAX) {
            current_hierarchy = 0;
            last              = true;
        }
        db_it = nodes[current_hierarchy].begin();
    }
    return last;
}

int db::get_node_bw_int(std::shared_ptr<node> &n)
{
    int bw;
    switch (n->bandwidth) {
    case beerocks::BANDWIDTH_20:
        bw = 20;
        break;
    case beerocks::BANDWIDTH_40:
        bw = 40;
        break;
    default:
        bw = 80;
        break;
    }
    return bw;
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
    auto node = get_node(mac);
    if (!node) {
        LOG(ERROR) << "can't find node with mac " << mac << ", consider as not prplmesh";
        return false;
    }
    return node->is_prplmesh;
}

void db::set_prplmesh(const sMacAddr &mac)
{
    auto local_bridge_mac = tlvf::mac_from_string(get_local_bridge_mac());
    if (!get_node(mac)) {
        if (local_bridge_mac == mac) {
            add_node_gateway(mac);
        } else {
            add_node_ire(mac);
        }
    }
    get_node(mac)->is_prplmesh = true;
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

bool db::set_node_params_from_map(const sMacAddr &mac, const ValuesMap &values_map)
{
    auto node = get_node(mac);
    if (!node) {
        LOG(WARNING) << " - node " << mac << " does not exist!";
        return false;
    }

    auto initial_radio = network_utils::ZERO_MAC;

    for (const auto &param : values_map) {
        if (param.first == TIMESTAMP_STR) {
            LOG(DEBUG) << "Setting node client_parameters_last_edit to " << param.second << " for "
                       << mac;
            node->client_parameters_last_edit =
                timestamp_from_seconds(string_utils::stoi(param.second));
        } else if (param.first == TIMELIFE_DELAY_STR) {
            LOG(DEBUG) << "Setting node client_time_life_delay_sec to " << param.second << " for "
                       << mac;
            node->client_time_life_delay_minutes =
                std::chrono::minutes(string_utils::stoi(param.second));
        } else if (param.first == INITIAL_RADIO_ENABLE_STR) {
            LOG(DEBUG) << "Setting node client_stay_on_initial_radio to " << param.second << " for "
                       << mac;
            node->client_stay_on_initial_radio =
                (param.second == "1") ? eTriStateBool::TRUE : eTriStateBool::FALSE;
        } else if (param.first == INITIAL_RADIO_STR) {
            LOG(DEBUG) << "Received client_initial_radio=" << param.second << " for " << mac;
            initial_radio = tlvf::mac_from_string(param.second);
        } else if (param.first == SELECTED_BANDS_STR) {
            LOG(DEBUG) << "Setting node client_selected_bands to " << param.second << " for "
                       << mac;
            node->client_selected_bands = string_utils::stoi(param.second);
        } else if (param.first == IS_UNFRIENDLY_STR) {
            LOG(DEBUG) << "Setting node client_is_unfriendly to " << param.second << " for " << mac;
            node->client_is_unfriendly =
                (param.second == std::to_string(true)) ? eTriStateBool::TRUE : eTriStateBool::FALSE;
        } else {
            LOG(WARNING) << "Unknown parameter, skipping: " << param.first << " for " << mac;
        }
    }

    // After configuring the values we can determine if the client_initial_radio should be set as well.
    // Since its value is only relevant if client_stay_on_initial_radio is set.
    // clear initial-radio data on disabling of stay_on_initial_radio.
    if (node->client_stay_on_initial_radio != eTriStateBool::TRUE) {
        LOG_IF((initial_radio != network_utils::ZERO_MAC), WARNING)
            << "ignoring initial-radio=" << initial_radio
            << " since stay-on-initial-radio is not enabled";
        node->client_initial_radio = network_utils::ZERO_MAC;
    } else if (initial_radio != network_utils::ZERO_MAC) {
        // If stay-on-initial-radio is set to enable and initial_radio is provided.
        node->client_initial_radio = initial_radio;
    } else if (node->state == STATE_CONNECTED) {
        // If stay-on-initial-radio is enabled and initial_radio is not set and client is already connected:
        // Set the initial_radio from parent radio mac (not bssid).
        auto bssid                 = node->parent_mac;
        auto parent_radio_mac      = get_node_parent_radio(bssid);
        node->client_initial_radio = tlvf::mac_from_string(parent_radio_mac);
        LOG(DEBUG) << "Setting client " << mac << " initial-radio to "
                   << node->client_initial_radio;
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

    return true;
}

bool db::remove_candidate_client(sMacAddr client_to_skip)
{

    // find cadidate client to be removed
    sMacAddr client_to_remove = get_candidate_client_for_removal(client_to_skip);
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

    for (const auto &node_map : nodes) {
        for (const auto &key_value : node_map) {
            const auto client = key_value.second;
            if (client->get_type() != beerocks::eType::TYPE_CLIENT) {
                continue;
            }
            const auto client_mac = tlvf::mac_from_string(key_value.first);

            // skip client if matches the provided client to skip
            if (client_mac == client_to_skip) {
                continue;
            }
            //TODO: improvement - stop search if "already-aged" candidate is found (don't-care of connectivity status)

            // Skip clients which have no persistent information.
            if (client->client_parameters_last_edit ==
                std::chrono::system_clock::time_point::min()) {
                continue;
            }

            // Max client timelife delay
            // This is ditermined according to the friendliness status of the client.
            // If a client is unfriendly we can
            auto selected_max_timelife_delay_sec =
                (client->client_is_unfriendly == eTriStateBool::TRUE)
                    ? unfriendly_device_max_timelife_delay_sec
                    : max_timelife_delay_sec;

            // Client timelife delay
            auto timelife_delay_sec =
                (client->client_time_life_delay_minutes !=
                 std::chrono::seconds(beerocks::PARAMETER_NOT_CONFIGURED))
                    ? std::chrono::seconds(client->client_time_life_delay_minutes)
                    : selected_max_timelife_delay_sec;

            // Calculate client expiry due time.
            // In case both clients are non-aging - both time-life will be 0 - so only the
            // last-edit-time will affect the candidate selected.
            auto current_client_expiry_due_time =
                client->client_parameters_last_edit + timelife_delay_sec;

            // Preferring non-aging clients over aging ones (even if disconnected).
            // If client is non-aging and candidate is aging - skip it
            if (is_aging_candidate_available &&
                client->client_time_life_delay_minutes == std::chrono::seconds::zero()) {
                continue;
            }

            // Previous candidate is not aging and current client is aging - replace candidate
            if (!is_aging_candidate_available &&
                (client->client_time_life_delay_minutes > std::chrono::seconds::zero())) {
                // Update candidate
                candidate_client_to_be_removed = client_mac;
                // Set the candidate client expiry due time for later comparison
                candidate_client_expiry_due_time = current_client_expiry_due_time;
                // Set aging-candidate-available
                is_aging_candidate_available = true;
                // Set disconnected-candidate-available
                is_disconnected_candidate_available =
                    (client->state == beerocks::STATE_DISCONNECTED);
                continue;
            }

            // Preferring disconnected clients over connected ones (even if less aged).
            if (is_disconnected_candidate_available &&
                client->state != beerocks::STATE_DISCONNECTED) {
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
                is_disconnected_candidate_available =
                    (client->state == beerocks::STATE_DISCONNECTED);
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

void db::add_node_from_data(const std::string &client_entry, const ValuesMap &values_map,
                            std::pair<uint16_t, uint16_t> &result)
{
    auto client_mac = client_db_entry_to_mac(client_entry);

    // Add client node with defaults and in default location
    if (!add_node_client(client_mac)) {
        LOG(ERROR) << "Failed to add client node for client_entry " << client_entry;
        result.first = 1;
        return;
    }

    // Set clients persistent information in the node
    if (!set_node_params_from_map(client_mac, values_map)) {
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

bool db::clear_ap_capabilities(const sMacAddr &radio_mac)
{
    auto radio_node = get_node(radio_mac);
    if (!radio_node) {
        LOG(WARNING) << " - node " << radio_mac << " does not exist!";
        return false;
    }

    std::string path_to_obj = radio_node->dm_path;
    if (path_to_obj.empty()) {
        return true;
    }
    path_to_obj += ".Capabilities";
    if (!m_ambiorix_datamodel->remove_optional_subobject(path_to_obj, "HTCapabilities")) {
        LOG(ERROR) << "Failed to remove optional subobject: " << path_to_obj << ".HTCapabilities";
        return false;
    }
    if (!m_ambiorix_datamodel->remove_optional_subobject(path_to_obj, "VHTCapabilities")) {
        LOG(ERROR) << "Failed to remove optional subobject: " << path_to_obj << ".VHTCapabilities";
        return false;
    }
    if (!m_ambiorix_datamodel->remove_optional_subobject(path_to_obj, "HECapabilities")) {
        LOG(ERROR) << "Failed to remove optional subobject: " << path_to_obj << ".HECapabilities";
        return false;
    }
    return true;
}

bool db::set_ap_ht_capabilities(const sMacAddr &radio_mac,
                                const wfa_map::tlvApHtCapabilities::sFlags &flags)
{
    auto radio_node = get_node(radio_mac);
    bool return_val = true;

    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node with mac: " << radio_mac;
        return false;
    }

    std::string path_to_obj = radio_node->dm_path;
    if (path_to_obj.empty()) {
        LOG(ERROR) << "Failed to get path for radio with mac: " << radio_mac;
        return false;
    }

    path_to_obj += ".Capabilities.";
    if (!m_ambiorix_datamodel->add_optional_subobject(path_to_obj, "HTCapabilities")) {
        LOG(ERROR) << "Failed to add sub-object " << path_to_obj << ".HTCapabilities";
        return false;
    }
    path_to_obj += "HTCapabilities.";
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_20_MHz",
                                   static_cast<bool>(flags.short_gi_support_20mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "GI_20_MHz: " << static_cast<bool>(flags.short_gi_support_20mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "GI_40_MHz",
                                   static_cast<bool>(flags.short_gi_support_40mhz))) {
        LOG(ERROR) << "Failed to  set " << path_to_obj
                   << "GI_40_MHz: " << static_cast<bool>(flags.short_gi_support_40mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "HT_40_Mhz",
                                   static_cast<bool>(flags.ht_support_40mhz))) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "HT_40_Mhz: " << static_cast<bool>(flags.ht_support_40mhz);
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "tx_spatial_streams",
                                   flags.max_num_of_supported_tx_spatial_streams + 1)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "tx_spatial_streams: " << flags.max_num_of_supported_tx_spatial_streams + 1;
        return_val = false;
    }
    if (!m_ambiorix_datamodel->set(path_to_obj, "rx_spatial_streams",
                                   flags.max_num_of_supported_rx_spatial_streams + 1)) {
        LOG(ERROR) << "Failed to set " << path_to_obj
                   << "rx_spatial_streams: " << flags.max_num_of_supported_rx_spatial_streams + 1;
        return_val = false;
    }
    return return_val;
}

bool db::dm_set_device_multi_ap_capabilities(const std::string &device_mac)
{
    auto device_node        = get_node(device_mac);
    std::string path_to_obj = device_node->dm_path;
    bool return_val         = true;

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

std::string db::dm_add_sta_element(const sMacAddr &bssid, const sMacAddr &client_mac)
{

    if (bssid == network_utils::ZERO_MAC) {
        LOG(WARNING) << "Client has empty parent bssid, not adding it to the data model, client="
                     << client_mac;
        return {};
    }

    std::string path_to_bss = dm_get_path_to_bss(bssid);
    if (path_to_bss.empty()) {
        LOG(ERROR) << "Failed get path to bss with mac: " << bssid;
        return {};
    }

    std::string path_to_sta = path_to_bss + "STA";
    std::string sta_instance;

    // TODO remove after refactoring Database nodes PPM-1057.
    // Verifying a STA is already added or not with datamodel method is bad practice.
    // Database node handling eliminate this action.
    auto sta_index = m_ambiorix_datamodel->get_instance_index(
        path_to_sta + ".[MACAddress == '%s'].", tlvf::mac_to_string(client_mac));

    if (sta_index) {
        sta_instance = path_to_sta + "." + std::to_string(sta_index);
    } else {
        sta_instance = m_ambiorix_datamodel->add_instance(path_to_sta);
        if (sta_instance.empty()) {
            LOG(ERROR) << "Failed to add sta instance " << path_to_sta
                       << ". STA mac: " << client_mac;
            return {};
        }
    }

    if (!m_ambiorix_datamodel->set(sta_instance, "MACAddress", tlvf::mac_to_string(client_mac))) {
        LOG(ERROR) << "Failed to set " << sta_instance << ".MACAddress: " << client_mac;
        return {};
    }

    m_ambiorix_datamodel->set_current_time(sta_instance);

    uint64_t add_sta_time = time(NULL);
    if (!m_ambiorix_datamodel->set(sta_instance, "LastConnectTime", add_sta_time)) {
        LOG(ERROR) << "Failed to set " << sta_instance << ".LastConnectTime: " << add_sta_time;
        return {};
    }
    return sta_instance;
}

std::string db::dm_add_association_event(const sMacAddr &bssid, const sMacAddr &client_mac)
{
    std::string path_association_event =
        "Controller.Notification.AssociationEvent.AssociationEventData";

    while (MAX_EVENT_HISTORY_SIZE <= m_assoc_events.size()) {
        uint32_t indx = m_assoc_events.front();

        if (!m_ambiorix_datamodel->remove_instance(path_association_event, indx)) {
            LOG(ERROR) << "Failed to remove " << path_association_event << indx << " instance.";
        }
        m_assoc_events.pop();
    }

    path_association_event = m_ambiorix_datamodel->add_instance(path_association_event);

    if (path_association_event.empty()) {
        return {};
    }
    auto index = get_dm_index_from_path(path_association_event);

    if (index.second) {
        m_assoc_events.push(index.second);
    }
    if (!m_ambiorix_datamodel->set(path_association_event, "BSSID", tlvf::mac_to_string(bssid))) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".BSSID: " << bssid;
        return {};
    }
    if (!m_ambiorix_datamodel->set(path_association_event, "MACAddress",
                                   tlvf::mac_to_string(client_mac))) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".MACAddress: " << client_mac;
        return {};
    }

    /*
     TODO:  Set the status code to real value. Now value hardcoded to 0
            means connection successfull (IEEE802.11-16, Table 9.46).
            Should be fixed after PPM-864.
    */
    if (!m_ambiorix_datamodel->set(path_association_event, "StatusCode",
                                   static_cast<uint32_t>(0))) {
        LOG(ERROR) << "Failed to set " << path_association_event << ".StatusCode: " << 0;
        return {};
    }
    m_ambiorix_datamodel->set_current_time(path_association_event);

    if (MAX_EVENT_HISTORY_SIZE < m_assoc_indx.size()) {
        m_assoc_indx.clear();
    }
    m_assoc_indx[tlvf::mac_to_string(client_mac)].push_back(index.second);
    return path_association_event;
}

std::string db::dm_add_device_element(const sMacAddr &mac)
{
    auto index = m_ambiorix_datamodel->get_instance_index("Controller.Network.Device.[ID == '%s'].",
                                                          tlvf::mac_to_string(mac));
    if (index) {
        LOG(WARNING) << "Device with ID: " << mac << " exists in the data model!";
        return {};
    }

    auto device_path = m_ambiorix_datamodel->add_instance("Controller.Network.Device");
    if (device_path.empty()) {
        LOG(ERROR) << "Failed to add instance " << device_path << ". Device mac: " << mac;
        return {};
    }

    if (!m_ambiorix_datamodel->set(device_path, "ID", tlvf::mac_to_string(mac))) {
        LOG(ERROR) << "Failed to set " << device_path << ".ID: " << tlvf::mac_to_string(mac);
        return {};
    }

    return device_path;
}

bool db::add_current_op_class(const sMacAddr &radio_mac, uint8_t op_class, uint8_t op_channel,
                              int8_t tx_power)
{
    auto radio_node = get_node(radio_mac);
    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node for mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Prepare path to the CurrentOperatingClasses instance
    // Data model path example: Controller.Network.Device.1.Radio.1.CurrentOperatingClasses
    auto op_class_path = radio_path + ".CurrentOperatingClasses";

    auto op_class_path_instance = m_ambiorix_datamodel->add_instance(op_class_path);
    if (op_class_path_instance.empty()) {
        LOG(ERROR) << "Failed to add instance " << op_class_path;
        return false;
    }

    m_ambiorix_datamodel->set_current_time(op_class_path_instance);

    //Set Operating class
    //Data model path: Controller.Network.Device.1.Radio.1.CurrentOperatingClasses.Class
    if (!m_ambiorix_datamodel->set(op_class_path_instance, "Class", op_class)) {
        LOG(ERROR) << "Failed to set " << op_class_path_instance << ".Class: " << op_class;
        return false;
    }

    //Set Operating channel
    //Data model path example: Controller.Network.Device.1.Radio.1.CurrentOperatingClasses.Channel
    if (!m_ambiorix_datamodel->set(op_class_path_instance, "Channel", op_channel)) {
        LOG(ERROR) << "Failed to set " << op_class_path_instance << ".Channel: " << op_channel;
        return false;
    }

    //Set TX power
    //Data model path example: Controller.Network.Device.1.Radio.1.CurrentOperatingClasses.TxPower
    if (!m_ambiorix_datamodel->set(op_class_path_instance, "TxPower", tx_power)) {
        LOG(ERROR) << "Failed to set " << op_class_path_instance << ".TxPower: " << tx_power;
        return false;
    }

    return true;
}

bool db::remove_current_op_classes(const sMacAddr &radio_mac)
{
    auto radio_node = get_node(radio_mac);
    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node for mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Prepare path to the CurrentOperatingClasses instance
    // Data model path example: Controller.Network.Device.1.Radio.1.CurrentOperatingClasses
    auto op_class_path = radio_path + ".CurrentOperatingClasses";

    if (!m_ambiorix_datamodel->remove_all_instances(op_class_path)) {
        LOG(ERROR) << "Failed to remove all instances for: " << op_class_path;
        return false;
    }

    return true;
}

bool db::remove_hostap_supported_operating_classes(const sMacAddr &radio_mac)
{
    auto supported_channels = get_hostap_supported_channels(radio_mac);
    auto radio_node         = get_node(radio_mac);

    // Remove from data model
    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node with mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    auto op_class_path = radio_path + ".Capabilities.OperatingClasses";
    if (!m_ambiorix_datamodel->remove_all_instances(op_class_path)) {
        LOG(ERROR) << "Failed to remove all instances for: " << op_class_path;
        return false;
    }

    // Remove from database
    std::vector<beerocks::message::sWifiChannel>().swap(supported_channels);

    return true;
}

bool db::set_radio_utilization(const sMacAddr &bssid, uint8_t utilization)
{

    std::string bssid_string = tlvf::mac_to_string(bssid);

    auto find_node = std::find_if(
        std::begin(nodes), std::end(nodes),
        [&bssid_string](const std::unordered_map<std::string, std::shared_ptr<son::node>> &map) {
            return map.find(bssid_string) != map.end();
        });

    if (find_node == std::end(nodes)) {
        LOG(ERROR) << "Failed to get radio node for bssid: " << bssid_string;
        return false;
    }

    auto radio_node = find_node->at(bssid_string);

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Path to the object example: Controller.Network.Device.1.Radio.1.Utilization
    if (!m_ambiorix_datamodel->set(radio_path, "Utilization", utilization)) {
        LOG(ERROR) << "Failed to set " << radio_path << ".Utilization: " << utilization;
        return false;
    }

    return true;
}

bool db::dm_set_radio_bss(const sMacAddr &radio_mac, const sMacAddr &bssid, const std::string &ssid)
{
    auto radio_node = get_node(radio_mac);
    if (!radio_node) {
        LOG(ERROR) << "Failed to get Radio node with mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    /*
        Prepare path to the BSS instance.
        Example: Controller.Network.Device.1.Radio.1.BSS.
    */
    auto bss_path  = radio_path + ".BSS";
    auto bss_index = m_ambiorix_datamodel->get_instance_index(bss_path + ".[BSSID == '%s'].",
                                                              tlvf::mac_to_string(bssid));
    std::string bss_instance;

    if (!bss_index) {
        bss_instance = m_ambiorix_datamodel->add_instance(bss_path);
        if (bss_instance.empty()) {
            LOG(ERROR) << "Failed to add " << bss_path << " instance.";
            return false;
        }
    } else {
        LOG(DEBUG) << "BSS instance exists for BSSID: " << bssid << ". Updating Data Model.";
        bss_instance = bss_path + "." + std::to_string(bss_index) + ".";
    }

    /*
        Set value for BSSID variable
        Example: Controller.Network.Device.1.Radio.1.BSS.1.BSSID
    */
    if (!m_ambiorix_datamodel->set(bss_instance, "BSSID", tlvf::mac_to_string(bssid))) {
        LOG(ERROR) << "Failed to set " << bss_instance << "BSSID: " << bssid;
        return false;
    }

    /*
        Set value for SSID variable
        Example: Controller.Network.Device.1.Radio.1.BSS.1.SSID
    */
    if (!m_ambiorix_datamodel->set(bss_instance, "SSID", ssid)) {
        LOG(ERROR) << "Failed to set " << bss_instance << "SSID: " << ssid;
        return false;
    }

    /*
        Set value for Enabled variable
        Example: Controller.Network.Device.1.Radio.1.BSS.1.Enabled
    */
    if (!m_ambiorix_datamodel->set(bss_instance, "Enabled", !ssid.empty())) {
        LOG(ERROR) << "Failed to set " << bss_instance << "Enabled: " << !ssid.empty();
        return false;
    }

    /*
        Set value for LastChange variable - it is creation time, when someone will
        try to get data from this parameter action method will calculate time in seconds
        from creation moment.
        Example: Controller.Network.Device.1.Radio.1.BSS.1.LastChange
    */
    uint64_t creation_time = time(NULL);
    if (!m_ambiorix_datamodel->set(bss_instance, "LastChange", creation_time)) {
        LOG(ERROR) << "Failed to set " << bss_instance << "LastChange: " << creation_time;
        return false;
    }
    m_ambiorix_datamodel->set_current_time(bss_instance);
    return true;
}

bool db::set_radio_metrics(const sMacAddr &radio_mac, uint8_t noise, uint8_t transmit,
                           uint8_t receive_self, uint8_t receive_other)
{

    auto radio_node = get_node(radio_mac);
    if (!radio_node) {
        LOG(ERROR) << "Failed to get radio node for mac: " << radio_mac;
        return false;
    }

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        return true;
    }

    // Data model path example: Controller.Network.Device.1.Radio.1.Noise
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

// Cover the get_path_ code for skipping errors about finding the path
// when AmbiorixDummy enabled
#ifdef ENABLE_NBAPI
std::string db::dm_get_path_to_bss(const sMacAddr &bssid)
{
    std::string bssid_string = tlvf::mac_to_string(bssid);
    auto node                = get_node(bssid_string);

    if (!node) {
        LOG(ERROR) << "Failed to get radio node for bssid: " << bssid_string;
        return {};
    }

    auto find_node = std::find_if(
        std::begin(nodes), std::end(nodes),
        [&bssid_string](const std::unordered_map<std::string, std::shared_ptr<son::node>> &map) {
            return map.find(bssid_string) != map.end();
        });

    if (find_node == std::end(nodes)) {
        LOG(ERROR) << "Failed to get radio node for bssid: " << bssid_string;
        return {};
    }

    auto radio_node = find_node->at(bssid_string);

    auto radio_path = radio_node->dm_path;
    if (radio_path.empty()) {
        LOG(ERROR) << "Failed to get radio path for radio, mac: " << radio_node->mac;
        return {};
    }

    auto bss_path = radio_path + ".BSS.";
    auto bss_index =
        m_ambiorix_datamodel->get_instance_index(bss_path + "[BSSID == '%s']", bssid_string);
    if (!bss_index) {
        LOG(ERROR) << "Failed to get bss index for bss with mac: " << bssid_string;
        return {};
    }
    return radio_path + ".BSS." + std::to_string(bss_index) + ".";
}

#else
std::string db::dm_get_path_to_bss(const sMacAddr &bssid) { return "dummy!"; }
#endif

bool db::set_estimated_service_parameters_be(const sMacAddr &bssid,
                                             uint32_t estimated_service_parameters_be)
{
    std::string path_to_bss = dm_get_path_to_bss(bssid);
    if (path_to_bss.empty()) {
        LOG(ERROR) << "Failed get path to bss with mac: " << bssid;
        return false;
    }

    if (!m_ambiorix_datamodel->set(path_to_bss, "EstServiceParametersBE",
                                   estimated_service_parameters_be)) {
        LOG(ERROR) << "Failed to set " << path_to_bss
                   << ".EstServiceParametersBE: " << estimated_service_parameters_be;
        return false;
    }

    return true;
}

bool db::add_interface(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                       uint16_t media_type, const std::string &status, const std::string &name)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    auto iface = device->add_interface(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to add interface with mac: " << interface_mac;
        return false;
    }

    return dm_add_interface_element(device_mac, interface_mac, media_type, status, name);
}

std::shared_ptr<prplmesh::controller::db::Interface>
db::get_interface_node(const sMacAddr &device_mac, const sMacAddr &interface_mac)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return nullptr;
    }

    return device->get_interface(interface_mac);
}

bool db::dm_add_interface_element(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                                  uint16_t media_type, const std::string &status,
                                  const std::string &name)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    auto iface = device->get_interface(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    // Empty data path refers for newly created object, so add instance to data model.
    if (iface->m_dm_path.empty()) {

        // Disabled NBAPI error prevention
        if (device->dm_path.empty()) {
            return true;
        }

        // Prepare path to the Interface object, like Controller.Network.Device.{i}.Interface
        auto interface_path = device->dm_path + ".Interface";

        auto interface_instance = m_ambiorix_datamodel->add_instance(interface_path);
        if (interface_instance.empty()) {
            LOG(ERROR) << "Failed to add " << interface_path
                       << ". Interface MAC: " << interface_mac;
            return false;
        }

        iface->m_dm_path = interface_instance;
    }

    // Prepare path to the Interface object Status, like Controller.Network.Device.{i}.Interface.{i}.Status
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "Status", status)) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".Status: " << status;
        return false;
    }
    // Prepare path to the Interface object MACAddress, like Controller.Network.Device.{i}.Interface.{i}.MACAddress
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "MACAddress",
                                   tlvf::mac_to_string(interface_mac))) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".MACAddress: " << interface_mac;
        return false;
    }
    // Prepare path to the Interface object Name, like Controller.Network.Device.{i}.Interface.{i}.Name
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "Name",
                                   (name.empty() ? tlvf::mac_to_string(interface_mac) : name))) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".Name: " << name;
        return false;
    }
    // Prepare path to the Interface object MediaType, like Controller.Network.Device.{i}.Interface.{i}.MediaType
    if (!m_ambiorix_datamodel->set(iface->m_dm_path, "MediaType", media_type)) {
        LOG(ERROR) << "Failed to set " << iface->m_dm_path << ".MediaType: " << media_type;
        return false;
    }
    return true;
}

bool db::remove_interface(const sMacAddr &device_mac, const sMacAddr &interface_mac)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    dm_remove_interface_element(device_mac, interface_mac);
    device->remove_interface(interface_mac);
    return true;
}

bool db::dm_remove_interface_element(const sMacAddr &device_mac, const sMacAddr &interface_mac)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    auto iface = device->get_interface(interface_mac);
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
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    std::vector<sMacAddr> erase_mac_list = device->get_unused_interfaces(interface_macs);
    for (const auto &iface_mac : erase_mac_list) {
        remove_interface(device_mac, iface_mac);
    }
    return true;
}

bool db::dm_update_interface_tx_stats(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                                      uint64_t packets_sent, uint32_t errors_sent)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    auto iface = device->get_interface(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    if (iface->m_dm_path.empty()) {
        return true;
    }

    // Prepare path to the Interface object Stats, like Controller.Network.Device.{i}.Interface.{i}.Stats
    auto stats_path = iface->m_dm_path + ".Stats";

    // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Stats.PacketsSent
    if (!m_ambiorix_datamodel->set(stats_path, "PacketsSent", packets_sent)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".PacketsSent: " << packets_sent;
        return false;
    }

    // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Stats.ErrorsSent
    if (!m_ambiorix_datamodel->set(stats_path, "ErrorsSent", errors_sent)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".ErrorsSent: " << errors_sent;
        return false;
    }

    return true;
}

bool db::dm_update_interface_rx_stats(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                                      uint64_t packets_received, uint32_t errors_received)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    auto iface = device->get_interface(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    if (iface->m_dm_path.empty()) {
        return true;
    }

    // Prepare path to the Interface object Stats, like Controller.Network.Device.{i}.Interface.{i}.Stats
    auto stats_path = iface->m_dm_path + ".Stats";

    // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Stats.PacketsReceived
    if (!m_ambiorix_datamodel->set(stats_path, "PacketsReceived", packets_received)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".PacketsReceived: " << packets_received;
        return false;
    }

    // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Stats.ErrorsReceived
    if (!m_ambiorix_datamodel->set(stats_path, "ErrorsReceived", errors_received)) {
        LOG(ERROR) << "Failed to set " << stats_path << ".ErrorsReceived: " << errors_received;
        return false;
    }

    return true;
}

bool db::add_neighbor(const sMacAddr &device_mac, const sMacAddr &interface_mac,
                      const sMacAddr &neighbor_mac, bool is_IEEE1905)
{
    auto device = get_node(device_mac);
    if (!device) {
        LOG(ERROR) << "Failed to get device node with mac: " << device_mac;
        return false;
    }

    auto iface = device->get_interface(interface_mac);
    if (!iface) {
        LOG(ERROR) << "Failed to get interface with mac: " << interface_mac;
        return false;
    }

    auto neighbor = device->add_neighbor(interface_mac, neighbor_mac, is_IEEE1905);
    if (!neighbor) {
        LOG(ERROR) << "Failed to add neighbor with mac: " << neighbor_mac;
        return false;
    }

    return dm_add_interface_neighbor(iface, neighbor);
}

bool db::dm_add_interface_neighbor(
    std::shared_ptr<prplmesh::controller::db::Interface> &interface,
    std::shared_ptr<prplmesh::controller::db::Interface::sNeighbor> &neighbor)
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

        // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Neighbor.{i}
        auto neighbor_path = interface->m_dm_path + ".Neighbor";

        auto neighbor_instance = m_ambiorix_datamodel->add_instance(neighbor_path);
        if (neighbor_instance.empty()) {
            LOG(ERROR) << "Failed to add " << neighbor_path << ". Neighbor MAC: " << neighbor->mac;
            return false;
        }

        neighbor->dm_path = neighbor_instance;
    }

    // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Neighbor.{i}.ID
    if (!m_ambiorix_datamodel->set(neighbor->dm_path, "ID", tlvf::mac_to_string(neighbor->mac))) {
        LOG(ERROR) << "Failed to set " << neighbor->dm_path << ".ID: " << neighbor->mac;
        return false;
    }

    // Set value for the path as Controller.Network.Device.{i}.Interface.{i}.Neighbor.{i}.IsIEEE1905
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
    auto sta_node = get_node(sta_mac);

    if (!sta_node || sta_node->get_type() != TYPE_CLIENT) {
        LOG(ERROR) << "Failed to get station node with mac: " << sta_mac;
        return false;
    }

    std::string path_to_sta = sta_node->dm_path;

    if (path_to_sta.empty()) {
        return true;
    }

    // Path example to the variable in Data Model
    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataDownlinkRate
    if (!m_ambiorix_datamodel->set(path_to_sta, "LastDataDownlinkRate",
                                   metrics.last_data_down_link_rate)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".LastDataDownlinkRate: " << metrics.last_data_down_link_rate;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataUplinkRate
    if (!m_ambiorix_datamodel->set(path_to_sta, "LastDataUplinkRate",
                                   metrics.last_data_up_link_rate)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".LastDataUplinkRate: " << metrics.last_data_up_link_rate;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationReceive
    if (!m_ambiorix_datamodel->set(path_to_sta, "UtilizationReceive",
                                   metrics.utilization_receive)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".UtilizationReceive: " << metrics.utilization_receive;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationTransmit
    if (!m_ambiorix_datamodel->set(path_to_sta, "UtilizationTransmit",
                                   metrics.utilization_transmit)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".UtilizationTransmit: " << metrics.utilization_transmit;
        return false;
    }
    return true;
}

bool db::dm_set_sta_traffic_stats(const sMacAddr &sta_mac, sAssociatedStaTrafficStats &stats)
{
    auto sta_node = get_node(sta_mac);

    if (!sta_node || sta_node->get_type() != TYPE_CLIENT) {
        LOG(ERROR) << "Failed to get station node with mac: " << sta_mac;
        return false;
    }

    std::string path_to_sta = sta_node->dm_path;

    if (path_to_sta.empty()) {
        return true;
    }

    // Path example to the variable in Data Model
    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesSent
    if (!m_ambiorix_datamodel->set(path_to_sta, "BytesSent", stats.m_byte_sent)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".BytesSent: " << stats.m_byte_sent;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesReceived
    if (!m_ambiorix_datamodel->set(path_to_sta, "BytesReceived", stats.m_byte_received)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".BytesReceived: " << stats.m_byte_received;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsSent
    if (!m_ambiorix_datamodel->set(path_to_sta, "PacketsSent", stats.m_packets_sent)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".PacketsSent: " << stats.m_packets_sent;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsReceived
    if (!m_ambiorix_datamodel->set(path_to_sta, "PacketsReceived", stats.m_packets_received)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".PacketsReceived: " << stats.m_packets_received;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.4.RetransCount
    if (!m_ambiorix_datamodel->set(path_to_sta, "RetransCount", stats.m_retransmission_count)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".RetransCount: " << stats.m_retransmission_count;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsSent
    if (!m_ambiorix_datamodel->set(path_to_sta, "ErrorsSent", stats.m_tx_packets_error)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".ErrorsSent: " << stats.m_tx_packets_error;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsReceived
    if (!m_ambiorix_datamodel->set(path_to_sta, "ErrorsReceived", stats.m_rx_packets_error)) {
        LOG(ERROR) << "Failed to set " << path_to_sta
                   << ".ErrorsReceived: " << stats.m_rx_packets_error;
        return false;
    }
    return true;
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

bool db::dm_remove_sta(const sMacAddr &sta_mac)
{
    auto sta_node = get_node(sta_mac);

    if (!sta_node || sta_node->get_type() != TYPE_CLIENT) {
        LOG(ERROR) << "Failed to get station node with mac: " << sta_mac;
        return false;
    }

    auto instance = get_dm_index_from_path(sta_node->dm_path);

    if (!m_ambiorix_datamodel->remove_instance(instance.first, instance.second)) {
        LOG(ERROR) << "Failed to remove " << sta_node->dm_path << " instance.";
        return false;
    }

    return true;
}

bool db::set_sta_dhcp_v4_lease(const sMacAddr &sta_mac, const std::string &host_name,
                               const std::string &ipv4_address)
{
    auto sta_node = get_node(sta_mac);

    if (!sta_node || sta_node->get_type() != TYPE_CLIENT) {
        return false;
    }

    // Update node attributes.
    sta_node->ipv4 = ipv4_address;
    sta_node->name = host_name;

    // Update datamodel attributes.
    std::string path_to_sta = sta_node->dm_path;

    if (path_to_sta.empty()) {
        return true;
    }

    // Path example to the variable in Data Model
    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname
    if (!m_ambiorix_datamodel->set(path_to_sta, "Hostname", host_name)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".Hostname: " << host_name;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.IPV4Address
    if (!m_ambiorix_datamodel->set(path_to_sta, "IPV4Address", ipv4_address)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".IPV4Address: " << ipv4_address;
        return false;
    }

    return true;
}

bool db::set_sta_dhcp_v6_lease(const sMacAddr &sta_mac, const std::string &host_name,
                               const std::string &ipv6_address)
{
    auto sta_node = get_node(sta_mac);

    if (!sta_node || sta_node->get_type() != TYPE_CLIENT) {
        return false;
    }

    // Update node attributes.
    sta_node->name = host_name;

    // Update datamodel attributes.
    std::string path_to_sta = sta_node->dm_path;

    if (path_to_sta.empty()) {
        return true;
    }

    // Path example to the variable in Data Model
    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname
    if (!m_ambiorix_datamodel->set(path_to_sta, "Hostname", host_name)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".Hostname: " << host_name;
        return false;
    }

    // Controller.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.IPV6Address
    if (!m_ambiorix_datamodel->set(path_to_sta, "IPV6Address", ipv6_address)) {
        LOG(ERROR) << "Failed to set " << path_to_sta << ".IPV6Address: " << ipv6_address;
        return false;
    }

    return true;
}
