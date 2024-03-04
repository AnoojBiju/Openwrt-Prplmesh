
/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "topology_task.h"
#include "../db/db_algo.h"
#include "../son_actions.h"
#include "bml_task.h"
#include "btm_request_task.h"
#include "client_steering_task.h"
#include "dhcp_task.h"

#include <bcl/beerocks_wifi_channel.h>
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <easylogging++.h>
#include <tlvf/ieee_1905_1/s802_11SpecificInformation.h>
#include <tlvf/ieee_1905_1/tlv1905NeighborDevice.h>
#include <tlvf/ieee_1905_1/tlvDeviceInformation.h>
#include <tlvf/ieee_1905_1/tlvNon1905neighborDeviceList.h>
#include <tlvf/wfa_map/tlvApOperationalBSS.h>
#include <tlvf/wfa_map/tlvClientAssociationEvent.h>
#include <tlvf/wfa_map/tlvProfile2ReasonCode.h>

#include <beerocks/tlvf/beerocks_message_1905_vs.h>

#ifdef FEATURE_PRE_ASSOCIATION_STEERING
#include "pre_association_steering/pre_association_steering_task.h"
#endif

using namespace beerocks;
using namespace net;
using namespace son;

topology_task::topology_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_)
    : task("topology_task"), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_)
{
}

void topology_task::work() {}

bool topology_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                          ieee1905_1::CmduMessageRx &cmdu_rx)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::TOPOLOGY_RESPONSE_MESSAGE: {
        handle_topology_response(src_mac, cmdu_rx);
        break;
    }
    case ieee1905_1::eMessageType::TOPOLOGY_NOTIFICATION_MESSAGE: {
        handle_topology_notification(src_mac, cmdu_rx);
        break;
    }
    default: {
        return false;
    }
    }
    return true;
}

bool topology_task::handle_topology_response(const sMacAddr &src_mac,
                                             ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received TOPOLOGY_RESPONSE_MESSAGE from " << src_mac << ", mid=" << std::hex
               << int(mid);

    auto tlvDeviceInformation = cmdu_rx.getClass<ieee1905_1::tlvDeviceInformation>();
    if (!tlvDeviceInformation) {
        LOG(ERROR) << "ieee1905_1::tlvDeviceInformation not found";
        return false;
    }

    const auto &al_mac = tlvDeviceInformation->mac();

    auto agent = database.m_agents.get(al_mac);
    if (!agent) {
        LOG(WARNING) << "Agent with mac is not found in database mac=" << al_mac;
        return false;
    }

    // Update Profile Information in Agent.
    auto tlvProfile2MultiApProfile = cmdu_rx.getClass<wfa_map::tlvProfile2MultiApProfile>();
    if (tlvProfile2MultiApProfile) {
        agent->profile = tlvProfile2MultiApProfile->profile();
        if (!database.dm_set_device_multi_ap_profile(*agent)) {
            LOG(ERROR) << "Failed to set Multi-AP profile in DM for Agent " << agent->al_mac;
            return false;
        }
    }

    // Set agent backhaul link as etherent and parent as empty for external Agents
    // According to wireless interface connections, parameters are updated.
    // Default backhaul interface mac is bridge MAC (al_mac) for wired devices.
    //TODO: Wired parent link will be detected at the end of Topology Response (PPM-2043)
    if (!agent->is_gateway) {
        agent->backhaul.backhaul_iface_type = beerocks::IFACE_TYPE_ETHERNET;

        //TODO: if needed, parse Device Bridge Capability (PPM-133)
        agent->backhaul.backhaul_interface = al_mac;
        agent->backhaul.parent_agent.reset();
        agent->backhaul.parent_interface        = beerocks::net::network_utils::ZERO_MAC;
        agent->backhaul.wireless_backhaul_radio = nullptr;
    }

    std::vector<sMacAddr> interface_macs{};

    for (uint8_t i = 0; i < tlvDeviceInformation->local_interface_list_length(); i++) {
        const auto iface_info_tuple = tlvDeviceInformation->local_interface_list(i);
        if (!std::get<0>(iface_info_tuple)) {
            LOG(ERROR) << "Failed to get " << int(i) << " element of local iface info "
                       << "on Device Information TLV";
            return false;
        }

        auto &iface_info = std::get<1>(iface_info_tuple);

        const auto &iface_mac = iface_info.mac();
        auto iface_mac_str    = tlvf::mac_to_string(iface_mac);

        const auto media_type       = iface_info.media_type();
        const auto media_type_group = media_type >> 8;

        interface_macs.push_back(iface_mac);

        // TODO Name and Status of Interface should be add
        database.add_interface(al_mac, iface_mac, media_type);

        LOG(DEBUG) << "Interface is added al_mac:" << al_mac << " iface_mac:" << iface_mac;
        LOG(DEBUG) << "media type: " << media_type
                   << " group: " << tlvf::print_media_type_group(media_type_group)
                   << " info length: " << iface_info.media_info_length();

        // Check that the interface belongs to the IEEE 802.3 group.
        if (ieee1905_1::eMediaTypeGroup::IEEE_802_3 == media_type_group) {
            LOG(DEBUG) << "New 802.3 interface is reported with mac=" << iface_mac;
            // TODO Add implementation for 802.3 interfaces.
        }

        // Check that the interface belongs to the IEEE 802.11 group.
        // For wireless interface it is defined on IEEE 1905.1 that the size of the media info
        // is n=10 octets, which the size of s802_11SpecificInformation struct.
        // For wired interface n=0.
        if ((ieee1905_1::eMediaTypeGroup::IEEE_802_11 == media_type_group) &&
            (iface_info.media_info_length() == 10)) {

            const auto media_info = reinterpret_cast<ieee1905_1::s802_11SpecificInformation *>(
                iface_info.media_info(0));
            const auto iface_role = media_info->role;

            auto print_interface_role = [](const ieee1905_1::eRole iface_role) -> std::string {
                switch (iface_role) {
                case ieee1905_1::eRole::AP:
                    return "AP";
                case ieee1905_1::eRole::NON_AP_NON_PCP_STA:
                    return "STA";
                case ieee1905_1::eRole::WI_FI_P2P_CLIENT:
                    return "P2P-Client";
                case ieee1905_1::eRole::WI_FI_P2P_GROUP_OWNER:
                    return "GO";
                case ieee1905_1::eRole::IEEE_802_11AD_PCP:
                    return "PCP";
                default:
                    return "NA";
                }
            };

            LOG(DEBUG) << "New 1905.1 wireless interface is reported with mac=" << iface_mac
                       << ", role=" << print_interface_role(iface_role);

            // For future implementation
            // const auto iface_bw     = media_info->ap_channel_bandwidth;
            // const auto iface_cf1    = media_info->ap_channel_center_frequency_index1;
            // const auto iface_cf2    = media_info->ap_channel_center_frequency_index2;

            // This is the case where agent reports that it has wireless backhaul connection
            // TODO: If agent has wired & wireless (stale) backhaul connection at the same time,
            // wireless connection is considered active. (PPM-2043)
            if (iface_role == ieee1905_1::eRole::NON_AP_NON_PCP_STA &&
                media_info->network_membership != beerocks::net::network_utils::ZERO_MAC) {

                // Search parent/connected agent
                auto parent_agent = database.get_agent_by_bssid(media_info->network_membership);
                if (!parent_agent) {
                    LOG(ERROR) << "Parent agent is not found on database";
                    continue;
                }

                auto backhaul_sta = database.get_station(iface_mac);
                if (!backhaul_sta) {
                    LOG(ERROR) << "Backhaul station is not found on database";
                    continue;
                }

                auto parent_bss = backhaul_sta->get_bss();
                if (!parent_bss) {
                    LOG(ERROR) << "Connected BSS of the station is not found, sta mac="
                               << backhaul_sta->mac;
                    continue;
                }

                // Network Membership verification from database
                // This case could occur, if we can topology response before topology notification
                // with JOIN notification for that station.
                if (media_info->network_membership != parent_bss->bssid) {
                    LOG(INFO) << "Network membership does not align with database, parent_bssid="
                              << parent_bss->bssid
                              << ", network_membership=" << media_info->network_membership;
                    continue;
                }

                LOG(DEBUG) << "Wireless BH Link is reported for agent=" << agent->al_mac
                           << " parent agent=" << parent_agent->al_mac
                           << " parent's bss=" << parent_bss->bssid << " with bSTA=" << iface_mac;

                agent->backhaul.parent_agent = parent_agent;

                // Set backhaul link type as wireless
                agent->backhaul.backhaul_iface_type = beerocks::IFACE_TYPE_WIFI_UNSPECIFIED;

                // Set backhaul interface
                agent->backhaul.backhaul_interface = iface_mac;
                agent->backhaul.parent_interface   = media_info->network_membership;
                agent->backhaul.wireless_backhaul_radio =
                    database.get_radio_by_backhaul_cap(media_info->network_membership);
            }
        }
    }

    // Update external agents multi ap backhaul datamodel
    if (!agent->is_gateway) {
        database.dm_set_device_multi_ap_backhaul(*agent);
    }

    // Update active mac list of the device node
    database.dm_update_interface_elements(al_mac, interface_macs);

    // create topology response update event for bml listeners
    bml_task::topology_response_update_event new_bml_event;
    new_bml_event.al_mac = al_mac;
    for (const auto &radio_elm : agent->radios) {
        LOG(INFO) << "Added radio " << radio_elm.first << " to the BML event.";
        new_bml_event.radio_interfaces.push_back(radio_elm.first);
    }
    tasks.push_event(database.get_bml_task_id(), bml_task::TOPOLOGY_RESPONSE_UPDATE,
                     &new_bml_event);

    //Parse BssidIfaceMapping vsTLV
    std::unordered_map<sMacAddr, int8_t> bssid_vap_map;
    std::shared_ptr<beerocks_message::tlvVsBssidIfaceMapping> tlvBssidIfaceMapping;
    auto beerocks_header = beerocks::message_com::parse_intel_vs_message(cmdu_rx);
    if (beerocks_header) {
        tlvBssidIfaceMapping =
            beerocks_header->addClass<beerocks_message::tlvVsBssidIfaceMapping>();
    }
    if (tlvBssidIfaceMapping) {
        LOG(DEBUG) << "Received Bssid Interface Mapping vsTLV from prplMesh agent";
        for (uint8_t i = 0; i < tlvBssidIfaceMapping->bssid_vap_id_map_length(); i++) {
            beerocks_message::sBssidVapId &bssid_vap_id =
                std::get<1>(tlvBssidIfaceMapping->bssid_vap_id_map(i));
            if (bssid_vap_id.bssid != network_utils::ZERO_MAC) {
                bssid_vap_map.emplace(bssid_vap_id.bssid, bssid_vap_id.vap_id);
            }
        }
    }

    auto tlvApInformation = cmdu_rx.getClass<wfa_map::tlvApOperationalBSS>();
    if (tlvApInformation) {
        for (uint8_t i = 0; i < tlvApInformation->radio_list_length(); i++) {
            auto radio_entry = std::get<1>(tlvApInformation->radio_list(i));
            LOG(DEBUG) << "Operational BSS radio " << radio_entry.radio_uid();

            // Update BSSes in the Agent
            auto radio = database.get_radio(src_mac, radio_entry.radio_uid());
            if (!radio) {
                LOG(WARNING) << "OperationalBSS on unknown radio  " << radio_entry.radio_uid()
                             << " on " << src_mac;
                continue;
            }

            radio->bsses.keep_new_prepare();
            for (uint8_t j = 0; j < radio_entry.radio_bss_list_length(); j++) {
                auto bss_entry = std::get<1>(radio_entry.radio_bss_list(j));
                LOG(DEBUG) << "Operational BSS " << bss_entry.radio_bssid();

                //Setting default values.
                int8_t vap_id = eBeeRocksIfaceIds::IFACE_ID_INVALID;

                auto vap_map_it = bssid_vap_map.find(bss_entry.radio_bssid());
                if (!bssid_vap_map.empty() && vap_map_it == bssid_vap_map.end()) {
                    /* We don't expect the Controller to get inside this condition.
                     * If we don't find the reported BSSID from the AP Operational BSS TLV
                     * inside this bssid_vap_map and if the same map is not empty, then
                     * there is a problem with the agent filling up wrong BSSIDs
                     * inside the tlvVsBssidIfaceMapping, hence a fatal message is displayed.
                     */
                    LOG(FATAL) << "Fatal BssidIfaceMapping message";
                    return false;
                } else if (vap_map_it != bssid_vap_map.end()) {
                    vap_id = vap_map_it->second;
                    LOG(DEBUG) << "bssid=" << vap_map_it->first << ", vap_id=" << int(vap_id);
                }

                auto bss =
                    database.add_bss(*radio, bss_entry.radio_bssid(), bss_entry.ssid_str(), vap_id);
                bss->enabled = true;
                // Backhaul is not reported in this message. Leave it unchanged.
                // TODO "backhaul" is not set in this TLV, so just assume false
                if (vap_id == eBeeRocksIfaceIds::IFACE_ID_INVALID) {
                    LOG(DEBUG) << "Non-Prplmesh Agent";
                    if (!database.update_vap(src_mac, radio_entry.radio_uid(),
                                             bss_entry.radio_bssid(), bss_entry.ssid_str(),
                                             false)) {
                        LOG(ERROR) << "Failed to update VAP for radio " << radio_entry.radio_uid()
                                   << " BSS " << bss_entry.radio_bssid() << " SSID "
                                   << bss_entry.ssid_str();
                    }
                } else {
                    LOG(DEBUG) << "Prplmesh Agent";
                    // update BSS vap_id if still undefined
                    bss->update_vap_id(vap_id);
                    if (!database.add_vap(al_mac, tlvf::mac_to_string(radio_entry.radio_uid()),
                                          int(vap_id), tlvf::mac_to_string(bss_entry.radio_bssid()),
                                          bss_entry.ssid_str(), false)) {
                        LOG(ERROR)
                            << "Failed to add VAP for radio " << radio_entry.radio_uid() << " BSS "
                            << bss_entry.radio_bssid() << " SSID " << bss_entry.ssid_str();
                    }
                }
            }
            auto removed = radio->bsses.keep_new_remove_old();
            for (const auto &bss : removed) {
                // Remove all clients from that vap
                auto client_list = database.get_node_children(tlvf::mac_to_string(bss->bssid),
                                                              beerocks::TYPE_CLIENT);
                for (auto &client : client_list) {
                    son_actions::handle_dead_node(client, true, database, tasks);
                }

                // Remove the vap from DB
                LOG(DEBUG) << "Removing BSS with path " << bss->dm_path << " from DB";
                database.remove_vap(*radio, *bss);
            }
        }
    }

    /* If this TLV is recieved in the 1905.1 Topology Response Message...
         then the src agent is hosting VBSSes (which were sent in the AP Operational BSS TLV) which now need to be marked as virtual
    */
    auto vbss_config_report_tlv = cmdu_rx.getClass<wfa_map::VbssConfigurationReport>();
    if (vbss_config_report_tlv) {
        handle_vbss_configuration_tlv(src_mac, vbss_config_report_tlv);
    }

    for (const auto &iface_mac : interface_macs) {

        auto iface_node = database.get_interface_node(al_mac, iface_mac);
        if (!iface_node) {
            LOG(ERROR) << "Failed to get interface node with mac: " << iface_mac;
            continue;
        }
        iface_node->m_neighbors.keep_new_prepare();
        auto interface = agent->interfaces.get(iface_mac);
        if (interface) {
            interface->neighbors.keep_new_prepare();
        }
    }

    // The reported neighbors list might not be correct since the reporting al_mac hasn't received
    // a Topology Discovery from its neighbors yet. Therefore, remove a neighbor node only if more
    // than 65 seconds (timeout according to standard + 5 seconds grace) have passed since we added
    // this node. This promise that the reported al_mac will get the Topology Discovery messages
    // from its neighbors and add them to the report.
    bool check_dead_neighbors =
        (database.get_last_state_change(tlvf::mac_to_string(src_mac)) +
             std::chrono::seconds(beerocks::ieee1905_1_consts::DISCOVERY_NOTIFICATION_TIMEOUT_SEC +
                                  5) <
         std::chrono::steady_clock::now());

    std::unordered_set<sMacAddr> reported_neighbor_al_macs;
    auto tlv1905NeighborDeviceList = cmdu_rx.getClassList<ieee1905_1::tlv1905NeighborDevice>();

    for (const auto &tlv1905NeighborDevice : tlv1905NeighborDeviceList) {
        if (!tlv1905NeighborDevice) {
            LOG(ERROR) << "ieee1905_1::tlv1905NeighborDevice has invalid pointer";
            return false;
        }

        auto device_count = tlv1905NeighborDevice->mac_al_1905_device_length() /
                            sizeof(ieee1905_1::tlv1905NeighborDevice::sMacAl1905Device);

        for (size_t i = 0; i < device_count; i++) {
            const auto neighbor_al_mac_tuple = tlv1905NeighborDevice->mac_al_1905_device(i);
            if (!std::get<0>(neighbor_al_mac_tuple)) {
                LOG(ERROR) << "Getting al_mac element has failed";
                return false;
            }

            auto &neighbor_al_mac = std::get<1>(neighbor_al_mac_tuple).mac;

            // Add neighbor to related the interface
            database.add_neighbor(al_mac, tlv1905NeighborDevice->mac_local_iface(), neighbor_al_mac,
                                  true);

            LOG(DEBUG) << "Inserting reported 1905 neighbor " << neighbor_al_mac << " to the list";
            reported_neighbor_al_macs.insert(neighbor_al_mac);
        }
    }

    recently_reported_neighbors[al_mac] = std::chrono::steady_clock::now();
    // Remove neighbors from recently_reported_neighbors map if they stay there more than 5 seconds.
    for (auto neighbor = recently_reported_neighbors.begin();
         neighbor != recently_reported_neighbors.end();) {
        if (std::chrono::seconds(5) < (std::chrono::steady_clock::now() - neighbor->second)) {
            neighbor = recently_reported_neighbors.erase(neighbor);
        } else {
            ++neighbor;
        }
    }

    for (auto reported_neighbor_mac : reported_neighbor_al_macs) {
        if (!database.has_node(reported_neighbor_mac) &&
            recently_reported_neighbors.find(reported_neighbor_mac) ==
                recently_reported_neighbors.end()) {
            // Send a Topology Query if any new neighbor was detected.
            if (!cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_QUERY_MESSAGE)) {
                LOG(ERROR) << "Failed to build TOPOLOGY_QUERY_MESSAGE message!";
            }
            // Save just reported new neighbor to avoid sending unnecessary multiple
            // Topology Query from different devices to the same new node.
            recently_reported_neighbors.insert(
                {reported_neighbor_mac, std::chrono::steady_clock::now()});
            son_actions::send_cmdu_to_agent(reported_neighbor_mac, cmdu_tx, database);
            // Send an AP-AutoConfiguration Renew message to notify the neighbor
            // that an AP-AutoConfiguration WSC message should be sent.
            son_actions::send_ap_config_renew_msg(cmdu_tx, database);
        }
    }

    auto tlvNon1905NeighborDeviceList =
        cmdu_rx.getClassList<ieee1905_1::tlvNon1905neighborDeviceList>();

    for (const auto &tlvNon1905NeighborDevice : tlvNon1905NeighborDeviceList) {
        if (!tlvNon1905NeighborDevice) {
            LOG(ERROR) << "ieee1905_1::tlvNon1905NeighborDevice has invalid pointer";
            return false;
        }

        auto device_count =
            tlvNon1905NeighborDevice->mac_non_1905_device_length() / sizeof(sMacAddr);

        for (size_t i = 0; i < device_count; i++) {
            const auto neighbor_al_mac_tuple = tlvNon1905NeighborDevice->mac_non_1905_device(i);
            if (!std::get<0>(neighbor_al_mac_tuple)) {
                LOG(ERROR) << "Getting al_mac element has failed";
                return false;
            }

            auto &neighbor_al_mac = std::get<1>(neighbor_al_mac_tuple);

            // Add neighbor to related the interface
            database.add_neighbor(al_mac, tlvNon1905NeighborDevice->mac_local_iface(),
                                  neighbor_al_mac, false);

            LOG(DEBUG) << "Inserting reported non 1905 neighbor " << neighbor_al_mac
                       << " to the list";
        }
    }

    if (check_dead_neighbors) {
        handle_dead_neighbors(src_mac, al_mac, reported_neighbor_al_macs);
    }

    // Update active neighbors mac list of the interface node
    for (const auto &iface_mac : interface_macs) {

        auto iface_node = database.get_interface_node(al_mac, iface_mac);
        if (!iface_node) {
            LOG(ERROR) << "Failed to get interface node with mac: " << iface_mac;
            continue;
        }

        auto removed_neighbors = iface_node->m_neighbors.keep_new_remove_old();
        auto interface         = agent->interfaces.get(iface_mac);
        if (interface) {
            interface->neighbors.keep_new_remove_old();
        }

        // Removed members needs to be cleaned up from datamodel also.
        for (const auto &removed_neighbor : removed_neighbors) {
            database.dm_remove_interface_neighbor(removed_neighbor->dm_path);
        }
    }

    //TODO: After handling Device and Neighbor Information, identify Parent Agent (PPM-2043)

    return true;
}

void topology_task::handle_vbss_configuration_tlv(
    const sMacAddr &src_mac, std::shared_ptr<wfa_map::VbssConfigurationReport> config_report_tlv)
{

    uint8_t num_radios = config_report_tlv->number_of_radios();
    for (uint8_t radio_idx = 0; radio_idx < num_radios; radio_idx++) {
        auto radio_tup = config_report_tlv->radio_list(radio_idx);
        if (!std::get<0>(radio_tup)) {
            LOG(ERROR) << "Failed to get radio (from VbssConfigurationReport) for index "
                       << radio_idx;
            continue;
        }
        auto radio_info = std::get<1>(radio_tup);

        for (uint8_t bss_idx = 0; bss_idx < radio_info.number_bss(); bss_idx++) {
            auto bss_tup = radio_info.bss_list(bss_idx);
            if (!std::get<0>(bss_tup)) {
                LOG(ERROR) << "Failed to get BSS (from VbssConfigurationReport) for radio at index "
                           << radio_idx << " at index " << bss_idx;
                continue;
            }
            auto bss_info = std::get<1>(bss_tup);

            // BSS already exists since it was passed in the AP Operational BSS TLV,
            // Just declare that this BSS is a virtual BSS
            auto existing_bss = database.get_bss(bss_info.bssid());
            if (!existing_bss) {
                LOG(ERROR) << "Failed to set BSS (" << bss_info.bssid()
                           << ") as a virtual BSS! BSS does not exist for BSSID!";
                continue;
            }

            existing_bss->is_vbss = true;
            database.get_ambiorix_obj()->set(existing_bss->dm_path, "IsVBSS", true);
        }
    }
}

void topology_task::handle_dead_neighbors(const sMacAddr &src_mac, const sMacAddr &al_mac,
                                          std::unordered_set<sMacAddr> reported_neighbor_al_macs)
{
    LOG(TRACE) << "Checking if one of " << src_mac << " neighbors is no longer connected";

    auto neighbor_al_macs_on_db = database.get_1905_1_neighbors(al_mac);
    LOG(DEBUG) << "Comparing reported neighbors to neighbors on the database, neighbors_on_db="
               << neighbor_al_macs_on_db.size();

    for (const auto &neighbor_al_mac_on_db : neighbor_al_macs_on_db) {

        LOG(DEBUG) << "Checks if al_mac " << al_mac << " neighbor " << neighbor_al_mac_on_db
                   << " is reported in this message";

        // If reported al_mac is on the db skip it, otherwise remove the node.
        if (reported_neighbor_al_macs.find(neighbor_al_mac_on_db) !=
            reported_neighbor_al_macs.end()) {
            continue;
        }

        std::string neighbor_al_mac_on_db_str = tlvf::mac_to_string(neighbor_al_mac_on_db);
        auto backhhaul_mac                    = database.get_node_parent(neighbor_al_mac_on_db_str);

        // It is possible that re-routing took place, and the node is now a neighbour of some
        // other node. To filter such cases, compare the current al_mac of the neighbor to the
        // al_mac of the reporter. If they are not equal then it means than the neighbor is
        // currently under another node.
        auto current_parent_al_mac = database.get_node_parent_ire(backhhaul_mac);
        if (current_parent_al_mac != src_mac) {
            continue;
        }

        LOG(DEBUG) << "known neighbor al_mac  " << neighbor_al_mac_on_db
                   << " is not reported on 1905 Neighbor Device TLV, removing the al_mac node";
        son_actions::handle_dead_node(backhhaul_mac, true, database, tasks);
    }
}

bool topology_task::handle_topology_notification(const sMacAddr &src_mac,
                                                 ieee1905_1::CmduMessageRx &cmdu_rx)
{

    auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received TOPOLOGY_NOTIFICATION_MESSAGE, from " << src_mac << ", mid=" << std::hex
               << int(mid);

    // IEEE 1905.1 defines that TOPOLOGY_NOTIFICATION_MESSAGE must containt one 1905.1 AL MAC
    // address type TLV, and MultiAp standard extend it with zero or one Client Association Event
    // TLV. So if we didn't receive Client Association Event TLV, we need to send
    // TOPOLOGY_QUERY_MESSAGE to figure out what has changed on the topology.
    auto client_association_event_tlv = cmdu_rx.getClass<wfa_map::tlvClientAssociationEvent>();
    if (!client_association_event_tlv) {
        LOG(INFO) << "wfa_map::tlvClientAssociationEvent not found, sending TOPOLOGY_QUERY_MESSAGE";

        return son_actions::send_topology_query_msg(src_mac, cmdu_tx, database);
    }

    std::shared_ptr<beerocks_message::tlvVsClientAssociationEvent> vs_tlv = nullptr;
    auto beerocks_header = beerocks::message_com::parse_intel_vs_message(cmdu_rx);
    if (beerocks_header) {
        vs_tlv = beerocks_header->addClass<beerocks_message::tlvVsClientAssociationEvent>();
        if (!vs_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvVsClientAssociationEvent failed";
            return false;
        }
    }

    auto &client_mac    = client_association_event_tlv->client_mac();
    auto client_mac_str = tlvf::mac_to_string(client_mac);

    auto &bssid    = client_association_event_tlv->bssid();
    auto bssid_str = tlvf::mac_to_string(bssid);

    auto association_event = client_association_event_tlv->association_event();
    bool client_connected =
        (association_event == wfa_map::tlvClientAssociationEvent::CLIENT_HAS_JOINED_THE_BSS);

    LOG(INFO) << "client " << (client_connected ? "connected" : "disconnected")
              << ", client_mac=" << client_mac_str << ", bssid=" << bssid_str;

    if (client_connected) {
        //add or update node parent
        auto client = database.add_node_station(src_mac, client_mac, bssid);
        if (!client) {
            LOG(ERROR) << "client " << client_mac << " not created";
            return false;
        }

        LOG(INFO) << "client connected, al_mac=" << src_mac << " mac=" << client_mac_str
                  << ", bssid=" << bssid_str;

        auto wifi_channel = database.get_node_wifi_channel(bssid_str);
        if (wifi_channel.is_empty()) {
            LOG(WARNING) << "empty wifi channel of " << bssid_str << " is empty";
        }
        auto bss_bw = wifi_channel.get_bandwidth();

        auto client_bw = wifi_channel.get_bandwidth();
        if (vs_tlv) {
            if (son::wireless_utils::get_station_max_supported_bw(vs_tlv->capabilities(),
                                                                  client_bw)) {
                client_bw = std::min(client_bw, bss_bw);
            }
        }
        database.set_node_wifi_channel(client_mac, wifi_channel);

        // Note: The Database node stats and the Datamodels' stats are not the same.
        // Therefore, client information in data model and in node DB might differ.
        database.clear_node_stats_info(client_mac);
        client->clear_cross_rssi();
        database.dm_clear_sta_stats(tlvf::mac_from_string(client_mac_str));

        if (!(database.get_node_type(client_mac_str) == beerocks::TYPE_IRE_BACKHAUL &&
              database.get_node_handoff_flag(*client))) {
            // The node is not an IRE in handoff
            database.set_node_type(client_mac_str, beerocks::TYPE_CLIENT);
        }

        database.set_node_backhaul_iface_type(client_mac_str,
                                              beerocks::IFACE_TYPE_WIFI_UNSPECIFIED);

        if (vs_tlv) {
            database.set_node_vap_id(client_mac_str, vs_tlv->vap_id());
            database.set_station_capabilities(client_mac_str, vs_tlv->capabilities());
        }

        // Notify existing steering task of completed connection
        // Check if task is running before pushing the event
        if (tasks.is_task_running(client->steering_task_id)) {
            tasks.push_event(client->steering_task_id, client_steering_task::STA_CONNECTED);
        }

        // Notify existing btm request task of completed connection
        // Check if task is running before pushing the event
        if (tasks.is_task_running(client->btm_request_task_id)) {
            tasks.push_event(client->btm_request_task_id, client_steering_task::STA_CONNECTED);
        }
        int dhcp_task = database.get_dhcp_task_id();
        tasks.push_event(dhcp_task, DhcpTask::STA_CONNECTED);

#ifdef FEATURE_PRE_ASSOCIATION_STEERING
        //push event to pre_association_steering_task task
        if (database.get_pre_association_steering_task_id() != -1 && vs_tlv) {
            bwl::sClientAssociationParams new_event = {};

            new_event.mac          = client_mac;
            new_event.bssid        = bssid;
            new_event.vap_id       = vs_tlv->vap_id();
            new_event.capabilities = vs_tlv->capabilities();

            tasks.push_event(
                database.get_pre_association_steering_task_id(),
                pre_association_steering_task::eEvents::STEERING_EVENT_CLIENT_CONNECT_NOTIFICATION,
                &new_event);
        }
#endif /* FEATURE_PRE_ASSOCIATION_STEERING */

        son_actions::handle_completed_connection(database, cmdu_tx, tasks, client_mac_str);

    } else {
        // client disconnected
#ifdef FEATURE_PRE_ASSOCIATION_STEERING
        // Push event to pre_association_steering_task task
        if (database.get_pre_association_steering_task_id() != -1 && vs_tlv) {
            beerocks_message::sSteeringEvDisconnect new_event = {};
            new_event.client_mac                              = client_mac;
            new_event.bssid                                   = bssid;
            new_event.reason                                  = vs_tlv->disconnect_reason();
            new_event.source = beerocks_message::eDisconnectSource(vs_tlv->disconnect_source());
            new_event.type   = beerocks_message::eDisconnectType(vs_tlv->disconnect_type());

            tasks.push_event(database.get_pre_association_steering_task_id(),
                             pre_association_steering_task::eEvents::
                                 STEERING_EVENT_CLIENT_DISCONNECT_NOTIFICATION,
                             &new_event);
        }
#endif /* FEATURE_PRE_ASSOCIATION_STEERING */

        auto client = database.get_station(tlvf::mac_from_string(client_mac_str));
        if (!client) {
            LOG(ERROR) << "Station " << client_mac_str << " not found";
            return false;
        }

        /*
            TODO: Reason code should come from Client Disassociation Stats message in
                    reason Code TLV but since we do not have this data Reason Code
                    set to 1 (UNSPECIFIED_REASON - IEEE802.11-16, Table 9.45).
                    Should be fixed after PPM-864.
            TODO: ReasonCode should be tested after PPM-1905 for nl80211 platforms.
        */
        uint16_t reason_code = (vs_tlv)
                                   ? vs_tlv->disconnect_reason()
                                   : (uint16_t)wfa_map::tlvProfile2ReasonCode::UNSPECIFIED_REASON;
        if (!database.notify_disconnection(client_mac_str, reason_code, bssid_str)) {
            LOG(WARNING) << "Failed to notify disconnection event.";
        }

        // STA only needs to be removed if the BSSID reported in the disconnection event matches
        // the BSSID the station is currently connected to.
        // Otherwise, the station has probably already re-connected to another BSS in the meantime
        // and we should not remove it.
        auto bss = client->get_bss();
        if (!bss) {
            LOG(INFO) << "BSS of the Station is empty mac: " << client->mac;
            return false;
        }
        bool reported_by_parent = bssid == bss->bssid;

        if (reported_by_parent && !database.dm_remove_sta(*client)) {
            LOG(ERROR) << "Failed to remove STA from data model mac:" << client_mac_str;
        }

        // TODO: Validate usages of reported_by_parent flag usages (PPM-1948)
        son_actions::handle_dead_node(client_mac_str, reported_by_parent, database, tasks);
    }

    return true;
}
