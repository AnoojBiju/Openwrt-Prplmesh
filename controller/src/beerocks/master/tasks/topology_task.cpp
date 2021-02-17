
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
#include "client_steering_task.h"

#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <easylogging++.h>
#include <tlvf/ieee_1905_1/s802_11SpecificInformation.h>
#include <tlvf/ieee_1905_1/tlv1905NeighborDevice.h>
#include <tlvf/ieee_1905_1/tlvDeviceInformation.h>
#include <tlvf/ieee_1905_1/tlvNon1905neighborDeviceList.h>
#include <tlvf/wfa_map/tlvApOperationalBSS.h>
#include <tlvf/wfa_map/tlvClientAssociationEvent.h>

#ifdef BEEROCKS_RDKB
#include "rdkb/rdkb_wlan_task.h"
#endif

using namespace beerocks;
using namespace net;
using namespace son;

topology_task::topology_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_)
    : database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_)
{
}

void topology_task::work() {}

bool topology_task::handle_ieee1905_1_msg(const std::string &src_mac,
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

bool topology_task::handle_topology_response(const std::string &src_mac,
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

    // Get all Agent known fronthaul radios if exist, and compare it to what the Agent reports.
    // If a radio exist on the database but not the tlvDeviceInformation, this radio node needs
    // to be removed.
    // This shall work in the opposite way as well: If it doesn't exist on the database, but
    // reported in the TLV, then we need to add the node to the database. Of course this will remain
    // as "TODO" for future task. Meanwhile parse properly the TLV, leaving the unused parts in
    // comment for future implementation.
    auto fronthaul_radios_on_db = database.get_node_children(
        tlvf::mac_to_string(al_mac), beerocks::TYPE_SLAVE, beerocks::STATE_CONNECTED);

    std::unordered_set<std::string> reported_fronthaul_radios;
    std::vector<sMacAddr> interface_macs{};

    // create topology response update event for bml listeners
    bml_task::topology_response_update_event new_bml_event;
    new_bml_event.al_mac = al_mac;

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

        // For wireless interface it is defined on IEEE 1905.1 that the size of the media info
        // is n=10 octets, which the size of s802_11SpecificInformation struct.
        // For wired interface n=0.
        if ((ieee1905_1::eMediaTypeGroup::IEEE_802_11 == media_type_group) &&
            (iface_info.media_info_length() == 10)) {

            const auto media_info = reinterpret_cast<ieee1905_1::s802_11SpecificInformation *>(
                iface_info.media_info(0));
            const auto iface_role = media_info->role;

            // For future implementation
            // const auto &iface_bssid = media_info->network_membership;
            // const auto iface_bw     = media_info->ap_channel_bandwidth;
            // const auto iface_cf1    = media_info->ap_channel_center_frequency_index1;
            // const auto iface_cf2    = media_info->ap_channel_center_frequency_index2;

            if (iface_role == ieee1905_1::eRole::AP) {
                reported_fronthaul_radios.insert(iface_mac_str);
            }

            // update bml event with the new radio interface
            new_bml_event.radio_interfaces.push_back(iface_info);

            LOG(DEBUG) << "New radio interface is reported, mac=" << iface_mac
                       << ", AP=" << (iface_role == ieee1905_1::eRole::AP);

            // TODO: Add/Update the node on the database
        }
    }

    // Update active mac list of the device node
    database.dm_update_interface_elements(al_mac, interface_macs);

    tasks.push_event(database.get_bml_task_id(), bml_task::TOPOLOGY_RESPONSE_UPDATE,
                     &new_bml_event);

    // If the database has radio mac that is not reported, remove its node from the db.
    for (const auto &fronthaul_radio_on_db : fronthaul_radios_on_db) {
        if (reported_fronthaul_radios.find(fronthaul_radio_on_db) ==
            reported_fronthaul_radios.end()) {
            LOG(DEBUG) << "radio " << fronthaul_radio_on_db
                       << " is not reported on Device Information TLV, removing the radio node";
            son_actions::handle_dead_node(fronthaul_radio_on_db, true, database, cmdu_tx, tasks);
        }
    }

    auto tlvApInformation = cmdu_rx.getClass<wfa_map::tlvApOperationalBSS>();
    if (tlvApInformation) {
        for (uint8_t i = 0; i < tlvApInformation->radio_list_length(); i++) {
            auto radio_entry = std::get<1>(tlvApInformation->radio_list(i));
            LOG(DEBUG) << "Operational BSS radio " << radio_entry.radio_uid();
            if (fronthaul_radios_on_db.find(tlvf::mac_to_string(radio_entry.radio_uid())) ==
                fronthaul_radios_on_db.end()) {
                LOG(WARNING) << "OperationalBSS on unknown radio " << radio_entry.radio_uid();
                continue;
            }
            // Update BSSes in the sAgent
            auto radio =
                database.get_radio(tlvf::mac_from_string(src_mac), radio_entry.radio_uid());
            if (!radio) {
                LOG(WARNING) << "OperationalBSS on unknown radio  " << radio_entry.radio_uid()
                             << " on " << src_mac;
                continue;
            }

            radio->bsses.keep_new_prepare();

            for (uint8_t j = 0; j < radio_entry.radio_bss_list_length(); j++) {
                auto bss_entry = std::get<1>(radio_entry.radio_bss_list(j));
                LOG(DEBUG) << "Operational BSS " << bss_entry.radio_bssid();

                // TODO "backhaul" is not set in this TLV, so just assume false
                if (!database.update_vap(radio_entry.radio_uid(), bss_entry.radio_bssid(),
                                         bss_entry.ssid_str(), false)) {
                    LOG(ERROR) << "Failed to update VAP for radio " << radio_entry.radio_uid()
                               << " BSS " << bss_entry.radio_bssid() << " SSID "
                               << bss_entry.ssid_str();
                }
                auto bss  = radio->bsses.add(bss_entry.radio_bssid());
                bss->ssid = bss_entry.ssid_str();
                // backhaul is not reported in this message. Leave it unchanged.
            }

            auto removed = radio->bsses.keep_new_remove_old();
            for (const auto &bss : removed) {
                database.remove_vap(tlvf::mac_to_string(radio->radio_uid), bss->vap_id);
                son_actions::handle_dead_node(tlvf::mac_to_string(bss->bssid), true, database,
                                              cmdu_tx, tasks);
            }
        }
    }

    // Clear neighbor informations of all interfaces.
    for (const auto &iface : interface_macs) {
        database.dm_remove_interface_neighbors(al_mac, iface);
    }

    // The reported neighbors list might not be correct since the reporting al_mac hasn't received
    // a Topology Discovery from its neighbors yet. Therefore, remove a neighbor node only if more
    // than 65 seconds (timeout according to standard + 5 seconds grace) have passed since we added
    // this node. This promise that the reported al_mac will get the Topology Discovery messages
    // from its neighbors and add them to the report.
    bool check_dead_neighbors =
        (database.get_last_state_change(src_mac) +
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

            // Add neighbor to related interface
            database.dm_add_interface_neighbor(al_mac, tlv1905NeighborDevice->mac_local_iface(),
                                               std::get<1>(neighbor_al_mac_tuple).mac, true);

            auto &neighbor_al_mac = std::get<1>(neighbor_al_mac_tuple).mac;
            LOG(DEBUG) << "Inserting reported neighbor " << neighbor_al_mac << " to the list";
            reported_neighbor_al_macs.insert(neighbor_al_mac);
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

            // Add neighbor to related interface
            database.dm_add_interface_neighbor(al_mac, tlvNon1905NeighborDevice->mac_local_iface(),
                                               std::get<1>(neighbor_al_mac_tuple), false);
        }
    }

    if (check_dead_neighbors) {
        handle_dead_neighbors(src_mac, al_mac, reported_neighbor_al_macs);
    }
    return true;
}

void topology_task::handle_dead_neighbors(const std::string &src_mac, const sMacAddr &al_mac,
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
        son_actions::handle_dead_node(backhhaul_mac, true, database, cmdu_tx, tasks);
    }
}

bool topology_task::handle_topology_notification(const std::string &src_mac,
                                                 ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // TODO: Move handling of Topology Notification here
    return true;
}
