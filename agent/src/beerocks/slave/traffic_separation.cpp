/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

#include "traffic_separation.h"

namespace beerocks {
namespace net {

void TrafficSeparation::apply_traffic_separation(const std::string &radio_iface)
{
    // Since the following call is locking the database, thread safety is promised on this function.
    auto db = AgentDB::get();

    network_utils::set_vlan_filtering(db->bridge.iface_name,
                                      db->traffic_separation.primary_vlan_id);

    // If the primary VID has changed to zero, vlan filtering is disabled, so there is no point
    // modifying the VLAN policy on the platform interfaces.
    if (db->traffic_separation.primary_vlan_id == 0) {
        return;
    }

    // The Bridge, the WAN ports and the LAN ports should all have "Tagged Port" policy.
    // Update the Bridge Policy
    bool is_bridge = true;
    set_vlan_policy(db->bridge.iface_name, TAGGED_PORT_PRIMARY_UNTAGGED, is_bridge);

    // Since we already set the bridge, and there are no more bridge interfaces, the 'bridge_iface'
    // is set to 'false' from now on.
    is_bridge = false;

    // Update WAN and LAN Ports.
    if (!db->device_conf.local_gw) {
        set_vlan_policy(db->ethernet.wan.iface_name, TAGGED_PORT_PRIMARY_UNTAGGED, is_bridge);
    }
    for (const auto &lan_iface_info : db->ethernet.lan) {
        set_vlan_policy(lan_iface_info.iface_name, TAGGED_PORT_PRIMARY_UNTAGGED, is_bridge);
    }

    // Wireless Backhaul
    if (!db->device_conf.local_gw && !db->backhaul.selected_iface_name.empty() &&
        db->backhaul.connection_type == AgentDB::sBackhaul::eConnectionType::Wireless) {

        auto radio = db->radio(db->backhaul.selected_iface_name);
        if (!radio) {
            LOG(ERROR) << "Could not find Backhaul Radio interface!";
            return;
        }
        if (db->backhaul.bssid_multi_ap_profile > 1) {
            set_vlan_policy(radio->back.iface_name, TAGGED_PORT_PRIMARY_TAGGED, is_bridge);
        } else {
            set_vlan_policy(radio->back.iface_name, UNTAGGED_PORT, is_bridge);
        }
    }

    // If radio interface has not been given, then stop configuring the VLAN policy after finished
    // to configure the bridge, ethernet ports and wireless backhaul interface.
    // This should happen whenever the backhaul connects, and we need to update the Primary VLAN
    // of the platform so we would be able to get messages from the Controller.
    if (radio_iface.empty()) {
        return;
    }

    // Update Policy given Radio interface.
    auto radio = db->radio(radio_iface);
    if (!radio) {
        return;
    }

    for (const auto &bss : radio->front.bssids) {

        // Skip unconfigured BSS.
        if (bss.ssid.empty()) {
            continue;
        }

        LOG(DEBUG) << "BSS " << bss.mac << ", ssid:" << bss.ssid << ", fBSS: " << bss.fronthaul_bss
                   << ", bBSS: " << bss.backhual_bss
                   << ", p1_dis: " << bss.backhaul_bss_disallow_profile1_agent_association
                   << ", p2_dis: " << bss.backhaul_bss_disallow_profile2_agent_association;

        std::string bss_iface;

        if (!network_utils::linux_iface_get_name(bss.mac, bss_iface)) {
            LOG(INFO) << "Interface with MAC " << bss.mac << " does not exist";
            continue;
        }

        // fBSS
        if (bss.fronthaul_bss && !bss.backhual_bss) {
            auto ssid_vlan_pair_iter = db->traffic_separation.ssid_vid_mapping.find(bss.ssid);
            if (ssid_vlan_pair_iter == db->traffic_separation.ssid_vid_mapping.end()) {
                LOG(ERROR) << "SSID not found on SSID VID map";
                return;
            }
            auto vid_to_set = ssid_vlan_pair_iter->second;
            set_vlan_policy(bss_iface, UNTAGGED_PORT, is_bridge, vid_to_set);
        }
        // bBSS
        else if (!bss.fronthaul_bss && bss.backhual_bss) {
            if (bss.backhaul_bss_disallow_profile1_agent_association ==
                bss.backhaul_bss_disallow_profile2_agent_association) {
                LOG(WARNING) << "bBSS invalid configuration - "
                             << "backhaul_bss_disallow_profile1_agent_association = "
                                "backhaul_bss_disallow_profile2_agent_association = "
                             << bss.backhaul_bss_disallow_profile1_agent_association;
                return;
            }
            auto bss_extended_ifaces =
                network_utils::get_extended_bss_ifaces(bss_iface, db->bridge.iface_name);

            for (const auto &bss_extended_iface : bss_extended_ifaces) {
                // Profile-2 Backhaul BSS
                if (bss.backhaul_bss_disallow_profile1_agent_association) {
                    set_vlan_policy(bss_extended_iface, TAGGED_PORT_PRIMARY_UNTAGGED, is_bridge);
                }
                // Profile-1 Backhual BSS
                else {
                    set_vlan_policy(bss_extended_iface, UNTAGGED_PORT, is_bridge,
                                    db->traffic_separation.primary_vlan_id);
                }
            }
        }
        // Combined fBSS & bBSS - Currently Support only Profile-1
        else {
            if (!bss.backhaul_bss_disallow_profile2_agent_association) {
                LOG(WARNING) << "bBSS invalid configuration! "
                             << "Combined BSS not supported with Profile-2 bBSS - Skip";
                continue;
            }
            if (bss.backhaul_bss_disallow_profile1_agent_association) {
                LOG(ERROR) << "bBSS invalid configuration! "
                           << "Profile-1 and Profile-2 Backhaul connection are both disallowed - "
                              "Skip";
                return;
            }

            set_vlan_policy(bss_iface, UNTAGGED_PORT, is_bridge,
                            db->traffic_separation.primary_vlan_id);

            auto bss_extended_ifaces =
                network_utils::get_extended_bss_ifaces(bss_iface, db->bridge.iface_name);

            for (const auto &bss_extended_iface : bss_extended_ifaces) {
                set_vlan_policy(bss_extended_iface, UNTAGGED_PORT, is_bridge,
                                db->traffic_separation.primary_vlan_id);
            }
        }
    }
}

void TrafficSeparation::set_vlan_policy(const std::string &iface, ePortMode port_mode,
                                        bool is_bridge, uint16_t untagged_port_vid)
{
    if (iface.empty()) {
        LOG(ERROR) << "iface is empty!";
        return;
    }

    // Helper variables to make the code more readable.
    bool del = true; // First, remove all VIDs (vid=0).
    bool pvid;
    bool untagged;

    network_utils::set_iface_vid_policy(iface, del, 0, is_bridge);

    del = false;

    if (port_mode == TAGGED_PORT_PRIMARY_UNTAGGED || port_mode == TAGGED_PORT_PRIMARY_TAGGED) {
        if (port_mode == TAGGED_PORT_PRIMARY_UNTAGGED) {
            // Set the new Primary VLAN with "PVID" and "Egress Untagged" policy.
            pvid     = true;
            untagged = true;
        } else {
            // Set the new Primary VLAN as Not "PVID" and Not "Egress Untagged" policy.
            pvid     = false;
            untagged = false;
        }
        auto db = AgentDB::get();
        network_utils::set_iface_vid_policy(iface, del, db->traffic_separation.primary_vlan_id,
                                            is_bridge, pvid, untagged);

        // Add secondary VIDs.
        pvid     = false;
        untagged = false;
        for (const auto sec_vid : db->traffic_separation.secondaries_vlans_ids) {
            network_utils::set_iface_vid_policy(iface, del, sec_vid, is_bridge, pvid, untagged);
        }
    }
    // port_mode == UNTAGGED_PORT
    else {
        if (!untagged_port_vid) {
            LOG(ERROR) << "Untagged Port VID was not set";
            return;
        }
        // Set the new Primary VLAN with "PVID" and "Egress Untagged" policy.
        pvid      = true;
        untagged  = true;
        is_bridge = false; // Untagged Port cannot be a bridge interface.
        network_utils::set_iface_vid_policy(iface, del, untagged_port_vid, is_bridge, pvid,
                                            untagged);
    }
}

} // namespace net
} // namespace beerocks
