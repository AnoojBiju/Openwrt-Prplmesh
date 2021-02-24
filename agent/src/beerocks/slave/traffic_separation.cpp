/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

#include "agent_db.h"
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

        // Double tagged packets with S-Tag must be filtered on tagged ports.
        if (!is_bridge) {
            network_utils::set_vlan_packet_filter(true, iface);
        }
    }
    // port_mode == UNTAGGED_PORT
    else {
        if (!untagged_port_vid) {
            LOG(ERROR) << "Untagged Port VID was not set on port_mode of UNTAGGED_PORT";
            return;
        }
        // Set the new Primary VLAN with "PVID" and "Egress Untagged" policy.
        pvid      = true;
        untagged  = true;
        is_bridge = false; // Untagged Port cannot be a bridge interface.
        network_utils::set_iface_vid_policy(iface, del, untagged_port_vid, is_bridge, pvid,
                                            untagged);

        // Filter packets containing the VID of the Untagged Port.
        network_utils::set_vlan_packet_filter(true, iface, untagged_port_vid);
    }
}

} // namespace net
} // namespace beerocks
