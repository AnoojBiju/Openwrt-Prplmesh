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

    // Create a VLAN interface linked to the bridge interface for each Secondary VLAN.
    auto linux_ifaces = network_utils::linux_get_iface_list();

    std::string bridge_vlan_base_str = db->bridge.iface_name + ".";

    std::list<sBridgeVlanInfo> bridge_vlan_interfaces;
    for (const auto &iface : linux_ifaces) {
        auto char_pos = iface.find(bridge_vlan_base_str);
        if (char_pos == std::string::npos) {
            continue;
        }
        bridge_vlan_interfaces.emplace_back(iface);

        // If there is a vlan interface linked to the bridge, bring it down. This is to prevent of
        // residues interface configuration of previous configuration to have effect.
        network_utils::linux_iface_ctrl(iface, false);
    }

    // Clear bridge_vlan_interfaces so we could reuse it
    bridge_vlan_interfaces.clear();

    std::string ipv4_str;
    network_utils::iface_info bridge_iface_info;
    if (network_utils::get_iface_info(bridge_iface_info, db->bridge.iface_name) != 0) {
        LOG(ERROR) << "Failed to get iface info of bridge " << db->bridge.iface_name;
        return;
    }

    sIpv4Addr bridge_ipv4 = network_utils::ipv4_from_string(bridge_iface_info.ip);
    sIpv4Addr subnetmask  = network_utils::ipv4_from_string(bridge_iface_info.netmask);

    // Subnetmask least significant byte.
    // 255.255.255.0 = 2, 255.255.0.0 = 1, 255.0.0.0 = 0
    int8_t subnetmask_lsb = subnetmask.oct[2] ? 2 : subnetmask.oct[1] ? 1 : 0;

    auto bridge_vlan_ipv4 = bridge_ipv4;

    // Increment subnet IP address by one safely.
    auto increment_subnet_ip_safe = [&](sIpv4Addr &br_vlan_ipv4, int8_t &sub_lsb) {
        if (sub_lsb < 0) {
            LOG(ERROR) << "Subnetmask least significant byte is -1!";
            return false;
        }
        br_vlan_ipv4.oct[sub_lsb]++;
        if (br_vlan_ipv4 == bridge_ipv4) {
            sub_lsb--;
            br_vlan_ipv4.oct[sub_lsb]++;
        }
        return true;
    };

    static const std::unordered_map<int8_t, std::string> subnetmasks = {
        {0, "255.0.0.0"}, {1, "255.255.0.0"}, {2, "255.255.255.0"}};

    for (auto secondary_vid : db->traffic_separation.secondaries_vlans_ids) {
        auto vlan_iface_of_bridge =
            network_utils::create_vlan_interface(db->bridge.iface_name, secondary_vid);

        if (vlan_iface_of_bridge.empty()) {
            return;
        }
        // Increment the subnet by one.
        if (!increment_subnet_ip_safe(bridge_vlan_ipv4, subnetmask_lsb)) {
            return;
        }

        auto bridge_vlan_ipv4_str       = network_utils::ipv4_to_string(bridge_vlan_ipv4);
        auto bridge_vlan_subnetmask_str = subnetmasks.at(subnetmask_lsb);

        if (db->device_conf.local_gw) {
            subnetmask = network_utils::ipv4_from_string(bridge_vlan_subnetmask_str);

            // Find subnet
            auto &bridge_vlan_subnet = bridge_vlan_ipv4;
            for (uint8_t i = 0; i < sizeof(sIpv4Addr::oct); i++) {
                bridge_vlan_subnet.oct[i] &= subnetmask.oct[i];
            }

            bridge_vlan_interfaces.emplace_back(vlan_iface_of_bridge, bridge_vlan_subnet,
                                                bridge_vlan_subnetmask_str);
        } else {
            bridge_vlan_interfaces.emplace_back(vlan_iface_of_bridge);
        }

        if (!network_utils::linux_iface_ctrl(vlan_iface_of_bridge, true, bridge_vlan_ipv4_str,
                                             bridge_vlan_subnetmask_str)) {
            LOG(ERROR) << "Bringing interface " << vlan_iface_of_bridge << " up has failed";
            return;
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

bool TrafficSeparation::reconf_dhcp(std::list<sBridgeVlanInfo> &vlans_of_bridge)
{
    constexpr char base_cmd[]            = "/etc/init.d/dnsmasq ";
    constexpr char pid_file_path[]       = "/var/run/dnsmasq/";
    constexpr char pid_file_name[]       = "dnsmasq.cfg01411c.pid";
    constexpr char conf_file_full_path[] = "/var/etc/dnsmasq.conf.cfg01411c";

    // Kill the the running DHCP server (dnsmasq).
    // Doing it with kill function instead of "/etc/init.d/dnsmasq stop" since it would fail to stop
    // dnsmasq which was not brought up by "/etc/init.d/dnsmasq start".
    // If the running dnsmasq has been brought up by prplMesh only kill command can stop it.
    beerocks::os_utils::kill_pid(pid_file_path, pid_file_name);

    std::string cmd;
    // Reserve 100 bytes for appended data to prevent reallocations.
    cmd.reserve(100);

    // When restarting dnsmasq it restore the configuration to default.
    cmd.assign(base_cmd).append("restart");
    auto ret_str = os_utils::system_call(cmd, 2, false);
    if (!ret_str.empty()) {
        LOG(DEBUG) << "Answer: " << ret_str;
    }

    // Stop dnsmasq, since we need to run it manually because it needs to use the configuration
    // file with modifications. If we would run it with "/etc/init.d/dnsmasq start" it will discard
    // any changes we did to the configuration file.
    cmd.assign(base_cmd).append("stop");
    ret_str = os_utils::system_call(cmd, 2, false);
    if (!ret_str.empty()) {
        LOG(DEBUG) << "Answer: " << ret_str;
    }

    // Add interfaces to lease IP addresses on, in the DHCP configuration file.
    std::ofstream outfile;
    outfile.open(conf_file_full_path, std::ios_base::app); // open in append mode
    if (outfile.fail()) {
        LOG(ERROR) << "Failed to open file " << conf_file_full_path << ": " << std::strerror(errno);
        return false;
    }

    for (auto &vlan_info : vlans_of_bridge) {
        // Configuration looks like:
        // dhcp-range=interface:<iface_name>,<min IP>,<max IP>,<subnetmask>,12h
        vlan_info.subnet_ipv4.oct[3] = 100;
        auto min_ip                  = network_utils::ipv4_to_string(vlan_info.subnet_ipv4);
        vlan_info.subnet_ipv4.oct[3] = 200;
        auto max_ip                  = network_utils::ipv4_to_string(vlan_info.subnet_ipv4);
        outfile << "dhcp-range=interface:" << vlan_info.iface_name << "," << min_ip << "," << max_ip
                << "," << vlan_info.subnetmask << ",12h" << std::endl;
    }
    outfile.close();

    // Create cmd string to run manually DHCP server.
    cmd.assign("/usr/sbin/dnsmasq -C ")
        .append(conf_file_full_path)
        .append(" -k -x ")
        .append(pid_file_path)
        .append(pid_file_name);

    // Run DHCP server manually.
    ret_str = os_utils::system_call(cmd, 2, true);
    if (!ret_str.empty()) {
        LOG(DEBUG) << "Answer: " << ret_str;
    }
    return true;
}

void TrafficSeparation::assign_ip_to_vlan_iface(std::list<sBridgeVlanInfo> &vlans_of_bridge)
{
    std::string cmd;
    // Reserve 40 bytes for appended data to prevent reallocations.
    cmd.reserve(40);
    for (auto &vlan_info : vlans_of_bridge) {
        cmd.assign("udhcpc -i ").append(vlan_info.iface_name).append(" -f -S -q -n");
        auto ret_str = os_utils::system_call(cmd, 2, false);
        if (!ret_str.empty()) {
            LOG(DEBUG) << "Answer: " << ret_str;
        }
    }
}
} // namespace net
} // namespace beerocks
