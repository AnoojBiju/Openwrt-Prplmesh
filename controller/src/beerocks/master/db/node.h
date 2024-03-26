/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _NODE_H_
#define _NODE_H_

#include "../tasks/task.h"
#include "interface.h"
#include <bcl/beerocks_wifi_channel.h>
#include <bcl/network/network_utils.h>
#include <tlvf/common/sMacAddr.h>
#include <tlvf/ieee_1905_1/tlvReceiverLinkMetric.h>
#include <tlvf/ieee_1905_1/tlvTransmitterLinkMetric.h>
#include <tlvf/wfa_map/tlvApMetrics.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>

#include <list>
#include <map>
#include <unordered_set>

namespace son {

typedef struct {
    std::string mac;
    std::string ssid;
    bool backhaul_vap;
} sVapElement;

class node {
public:
    node(beerocks::eType type_, const std::string &mac_);

    beerocks::eType get_type();
    bool set_type(beerocks::eType type_);

    const std::string mac;           // client
    std::string parent_mac;          // hostap
    std::string previous_parent_mac; //hostap

    beerocks::WifiChannel wifi_channel;

    std::string ipv4;
    std::string name;
    int hierarchy = -1; //redundant but more efficient
    beerocks::message::sRadioCapabilities *capabilities;

    beerocks::eNodeState state = beerocks::STATE_DISCONNECTED;

    bool supports_6ghz            = true;
    int failed_6ghz_steer_attemps = 0;

    bool supports_5ghz            = true;
    int failed_5ghz_steer_attemps = 0;

    bool supports_24ghz            = true;
    int failed_24ghz_steer_attemps = 0;

    std::chrono::steady_clock::time_point last_state_change;

    int load_balancer_task_id             = -1;
    int dynamic_channel_selection_task_id = -1;
    class radio {
    public:
        std::unordered_map<int8_t, sVapElement> vaps_info;
    };
    std::shared_ptr<radio> hostap = std::make_shared<radio>();

    beerocks::eIfaceType iface_type = beerocks::IFACE_TYPE_ETHERNET;
    std::chrono::steady_clock::time_point last_seen;

    /**
     * @brief Returns active interface mac addresses via loop through interface objects.
     *
     * @return active interface mac's returned as vector of sMacAddr
     */
    std::vector<sMacAddr> get_interfaces_mac();

    /**
     * @brief Get Interface with the given MAC, create it if necessary.
     *
     * @param mac interface MAC address
     * @return shared pointer of Interface Object
     */
    std::shared_ptr<prplmesh::controller::db::Interface> add_interface(const sMacAddr &mac);

    /**
     * @brief Get Interface with the given MAC, if there is one. Else returns nullptr.
     *
     * @param mac interface MAC address
     * @return shared pointer of Interface Object on success, nullptr otherwise.
     */
    std::shared_ptr<prplmesh::controller::db::Interface> get_interface(const sMacAddr &mac);

    /**
     * @brief Remove the Interface with the given MAC Address.
     */
    void remove_interface(const sMacAddr &mac);

    /**
     * @brief Get all Interfaces
     */
    const std::vector<std::shared_ptr<prplmesh::controller::db::Interface>> &get_interfaces()
    {
        return m_interfaces;
    }

    /**
     * @brief Returns unused interface mac addresses
     *
     * @param new_interfaces vector of active interface macs from topology message
     * @return unused interface mac's returned as vector of sMacAddr
     */
    std::vector<sMacAddr> get_unused_interfaces(const std::vector<sMacAddr> &new_interfaces);

    /**
     * @brief Get Neighbor with the given MAC, create it if necessary within Interface.
     *
     * @param interface_mac interface MAC address
     * @param neighbor_mac neighbor MAC address
     * @param flag_ieee1905 is IEEE1905 Flag
     * @return shared pointer of Neighbor Object
     */
    std::shared_ptr<prplmesh::controller::db::Interface::sNeighbor>
    add_neighbor(const sMacAddr &interface_mac, const sMacAddr &neighbor_mac, bool flag_ieee1905);

private:
    beerocks::eType type;

    /**
     * @brief Interfaces configured on this node.
     *
     * The Interface objects are kept alive by this list. Only active interfaces should be on this list.
     *
     */
    std::vector<std::shared_ptr<prplmesh::controller::db::Interface>> m_interfaces;
};
} // namespace son
#endif
