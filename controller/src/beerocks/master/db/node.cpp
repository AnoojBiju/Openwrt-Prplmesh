/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "node.h"

#include <easylogging++.h>

using namespace beerocks;
using namespace son;

node::node(beerocks::eType type_, const std::string &mac_) : mac(mac_) // default value
{
    type = type_;
}

beerocks::eType node::get_type() { return type; }

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
