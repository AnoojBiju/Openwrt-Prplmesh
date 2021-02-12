/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <string>
#include <tlvf/common/sMacAddr.h>

// Forward declaration of son::node
namespace son {
class node;
}

namespace prplmesh {
namespace controller {
namespace db {

/** Node that represents a Interface in the controller database. */
class Interface {
public:
    Interface(const sMacAddr &mac, son::node &node) : m_mac(mac), m_node(node) {}

    const sMacAddr m_mac; // interface mac

    // Node on which the Interface exists.
    son::node &m_node;
    std::string dm_path; // data model path
};

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // INTERFACE_H
