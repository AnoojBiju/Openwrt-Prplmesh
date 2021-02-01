/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BSS_H
#define BSS_H

#include <string>
#include <tlvf/common/sMacAddr.h>

// Forward declaration of son::node
namespace son {
class node;
}

namespace prplmesh {
namespace controller {
namespace db {

/** Node that represents a BSS (VAP) in the controller database. */
class bss {
public:
    bss(const sMacAddr &bssid, son::node &radio) : m_bssid(bssid), m_radio(radio) {}

    /** BSSID of the BSS. */
    const sMacAddr m_bssid;

    /** Radio on which the BSS exists. */
    son::node &m_radio;

    /** SSID of the BSS - empty if unconfigured. */
    std::string m_ssid;
};

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // CLIENT_H
