/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef UNASSOCIATED_STATION_H
#define UNASSOCIATED_STATION_H

#include "agent.h"
#include <bcl/beerocks_defines.h>
#include <bcl/network/network_utils.h>

namespace prplmesh {
namespace controller {
namespace db {

// TODO : discuss if we better use the main Station class and append it ?? o splitting them into a base Station
// class and two children: associated/nonAssociated
// For this first version, I will use this new light class
class UnassociatedStation {
public:
    UnassociatedStation()                            = delete;
    UnassociatedStation(const UnassociatedStation &) = delete;
    explicit UnassociatedStation(const sMacAddr &al_mac_) : m_mac_address(al_mac_) {}

    struct Stats {
        uint8_t uplink_rcpi_dbm_enc = 0;
        std::string time_stamp;
    };

    void update_stats(Stats &new_stats) { m_stats = new_stats; };
    const Stats get_stats() const { return m_stats; };
    void set_channel(uint channel_in) { m_channel = channel_in; };
    const sMacAddr &get_mac_Address() const { return m_mac_address; };
    uint get_channel() const { return m_channel; };

private:
    sMacAddr m_mac_address;
    uint m_channel = 0;
    std::vector<std::shared_ptr<prplmesh::controller::db::Agent>>
        agents; //TODO: maybe we better send the monitoring request to a specific agents rather than all of them?

    Stats m_stats;
};
} // namespace db
} // namespace controller
} // namespace prplmesh
#endif
