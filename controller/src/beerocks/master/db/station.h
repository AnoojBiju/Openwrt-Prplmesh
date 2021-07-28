/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef STATION_H
#define STATION_H

#include <bcl/beerocks_defines.h>
#include <bcl/network/network_utils.h>
#include <chrono>
#include <string>
#include <tlvf/common/sMacAddr.h>

#include "node.h"

namespace prplmesh {
namespace controller {
namespace db {

/**
 * @brief Station struct.
 *
 * Struct representing a station. It can be a client or a backhaul station.
 */
class Station {
public:
    Station()                = delete;
    Station(const Station &) = delete;
    explicit Station(const sMacAddr &mac_) : mac(mac_) {}

    const sMacAddr mac;

    std::string ipv6;

    int association_handling_task_id = -1;
    int steering_task_id             = -1;
    int roaming_task_id              = -1;

    bool confined = false;

    uint16_t cross_rx_phy_rate_100kb   = 0;
    uint16_t cross_tx_phy_rate_100kb   = 0;
    double cross_estimated_rx_phy_rate = 0.0;
    double cross_estimated_tx_phy_rate = 0.0;

    /*
     * Persistent configurations - start
     * Client persistent configuration aging is refreshed on persistent configurations set
     * persistent configuration of aged clients removed from the persistent-db and cleared in the runtime-db
     */

    // Indicates when client parameters were last updated (even if not updated yet to persistent-db)
    // minimal value is used as invalid value.
    std::chrono::system_clock::time_point parameters_last_edit =
        std::chrono::system_clock::time_point::min();

    // Optional - if configured the client has its own configured timelife delay.
    std::chrono::minutes time_life_delay_minutes =
        std::chrono::minutes(beerocks::PARAMETER_NOT_CONFIGURED);

    sMacAddr initial_radio = beerocks::net::network_utils::ZERO_MAC;

    // If enabled, the client will be steered to the initial radio it connected to - save at initial_radio.
    son::eTriStateBool stay_on_initial_radio = son::eTriStateBool::NOT_CONFIGURED;

    // The selected bands that the client should be steered to.
    // Default value is PARAMETER_NOT_CONFIGURED - which means no limitation on bands.
    // Possible values are bitwise options of eClientSelectedBands.
    int8_t selected_bands = beerocks::PARAMETER_NOT_CONFIGURED;

    // The unfriendly status indicates how we interact with the client.
    // If the unfriendly status is not configured, the client is assumed friendly unless proven otherwise.
    // The friendliness status affects how we handle the aging mechanism.
    son::eTriStateBool is_unfriendly = son::eTriStateBool::NOT_CONFIGURED;

    /*
     * Persistent configurations - end
     */
};

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // STATION_H
