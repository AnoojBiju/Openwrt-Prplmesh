/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef STATION_H
#define STATION_H

#include <tlvf/common/sMacAddr.h>

namespace prplmesh {
namespace controller {
namespace db {

/**
 * @brief Station struct.
 *
 * Struct representing a station. It can be a client or a backhaul station.
 */
struct sStation {
public:
    sStation()                 = delete;
    sStation(const sStation &) = delete;
    explicit sStation(const sMacAddr &mac_) : mac(mac_) {}

    const sMacAddr mac;
};

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // STATION_H
