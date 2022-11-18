/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <easylogging++.h>

#include "include/ambiorix_connection_manager.h"

#include <algorithm>

namespace beerocks {
namespace wbapi {

std::recursive_mutex AmbiorixConnectionManager::connections_mutex;
std::vector<AmbiorixConnectionSmartPtr> AmbiorixConnectionManager::connections = {};

AmbiorixConnectionSmartPtr
AmbiorixConnectionManager::get_connection(const std::string &amxb_backend,
                                          const std::string &bus_uri)
{
    const std::lock_guard<std::recursive_mutex> lock(connections_mutex);
    auto it =
        std::find_if(connections.begin(), connections.end(),
                     [&](const AmbiorixConnectionSmartPtr &cnx) { return cnx->uri() == bus_uri; });
    if (it != connections.end()) {
        LOG(INFO) << "Share connection to " << bus_uri << " via" << amxb_backend;
        return *it;
    }
    auto cnx = AmbiorixConnection::create(amxb_backend, bus_uri);
    if (!cnx) {
        LOG(ERROR) << "Fail to create shared connection to " << bus_uri << " via" << amxb_backend;
        return cnx;
    }
    LOG(INFO) << "New connection to " << bus_uri << " via" << amxb_backend;
    it = connections.insert(connections.end(), std::move(cnx));
    return *it;
}

const AmbiorixConnectionSmartPtr AmbiorixConnectionManager::fetch_connection(int fd)
{
    const std::lock_guard<std::recursive_mutex> lock(connections_mutex);
    auto it = std::find_if(connections.begin(), connections.end(),
                           [&](const AmbiorixConnectionSmartPtr &cnx) {
                               return (cnx->get_fd() == fd || cnx->get_signal_fd() == fd);
                           });
    if (it != connections.end()) {
        return *it;
    }
    return AmbiorixConnectionSmartPtr{};
}

} // namespace wbapi
} // namespace beerocks
