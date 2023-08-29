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

AmbiorixConnectionSmartPtr
AmbiorixConnectionManager::get_connection(const std::string &amxb_backend, const std::string &uri)
{
    std::string new_backend(amxb_backend);
    std::string new_uri(uri);

    // For any failure, we fall back on the main bus connection
    auto fall_back_to_wbap = [&]() {
        LOG(WARNING) << " Falling back to : " << AMBIORIX_WBAPI_BACKEND_PATH
                     << " and uri: " << AMBIORIX_WBAPI_BUS_URI;
        new_backend = AMBIORIX_WBAPI_BACKEND_PATH;
        new_uri     = AMBIORIX_WBAPI_BUS_URI;
    };
    struct stat sb;

    if (amxb_backend != AMBIORIX_WBAPI_BACKEND_PATH) {
        if (stat(amxb_backend.c_str(), &sb) != 0) {
            LOG(WARNING) << "Ambiorix backend " << amxb_backend << " does not exist!";
            fall_back_to_wbap();
        }
    }
    if (new_uri != AMBIORIX_WBAPI_BUS_URI) {
        std::string tempo_uri(new_uri);
        auto position = tempo_uri.find(":");
        if (position != std::string::npos) {
            tempo_uri = new_uri.substr(position + 1);
        } else {
            LOG(WARNING) << "Ambiorix uri " << new_uri << "is missing ':' ";
            fall_back_to_wbap();
        }

        if (stat(tempo_uri.c_str(), &sb) != 0) {
            LOG(WARNING) << "Ambiorix uri " << new_uri << " does not exist!";
            fall_back_to_wbap();
        }
    }
    const std::lock_guard<std::recursive_mutex> lock(m_connections_mutex);

    auto it =
        std::find_if(m_connections.begin(), m_connections.end(),
                     [&](const AmbiorixConnectionSmartPtr &cnx) { return cnx->uri() == new_uri; });
    if (it != m_connections.end()) {
        LOG(DEBUG) << "Shared connection to " << new_uri << " via" << amxb_backend;
        return *it;
    } else {
        LOG(ERROR) << "no connection found";
    }
    return create(new_backend, new_uri);
}

AmbiorixConnectionSmartPtr AmbiorixConnectionManager::create(const std::string &amxb_backend,
                                                             const std::string &bus_uri)
{
    auto cnx = std::make_shared<AmbiorixConnection>(amxb_backend, bus_uri);
    if (!cnx || !cnx->init()) {
        LOG(FATAL) << "Failed to create new connection to " << bus_uri << " via" << amxb_backend;
        return AmbiorixConnectionSmartPtr{};
    } else {
        LOG(ERROR) << "created new connection to " << bus_uri;
    }
    auto it = m_connections.insert(m_connections.end(), std::move(cnx));
    return *it;
}

const AmbiorixConnectionSmartPtr AmbiorixConnectionManager::fetch_connection(int fd)
{
    const std::lock_guard<std::recursive_mutex> lock(m_connections_mutex);
    auto it = std::find_if(m_connections.begin(), m_connections.end(),
                           [&](const AmbiorixConnectionSmartPtr &cnx) {
                               return (cnx->get_fd() == fd || cnx->get_signal_fd() == fd);
                           });
    if (it != m_connections.end()) {
        return *it;
    }
    return AmbiorixConnectionSmartPtr{};
}

} // namespace wbapi
} // namespace beerocks
