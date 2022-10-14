/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "include/ambiorix_connection.h"
#include <bcl/beerocks_backport.h>

namespace beerocks {
namespace wbapi {

AmbiorixConnection::AmbiorixConnection(const std::string &amxb_backend, const std::string &bus_uri)
{
    int ret = 0;
    // Load the backend .so file
    ret = amxb_be_load(amxb_backend.c_str());
    LOG_IF(ret != 0, ERROR) << "Failed to load the " << amxb_backend.c_str() << " backend";
    // Connect to the bus
    ret = amxb_connect(&m_bus_ctx, bus_uri.c_str());
    LOG_IF(ret != 0, ERROR) << "Failed to connect to the " << bus_uri.c_str() << " bus";
    LOG(INFO) << "New connection to " << bus_uri << " via" << amxb_backend;
}

AmbiorixConnection::~AmbiorixConnection() { amxb_free(&m_bus_ctx); }

amxb_bus_ctx_t *&AmbiorixConnection::get_bus_ctx() { return m_bus_ctx; }

} // namespace wbapi
} // namespace beerocks
