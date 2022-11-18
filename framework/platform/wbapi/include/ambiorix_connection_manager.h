/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CONNECTION_MANAGER_H_
#define AMBIORIX_CONNECTION_MANAGER_H_

#include "ambiorix_connection.h"

namespace beerocks {
namespace wbapi {

/**
 * @class AmbiorixConnectionManager: manages shared bus connections
 * in multi-threaded case
 */
class AmbiorixConnectionManager {
public:
    /**
     * @brief: find or create ONE shared ambiorix bus connection per URI.
     */
    static AmbiorixConnectionSmartPtr
    get_connection(const std::string &amxb_backend = {AMBIORIX_WBAPI_BACKEND_PATH},
                   const std::string &bus_uri      = {AMBIORIX_WBAPI_BUS_URI});

    /**
     * @brief: fetch created ambiorix bus connection per file descriptor
     */
    static const AmbiorixConnectionSmartPtr fetch_connection(int fd);

private:
    /**
     * @brief List amx bus connections per URI
     */
    static std::vector<AmbiorixConnectionSmartPtr> connections;

    /**
     * @brief Mutex to protect list of connections in case of multi-threaded clients
     */
    static std::recursive_mutex connections_mutex;
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_CONNECTION_MANAGER_H_ */
