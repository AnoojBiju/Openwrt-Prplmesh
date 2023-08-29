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
     * @brief: get single instance
     */
    static AmbiorixConnectionManager *get_instance()
    {
        static AmbiorixConnectionManager instance{};
        return &instance;
    }

    AmbiorixConnectionManager(const AmbiorixConnectionManager &obj) = delete;
    AmbiorixConnectionManager &operator=(AmbiorixConnectionManager const &) = delete;
    ~AmbiorixConnectionManager() {}
    /**
     * @brief: get a connection to the uri
     * @return new connection if no connection has already been created using the passed uri
     * @return existing connection  if a connection to the uri has been previously created
     */
    AmbiorixConnectionSmartPtr
    get_connection(const std::string &amxb_backend = {AMBIORIX_WBAPI_BACKEND_PATH},
                   const std::string &bus_uri      = {AMBIORIX_WBAPI_BUS_URI});

    /**
     * @brief: fetch created ambiorix bus connection per file descriptor
     */
    const AmbiorixConnectionSmartPtr fetch_connection(int fd);

private:
    explicit AmbiorixConnectionManager(){};

    /**
     * @brief: create  a  new connection to the uri bus_uri
     */
    AmbiorixConnectionSmartPtr create(const std::string &amxb_backend, const std::string &bus_uri);

    /**
     * @brief List amx bus connections per URI
     */
    std::vector<AmbiorixConnectionSmartPtr> m_connections;

    std::recursive_mutex m_connections_mutex;
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_CONNECTION_MANAGER_H_ */
