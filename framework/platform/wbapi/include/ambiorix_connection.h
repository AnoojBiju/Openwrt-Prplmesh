/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CONNECTION_H_
#define AMBIORIX_CONNECTION_H_

// prplmesh
#include <easylogging++.h>

// Ambiorix

#include <amxc/amxc.h>

#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

namespace beerocks {
namespace wbapi {

/**
 * @class AmbiorixConnection
 */
class AmbiorixConnection {
public:
    /**
     * @brief connect to an ambiorix backend: load backend, connect to the bus
     *
     * @param[in] amxb_backend: path to the ambiorix backend (ex: "/usr/bin/mods/amxb/mod-amxb-ubus.so").
     * @param[in] bus_uri: path to the bus in uri form (ex: "ubus:/var/run/ubus.sock").
     *
    */
    explicit AmbiorixConnection(const std::string &amxb_backend, const std::string &bus_uri);

    virtual ~AmbiorixConnection();

    amxb_bus_ctx_t *&get_bus_ctx();

private:
    amxb_bus_ctx_t *m_bus_ctx = nullptr;
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_CONNECTION_H_ */
