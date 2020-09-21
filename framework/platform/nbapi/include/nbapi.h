/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef NBAPI_H
#define NBAPI_H

// prplmesh
#include <bcl/beerocks_event_loop.h>
#include <easylogging++.h>
#include <mapf/common/utils.h>

// Ambiorix
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxc/amxc.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

#include <amxo/amxo.h>
#include <amxo/amxo_save.h>

namespace beerocks {
namespace nbapi {

/**
 * @class Ambiorix
 * @brief This class manages the ambiorix instance.
 */
class Ambiorix {

public:
    explicit Ambiorix(std::shared_ptr<EventLoop> event_loop);

    /**
     * @brief Ambiorix destructor removes: bus connection, data model, parser and all data
     *        from the backend (UBus, PCB, etc.).
     */
    virtual ~Ambiorix();

    /**
     * @brief Initialize the ambiorix library: load backend, connect to the bus, load data model,
     *        register data model in the bus.
     *
     * @param amxb_backend Path to the ambiorix backend (ex: "/usr/bin/mods/amxb/mod-amxb-ubus.so").
     * @param bus_uri Path to the bus in uri form (ex: "ubus:/var/run/ubus.sock").
     * @param datamodel_path Path to the data model definition ODL file.
     * @return True on success and false otherwise.
     */
    bool init(const std::string &amxb_backend, const std::string &bus_uri,
              const std::string &datamodel_path);

private:
    // Methods

    /**
     * @brief Load and parse data model from the ODL file.
     *
     * @param datamodel_path Path to the data model definition ODL file.
     * @return True on success and false otherwise.
     */
    bool load_datamodel(const std::string &datamodel_path);

    /**
     * @brief Initialize event handlers for Ambiorix fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool init_event_loop();

    /**
     * @brief Initialize event handlers for the ambiorix signals fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool init_signal_loop();

    /**
     * @brief Remove event handlers for Ambiorix fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool remove_event_loop();

    /**
     * @brief Remove event handlers for the ambiorix signals fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool remove_signal_loop();

    /**
     * @brief Find object by relative path.
     *
     * @param relative_path Path to the object in datamodel (ex: "Controller.Network.ID").
     * @return Pointer on the object on success and nullptr otherwise.
     */
    amxd_object_t *find_object(const std::string &relative_path);

    // Variables
    amxb_bus_ctx_t *m_bus_ctx = nullptr;
    amxd_dm_t m_datamodel;
    amxo_parser_t m_parser;
    std::shared_ptr<EventLoop> m_event_loop;
};

} // namespace nbapi
} // namespace beerocks
#endif // NBAPI_H
