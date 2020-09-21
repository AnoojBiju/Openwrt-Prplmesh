/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include "nbapi.h"

namespace beerocks {
namespace nbapi {

Ambiorix::Ambiorix(std::shared_ptr<EventLoop> event_loop) : m_event_loop(event_loop)
{
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";
    amxo_parser_init(&m_parser);
    amxd_dm_init(&m_datamodel);
}

bool Ambiorix::init(const std::string &amxb_backend, const std::string &bus_uri,
                    const std::string &datamodel_path)
{
    LOG(DEBUG) << "Initializing the bus connection.";
    int status = 0;

    status = amxb_be_load(amxb_backend.c_str());
    if (status != 0) {
        LOG(ERROR) << "Failed to load backend, status: " << status;
        return false;
    }

    // Connect to the bus
    status = amxb_connect(&m_bus_ctx, bus_uri.c_str());
    if (status != 0) {
        LOG(ERROR) << "Failed to connect to the bus, status: " << status;
        return false;
    }

    if (!load_datamodel(datamodel_path)) {
        LOG(ERROR) << "Failed to load data model.";
        return false;
    }

    status = amxb_register(m_bus_ctx, &m_datamodel);
    if (status != 0) {
        LOG(ERROR) << "Failed to register the data model.";
        return false;
    }

    if (!init_event_loop()) {
        LOG(ERROR) << "Failed to initialize event loop.";
        return false;
    }

    if (!init_signal_loop()) {
        LOG(ERROR) << "Failed to initialize event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "The bus connection initialized successfully.";
    return true;
}

bool Ambiorix::load_datamodel(const std::string &datamodel_path)
{
    LOG(DEBUG) << "Loading the data model.";
    auto *root_obj = amxd_dm_get_root(&m_datamodel);
    if (!root_obj) {
        LOG(ERROR) << "Failed to get datamodel root object.";
        return false;
    }

    // Disable eventing while loading odls
    amxp_sigmngr_enable(&m_datamodel.sigmngr, false);

    amxo_parser_parse_file(&m_parser, datamodel_path.c_str(), root_obj);

    amxp_sigmngr_enable(&m_datamodel.sigmngr, true);

    LOG(DEBUG) << "The data model loaded successfully.";
    return true;
}

bool Ambiorix::init_event_loop()
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix fd in the event loop.";

    auto ambiorix_fd = amxb_get_fd(m_bus_ctx);
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .on_read =
            [&](int fd, EventLoop &loop) {
                amxb_read(m_bus_ctx);
                return true;
            },

        // Not implemented
        .on_write      = nullptr,
        .on_disconnect = nullptr,

        // Handle interface errors
        .on_error =
            [&](int fd, EventLoop &loop) {
                LOG(ERROR) << "Error on ambiorix fd.";
                return true;
            },
    };

    if (!m_event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix fd in the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool Ambiorix::init_signal_loop()
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix signals fd in the event loop.";

    auto ambiorix_fd = amxp_signal_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .on_read =
            [&](int fd, EventLoop &loop) {
                amxp_signal_read();
                return true;
            },
        // Not implemented
        .on_write      = nullptr,
        .on_disconnect = nullptr,

        // Handle interface errors
        .on_error =
            [&](int fd, EventLoop &loop) {
                LOG(ERROR) << "Error on ambiorix fd.";
                return true;
            },
    };

    if (!m_event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix signals fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool Ambiorix::remove_event_loop()
{
    LOG(DEBUG) << "Remove event handlers for Ambiorix fd from the event loop.";

    auto ambiorix_fd = amxb_get_fd(m_bus_ctx);
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    if (!m_event_loop->remove_handlers(ambiorix_fd)) {
        LOG(ERROR) << "Couldn't remove event handlers for the Ambiorix fd from the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd successfully removed from the event loop.";

    return true;
}

bool Ambiorix::remove_signal_loop()
{
    LOG(DEBUG) << "Remove event handlers for the Ambiorix signals fd from the event loop.";

    auto ambiorix_fd = amxp_signal_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    if (!m_event_loop->remove_handlers(ambiorix_fd)) {
        LOG(ERROR) << "Couldn't remove event handlers for the Ambiorix signals fd from the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "The event handlers for the Ambiorix signals fd removed successfully from the "
                  "event loop.";

    return true;
}

amxd_object_t *Ambiorix::find_object(const std::string &relative_path)
{

    auto object = amxd_dm_findf(&m_datamodel, "%s", relative_path.c_str());
    if (!object) {
        LOG(ERROR) << "Failed to get object from data model.";
        return nullptr;
    }

    return object;
}

Ambiorix::~Ambiorix()
{
    remove_event_loop();
    remove_signal_loop();
    amxb_free(&m_bus_ctx);
    amxd_dm_clean(&m_datamodel);
    amxo_parser_clean(&m_parser);
    amxb_be_remove_all();
}
} // namespace nbapi
} // namespace beerocks
