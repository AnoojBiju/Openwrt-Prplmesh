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
    LOG(DEBUG) << "Initializing the event loop.";

    auto ambiorix_fd = amxb_get_fd(m_bus_ctx);
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        // Accept incoming connections
        .on_read =
            [&](int fd, EventLoop &loop) {
                LOG(DEBUG) << "Incoming event on ambiorix fd:";
                amxb_read(m_bus_ctx);
                return true;
            },

        // Not implemented
        .on_write      = nullptr,
        .on_disconnect = nullptr,

        // Handle interface errors
        .on_error =
            [&](int fd, EventLoop &loop) {
                LOG(DEBUG) << "Error on ambiorix fd.";
                return true;
            },
    };

    m_event_loop->register_handlers(ambiorix_fd, handlers);

    LOG(DEBUG) << "The event loop initialized successfully.";
    return true;
}

amxd_object_t *Ambiorix::find_object(const std::string &relative_path)
{

    auto root_object = amxd_dm_get_root(&m_datamodel);
    if (!root_object) {
        LOG(ERROR) << "Failed to get root object from data model.";
        return nullptr;
    }

    auto object = amxd_object_findf(root_object, "%s", relative_path.c_str());
    if (!object) {
        LOG(ERROR) << "Failed to get " << relative_path << "object from data model.";
        return nullptr;
    }

    LOG(DEBUG) << "Return object pointer on: " << object->name;
    return object;
}

template <typename T> bool Ambiorix::set(const std::string &relative_path, const T &value)
{
    auto object = find_object(relative_path);
    if (!object) {
        LOG(ERROR) << "Couldn't get object by relative path.";
        return false;
    }

    amxd_trans_t transaction;
    auto status = amxd_trans_init(&transaction);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't inititalize transaction, status: " << status;
        return false;
    }

    status = amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't set transaction attributes, status: " << status;
        return false;
    }

    status = amxd_trans_select_object(&transaction, object);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't select transaction object, status: " << status;
        return false;
    }

    LOG(DEBUG) << "Set value: " << value << "to the object: " << object->name;

    std::string type = typeid(T).name();
    if (type == "std::string") {
        amxd_trans_set_value(cstring_t, &transaction, object->name, value.c_str());
    } else {
        amxd_trans_set_value(T, &transaction, object->name, value);
    }

    status = amxd_trans_apply(&transaction, &m_datamodel);
    if (status != amxd_status_ok) {
        LOG(ERROR) << "Couldn't apply transaction object, status: " << status;
        return false;
    }

    amxd_trans_clean(&transaction);

    amxc_var_set(T, status, value);

    return true;
}

Ambiorix::~Ambiorix()
{
    amxb_free(&m_bus_ctx);
    amxd_dm_clean(&m_datamodel);
    amxo_parser_clean(&m_parser);
    amxb_be_remove_all();
}
} // namespace nbapi
} // namespace beerocks
