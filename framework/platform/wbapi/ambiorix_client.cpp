/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include "ambiorix_client.h"

namespace beerocks {
namespace wbapi {

bool AmbiorixClient::connect(const std::string &amxb_backend, const std::string &bus_uri)
{
    int ret = 0;

    // Load the backend .so file
    ret = amxb_be_load(amxb_backend.c_str());
    if (ret != 0) {
        LOG(ERROR) << "Failed to load the " << amxb_backend.c_str() << " backend, ret: " << ret;
        return false;
    }

    // Connect to the bus
    ret = amxb_connect(&m_bus_ctx, bus_uri.c_str());
    if (ret != 0) {
        LOG(ERROR) << "Failed to connect to the " << bus_uri.c_str() << " bus, ret: " << ret;
        return false;
    }

    LOG(DEBUG) << "The bus connection initialized successfully.";

    return true;
}

amxc_var_t *AmbiorixClient::get_object(const std::string &object_path, const int32_t depth)
{
    amxc_var_t data;
    amxc_var_init(&data);
    amxc_var_t *result = nullptr;

    int ret = amxb_get(m_bus_ctx, object_path.c_str(), depth, &data, AMX_CL_DEF_TIMEOUT);
    if (ret == AMXB_STATUS_OK) {
        result = GETI_ARG(&data, 0);
        if (depth == 0) {
            result = amxc_var_get_first(result);
        }
        amxc_var_take_it(result);
    } else {
        LOG(DEBUG) << "Request path [" << object_path << "] failed ret: " << std::to_string(ret);
    }
    amxc_var_clean(&data);

    return result;
}

bool AmbiorixClient::update_object(const std::string &object_path, amxc_var_t *object)
{
    amxc_var_t data;
    amxc_var_init(&data);
    int ret = amxb_set(m_bus_ctx, object_path.c_str(), object, &data, AMX_CL_DEF_TIMEOUT);
    amxc_var_clean(&data);
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixClient::add_instance(const std::string &object_path, amxc_var_t *parameter,
                                  int &instance_id)
{
    amxc_var_t data;
    amxc_var_init(&data);
    bool success = false;
    if (amxb_add(m_bus_ctx, object_path.c_str(), 0, NULL, parameter, &data, AMX_CL_DEF_TIMEOUT) ==
        AMXB_STATUS_OK) {
        const char *path = GETP_CHAR(&data, "0.path");
        if (path) {
            std::string instance_path   = std::string(path).substr(0, std::string(path).size() - 1);
            std::size_t found           = instance_path.find_last_of(AMX_CL_OBJ_DELIMITER);
            std::string instance_id_str = instance_path.substr(found + 1);
            instance_id                 = std::stoi(instance_id_str);
            success                     = true;
        }
    }
    amxc_var_clean(&data);
    return success;
}

bool AmbiorixClient::remove_instance(const std::string &object_path, int instance_id)
{
    amxc_var_t data;
    amxc_var_init(&data);
    int ret =
        amxb_del(m_bus_ctx, object_path.c_str(), instance_id, NULL, &data, AMX_CL_DEF_TIMEOUT);
    amxc_var_clean(&data);
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixClient::call(const std::string &object_path, const char *method, amxc_var_t *args,
                          amxc_var_t *result)
{
    int ret = amxb_call(m_bus_ctx, object_path.c_str(), method, args, result, AMX_CL_DEF_TIMEOUT);
    return (ret == AMXB_STATUS_OK);
}

int AmbiorixClient::get_fd() { return amxb_get_fd(m_bus_ctx); }

int AmbiorixClient::get_signal_fd() { return amxp_signal_fd(); }

int AmbiorixClient::read() { return amxb_read(m_bus_ctx); }

int AmbiorixClient::read_signal() { return amxp_signal_read(); }

bool AmbiorixClient::init_event_loop(std::shared_ptr<EventLoop> event_loop)
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix fd in the event loop.";

    auto ambiorix_fd = get_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_events",
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

    if (!event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix fd in the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool AmbiorixClient::init_signal_loop(std::shared_ptr<EventLoop> event_loop)
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix signals fd in the event loop.";

    auto ambiorix_fd = get_signal_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_signal",
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

    if (!event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix signals fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool AmbiorixClient::remove_event_loop(std::shared_ptr<EventLoop> event_loop)
{
    LOG(DEBUG) << "Remove event handlers for Ambiorix fd from the event loop.";

    auto ambiorix_fd = get_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    if (!event_loop->remove_handlers(ambiorix_fd)) {
        LOG(ERROR) << "Couldn't remove event handlers for the Ambiorix fd from the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd successfully removed from the event loop.";

    return true;
}

bool AmbiorixClient::remove_signal_loop(std::shared_ptr<EventLoop> event_loop)
{
    LOG(DEBUG) << "Remove event handlers for the Ambiorix signals fd from the event loop.";

    auto ambiorix_fd = get_signal_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }

    if (!event_loop->remove_handlers(ambiorix_fd)) {
        LOG(ERROR) << "Couldn't remove event handlers for the Ambiorix signals fd from the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "The event handlers for the Ambiorix signals fd removed successfully from the "
                  "event loop.";

    return true;
}

bool AmbiorixClient::subscribe_to_object_event(const std::string &object_path,
                                               sAmxClEventCallback *event_callback)
{
    auto sub_cb = [](const char *const sig_name, const amxc_var_t *const data,
                     void *const priv) -> void {
        sAmxClEventCallback *event_callback = static_cast<sAmxClEventCallback *>(priv);
        if (event_callback) {
            const char *notification = GET_CHAR(data, "notification");
            if (notification && (event_callback->event_type == std::string(notification))) {
                if (event_callback->callback_fn) {
                    event_callback->callback_fn((amxc_var_t *)data, event_callback->context);
                }
            }
        }
    };
    int retval =
        amxb_subscribe(m_bus_ctx, object_path.c_str(), nullptr, sub_cb, (void *)event_callback);
    if (retval != AMXB_STATUS_OK) {
        LOG(ERROR) << "Subscribing to object events failed, path:" << object_path
                   << ", errno:" << retval;
        return false;
    }
    LOG(DEBUG) << "subscribe successfully to object events, path:" << object_path;
    return true;
}

AmbiorixClient::~AmbiorixClient() { amxb_free(&m_bus_ctx); }

} // namespace wbapi
} // namespace beerocks
