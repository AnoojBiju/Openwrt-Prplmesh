/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include "mutex"

#include "include/ambiorix_client_impl.h"

#include <amxb/amxb_operators.h>

#include <amxd/amxd_path.h>

namespace beerocks {
namespace wbapi {

// use recursive mutex to avoid simultaneous amx bus access
// (Amx does not support multi-threaded clients)
std::recursive_mutex amx_cli_mutex;

std::unordered_map<int, amxb_bus_ctx_t *> amx_fd_maps = {};

AmbiorixClientImpl::AmbiorixClientImpl(std::unique_ptr<AmbiorixConnection> connection)
    : m_connection(std::move(connection)), m_bus_ctx(m_connection->get_bus_ctx())
{
}

amxc_var_t *AmbiorixClientImpl::get_object(const std::string &object_path, const int32_t depth,
                                           bool only_first)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    amxc_var_t data;
    amxc_var_init(&data);
    amxc_var_t *result = nullptr;

    int ret = amxb_get(m_bus_ctx, object_path.c_str(), depth, &data, AMX_CL_DEF_TIMEOUT);
    if (ret == AMXB_STATUS_OK) {
        result = GETI_ARG(&data, 0);
        if ((depth == 0) && only_first) {
            result = amxc_var_get_first(result);
        }
        amxc_var_take_it(result);
    } else {
        LOG(ERROR) << "Request path [" << object_path << "] failed ret: " << std::to_string(ret);
    }
    amxc_var_clean(&data);

    return result;
}

bool AmbiorixClientImpl::resolve_path(const std::string &search_path,
                                      std::vector<std::string> &abs_path_list)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    abs_path_list.clear();
    amxd_path_t amxd_path;
    amxd_path_init(&amxd_path, search_path.c_str());
    amxc_var_t result;
    amxc_var_init(&result);
    if ((amxb_resolve(m_bus_ctx, &amxd_path, &result) == 0) && (!amxc_var_is_null(&result)) &&
        (amxc_var_type_of(&result) == AMXC_VAR_ID_LIST)) {
        amxc_var_for_each(path, &result)
        {
            abs_path_list.push_back(std::string(amxc_var_constcast(cstring_t, path)));
        }
    }
    amxd_path_clean(&amxd_path);
    amxc_var_clean(&result);
    return (!abs_path_list.empty());
}

bool AmbiorixClientImpl::resolve_path(const std::string &search_path, std::string &abs_path)
{
    std::vector<std::string> abs_path_list;
    if (resolve_path(search_path, abs_path_list)) {
        abs_path = abs_path_list[0];
        return true;
    }
    abs_path = "";
    return false;
}

bool AmbiorixClientImpl::update_object(const std::string &object_path, amxc_var_t *object)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    amxc_var_t data;
    amxc_var_init(&data);
    int ret = amxb_set(m_bus_ctx, object_path.c_str(), object, &data, AMX_CL_DEF_TIMEOUT);
    amxc_var_clean(&data);
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixClientImpl::add_instance(const std::string &object_path, amxc_var_t *parameter,
                                      int &instance_id)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    amxc_var_t data;
    amxc_var_init(&data);
    bool success = false;
    if (amxb_add(m_bus_ctx, object_path.c_str(), 0, NULL, parameter, &data, AMX_CL_DEF_TIMEOUT) ==
        AMXB_STATUS_OK) {
        amxc_var_t *pID = GETP_ARG(&data, "0.index");
        if (pID) {
            instance_id = amxc_var_get_uint32_t(pID);
            success     = true;
        }
    }
    amxc_var_clean(&data);
    return success;
}

bool AmbiorixClientImpl::remove_instance(const std::string &object_path, int instance_id)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    amxc_var_t data;
    amxc_var_init(&data);
    int ret =
        amxb_del(m_bus_ctx, object_path.c_str(), instance_id, NULL, &data, AMX_CL_DEF_TIMEOUT);
    amxc_var_clean(&data);
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixClientImpl::call(const std::string &object_path, const char *method, amxc_var_t *args,
                              amxc_var_t *result)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    int ret = amxb_call(m_bus_ctx, object_path.c_str(), method, args, result, AMX_CL_DEF_TIMEOUT);
    return (ret == AMXB_STATUS_OK);
}

int AmbiorixClientImpl::get_fd() { return amxb_get_fd(m_bus_ctx); }

int AmbiorixClientImpl::get_signal_fd() { return amxp_signal_fd(); }

static int s_read(amxb_bus_ctx_t *p_bus_ctx)
{
    //const std::lock_guard<std::mutex> lock(amx_cli_mutex);
    int ret = amxb_read(p_bus_ctx);
    if (ret > 0) {
        while (amxb_read(p_bus_ctx) > 0) {
        }
    }
    return ret;
}

int AmbiorixClientImpl::read() { return s_read(m_bus_ctx); }

static int s_read_signal()
{
    //const std::lock_guard<std::mutex> lock(amx_cli_mutex);
    int ret = amxp_signal_read();
    if (ret == 0) {
        while (amxp_signal_read() == 0) {
        }
    }
    return ret;
}

int AmbiorixClientImpl::read_signal() { return s_read_signal(); }

bool AmbiorixClientImpl::init_event_loop(std::shared_ptr<EventLoop> event_loop)
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix fd in the event loop.";

    auto ambiorix_fd = get_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Failed to get ambiorix file descriptor.";
        return false;
    }
    amx_fd_maps[ambiorix_fd] = m_bus_ctx;

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_events",
        .on_read =
            [&](int fd, EventLoop &loop) {
                s_read(amx_fd_maps[fd]);
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

    if (event_loop->remove_handlers(ambiorix_fd)) {
        LOG(WARNING) << "Replacing old handlers for the Amx fd " << std::to_string(ambiorix_fd);
    }
    if (!event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix fd in the event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool AmbiorixClientImpl::init_signal_loop(std::shared_ptr<EventLoop> event_loop)
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
                s_read_signal();
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

    if (event_loop->remove_handlers(ambiorix_fd)) {
        LOG(WARNING) << "Replacing old handlers for the Amx sig fd " << std::to_string(ambiorix_fd);
    }
    if (!event_loop->register_handlers(ambiorix_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix signals fd: " << ambiorix_fd
               << " successfully registered in the event loop.";

    return true;
}

bool AmbiorixClientImpl::remove_event_loop(std::shared_ptr<EventLoop> event_loop)
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
    amx_fd_maps.erase(ambiorix_fd);

    LOG(DEBUG) << "Event handlers for the Ambiorix fd successfully removed from the event loop.";

    return true;
}

bool AmbiorixClientImpl::remove_signal_loop(std::shared_ptr<EventLoop> event_loop)
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

static void sub_cb(const char *const sig_name, const amxc_var_t *const data, void *const priv)
{
    sAmxClEventCallback *event_callback = static_cast<sAmxClEventCallback *>(priv);
    if (event_callback) {
        const char *notification = GET_CHAR(data, "notification");
        if (notification) {
            if (event_callback->event_type == notification) {
                if (event_callback->callback_fn) {
                    event_callback->callback_fn((amxc_var_t *)data, event_callback->context);
                }
            }
        }
    }
}

bool AmbiorixClientImpl::subscribe_to_object_event(const std::string &object_path,
                                                   sAmxClEventCallback *event_callback,
                                                   const std::string &filter)
{
    const std::lock_guard<std::recursive_mutex> lock(amx_cli_mutex);
    amxb_subscription_t *sub = nullptr;
    int retval = amxb_subscription_new(&sub, m_bus_ctx, object_path.c_str(), filter.c_str(), sub_cb,
                                       (void *)event_callback);
    if (retval != AMXB_STATUS_OK) {
        LOG(ERROR) << "Subscribing to object events failed, path:" << object_path
                   << ", errno:" << retval;
        return false;
    }
    m_subscriptions.push_back(sub);
    LOG(DEBUG) << "subscribe successfully to object events, path:" << object_path;
    return true;
}

AmbiorixClientImpl::~AmbiorixClientImpl()
{
    amxb_subscription_t *sub = nullptr;
    while (!m_subscriptions.empty()) {
        sub = m_subscriptions.back();
        amxb_subscription_delete(&sub);
        m_subscriptions.pop_back();
    }
}

} // namespace wbapi
} // namespace beerocks
