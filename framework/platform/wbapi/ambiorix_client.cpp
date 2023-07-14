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

AmbiorixClient::AmbiorixClient(const std::string &amxb_backend, const std::string &bus_uri)
    : m_connection(amxb_backend, bus_uri)
{
}

bool AmbiorixClient::connect()
{

    if (!m_connection.init()) {
        LOG(ERROR) << "Failed to connect to the backend " << m_connection.get_amxb_backend_path()
                   << " on uri:  " << m_connection.get_uri();
        return false;
    } else {
        LOG(DEBUG) << "Successfully connected to  " << m_connection.get_amxb_backend_path()
                   << " on uri:  " << m_connection.get_uri();
    }

    LOG(DEBUG) << "Successfully connected to " << m_connection.get_uri();

    return true;
}

AmbiorixVariantSmartPtr AmbiorixClient::get_object(const std::string &object_path,
                                                   const int32_t depth)
{
    return m_connection.get_object(object_path, depth, true);
}

AmbiorixVariantSmartPtr AmbiorixClient::get_param(const std::string &obj_path,
                                                  const std::string &param_name)
{
    return m_connection.get_param(obj_path, param_name);
}

bool AmbiorixClient::resolve_path_multi(const std::string &search_path,
                                        std::vector<std::string> &absolute_path_list)
{
    return m_connection.resolve_path(search_path, absolute_path_list);
}

bool AmbiorixClient::resolve_path(const std::string &search_path, std::string &absolute_path)
{
    std::vector<std::string> absolute_path_list;
    if (resolve_path_multi(search_path, absolute_path_list) && !absolute_path_list.empty()) {
        absolute_path = absolute_path_list[0];
        return true;
    }
    absolute_path = "";
    return false;
}

bool AmbiorixClient::update_object(const std::string &object_path, AmbiorixVariant &object_data)
{
    return m_connection.update_object(object_path, object_data);
}

bool AmbiorixClient::add_instance(const std::string &object_path, AmbiorixVariant &object_data,
                                  int &instance_id)
{
    return m_connection.add_instance(object_path, object_data, instance_id);
}

bool AmbiorixClient::remove_instance(const std::string &object_path, int instance_id)
{
    return m_connection.remove_instance(object_path, instance_id);
}

bool AmbiorixClient::call(const std::string &object_path, const char *method, AmbiorixVariant &args,
                          AmbiorixVariant &result)
{
    return m_connection.call(object_path, method, args, result);
}

int AmbiorixClient::get_fd() { return m_connection.get_fd(); }

int AmbiorixClient::get_signal_fd() { return m_connection.get_signal_fd(); }

int AmbiorixClient::read() { return m_connection.read(); }

int AmbiorixClient::read_signal() { return m_connection.read_signal(); }

bool AmbiorixClient::init_event_loop(std::shared_ptr<EventLoop> event_loop)
{
    LOG(DEBUG) << "Register event handlers for the Ambiorix fd in the event loop.";

    auto ambiorix_fd = get_fd();
    if (ambiorix_fd < 0) {
        LOG(ERROR) << "Something Wrong with ambiorix fd: " << ambiorix_fd;
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_events",
        .on_read =
            [&, ambiorix_fd](int fd, EventLoop &loop) {
                if (fd == ambiorix_fd) {
                    read();
                }
                return true;
            },

        // Not implemented
        .on_write = nullptr,
        .on_disconnect =
            [&, ambiorix_fd](int fd, EventLoop &loop) {
                if (fd == ambiorix_fd) {
                    this->m_connection.disconnected();
                    LOG(ERROR) << "Ambiorix connection with fd= " << fd << " disconnected!";
                }
                return true;
            },

        // Handle interface errors
        .on_error =
            [ambiorix_fd](int fd, EventLoop &loop) {
                if (fd == ambiorix_fd) {
                    LOG(ERROR) << "Error on ambiorix fd " << ambiorix_fd;
                }
                return true;
            },
    };

    if (event_loop->remove_handlers(ambiorix_fd)) {
        LOG(WARNING) << "Replacing old handlers for the Amx fd: " << ambiorix_fd;
    }
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

    auto ambiorix_signal_fd = get_signal_fd();
    if (ambiorix_signal_fd < 0) {
        LOG(ERROR) << "Something Wrong with ambiorix signal fd: " << ambiorix_signal_fd;
        return false;
    }

    EventLoop::EventHandlers handlers = {
        .name = "ambiorix_signal",
        .on_read =
            [&, ambiorix_signal_fd](int fd, EventLoop &loop) {
                if (fd == ambiorix_signal_fd) {
                    read_signal();
                }
                return true;
            },
        // Not implemented
        .on_write = nullptr,
        .on_disconnect =
            [&, ambiorix_signal_fd](int fd, EventLoop &loop) {
                if (fd == ambiorix_signal_fd) {
                    this->m_connection.disconnected();
                    LOG(ERROR) << "Connection with signal fd: " << ambiorix_signal_fd
                               << " disconnected!";
                }
                return true;
            },

        // Handle interface errors
        .on_error =
            [ambiorix_signal_fd](int fd, EventLoop &loop) {
                if (fd == ambiorix_signal_fd) {
                    LOG(ERROR) << "Error on ambiorix signal fd: " << ambiorix_signal_fd;
                }
                return true;
            },
    };

    if (event_loop->remove_handlers(ambiorix_signal_fd)) {
        LOG(WARNING) << "Replacing old handlers for the Amx sig fd " << ambiorix_signal_fd;
    }
    if (!event_loop->register_handlers(ambiorix_signal_fd, handlers)) {
        LOG(ERROR) << "Couldn't register event handlers for the Ambiorix signals in the "
                      "event loop.";
        return false;
    }

    LOG(DEBUG) << "Event handlers for the Ambiorix signals fd: " << ambiorix_signal_fd
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
                                               std::shared_ptr<sAmbiorixEventHandler> event_handler,
                                               const std::string &filter)
{
    m_subscriptions.emplace_back(event_handler);
    if (!m_connection.subscribe(object_path, filter, m_subscriptions.back())) {
        LOG(ERROR) << "Subscribing to object events failed, path:" << object_path;
        m_subscriptions.pop_back();
        return false;
    }
    LOG(INFO) << "subscribed successfully to object events, path:" << object_path
              << "with filter= " << filter;
    return true;
}

AmbiorixClient::~AmbiorixClient()
{
    for (auto &subscription : m_subscriptions) {
        m_connection.unsubscribe(subscription);
    }
}

} // namespace wbapi
} // namespace beerocks
