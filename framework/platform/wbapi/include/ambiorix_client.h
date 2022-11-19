/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CLIENT_H
#define AMBIORIX_CLIENT_H

// prplmesh
#include <bcl/beerocks_event_loop.h>
#include <easylogging++.h>

// Ambiorix
#include "ambiorix_connection.h"

namespace beerocks {
namespace wbapi {

/**
 * @class AmbiorixClient
 * @brief This class manages the AmbiorixClient instance.
 */
class AmbiorixClient {

public:
    AmbiorixClient(){};
    AmbiorixClient(const AmbiorixClient &) = delete;
    AmbiorixClient &operator=(const AmbiorixClient &) = delete;
    ~AmbiorixClient();

    /**
     * @brief connect to an ambiorix backend: load backend, connect to the bus
     *
     * @param[in] amxb_backend: path to the ambiorix backend (ex: "/usr/bin/mods/amxb/mod-amxb-ubus.so").
     * @param[in] bus_uri: path to the bus in uri form (ex: "ubus:/var/run/ubus.sock").
     * @return True on success and false otherwise.
     * 
    */
    bool connect(const std::string &amxb_backend = {AMBIORIX_WBAPI_BACKEND_PATH},
                 const std::string &bus_uri      = {AMBIORIX_WBAPI_BUS_URI});

    /**
     * @brief read and return content tree of first object matching requested path.
     *
     * @param[in] object_path: may be search path (possibly multiple match) or absolute path (unique match)
     * @param[in] depth: relative depth, it indicates how many levels of child objects are returned
     * @return AmbiorixVariantSmartPtr smart pointer to ambiorixVariant including result.
     *                                 Empty when operation fails.
     */
    AmbiorixVariantSmartPtr get_object(const std::string &object_path, const int32_t depth = 0);

    /**
     * @brief read and return object parameter content.
     *
     * @param[in] obj_path: parent object path.
     * @param[in] param_name: parameter name.
     * @return AmbiorixVariantSmartPtr smart pointer to ambiorixVariant including result.
     *                                 Empty when operation fails.
     */
    AmbiorixVariantSmartPtr get_param(const std::string &obj_path, const std::string &param_name);

    /**
     * @brief get content, with provided depth, of all objects matching path
     * in map of Ambiorix variant objects, sorted by path string
     *
     * @param[in] object_path: may be search path (possibly multiple match) or absolute path (unique match)
     * @param[in] depth: relative depth, it indicates how many levels of child objects are returned
     * @return AmbiorixVariantListSmartPtr including variant childs
     *      or AmbiorixVariantMapSmartPtr sorting childs in pairs of [object path, object content],
     *      or Empty when operation fails.
     */
    template <typename T>
    T get_object_multi(const std::string &object_path, const int32_t depth = 0)
    {
        if (!m_connection) {
            return T{};
        }
        auto objs = m_connection->get_object(object_path, depth, false);
        if (!objs) {
            return T{};
        }
        return objs->take_childs<T>();
    }

    /**
     * @brief request parameter value and converts it to basic types
     * through template specialization.
     *
     * @param[out] result: reference to typed result, filled with converted parameter value
     * @param[in] obj_path: parent object path.
     * @param[in] param_name: parameter name.
     * @return true on success, false otherwise.
     */
    template <typename T>
    bool get_param(T &result, const std::string &obj_path, const std::string &param_name)
    {
        auto var = get_param(obj_path, param_name);
        return (var && var->get(result));
    }

    /**
     * @brief resolve a search path, and retrieve first matching result.
     *
     * @param[in] search_path: search path to object/parameter.
     * @param[out] absolute_path: first resolved path string, empty when failing.
     * @return true when search path is resolved, false otherwise.
    */
    bool resolve_path(const std::string &search_path, std::string &absolute_path);

    /**
     * @brief resolve a search path, and retrieve all matching results.
     *
     * @param[in] search_path: search path to object/parameter.
     * @param[out] absolute_path_list: all resolved path strings, cleared when failing.
     * @return true when search path is resolved, false otherwise.
    */
    bool resolve_path_multi(const std::string &search_path,
                            std::vector<std::string> &absolute_path_list);

    /**
     * @brief update a given object.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object_data: data to be updated.
     * @return True on success and false otherwise.
    */
    bool update_object(const std::string &object_path, AmbiorixVariant &object_data);

    /**
     * @brief add instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object_data: parameters values of the instance.
     * @param[out] instance_id: the new instance id.
     * @return True on success and false otherwise.
    */
    bool add_instance(const std::string &object_path, AmbiorixVariant &object_data,
                      int &instance_id);

    /**
     * @brief remove instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] instance_id: the instance id.
     * @return True on success and false otherwise.
    */
    bool remove_instance(const std::string &object_path, int instance_id);

    /**
     * @brief invokes a data model function.
     *
     * @param[in] object_path: object path to the object that contains the function.
     * @param[in] method: name of the function being called.
     * @param[in] args: the function arguments in a amxc variant htable type.
     * @param[out] result: will contain the return value(s) and/or the out arguments.
     * @return True on success and false otherwise.
    */
    bool call(const std::string &object_path, const char *method, AmbiorixVariant &args,
              AmbiorixVariant &result);

    /**
     * @brief get the amxb file descriptor.
     * Use this function to add the file descriptor to your event loop.
     *
     * @return the valid file descriptor or -1 when no file descriptor is available.
    */
    int get_fd();

    /**
     * @brief get the amxp signal file descriptor.
     *
     * @return the valid file descriptor or -1 when no file descriptor is available.
    */
    int get_signal_fd();

    /**
     * @brief read data from the file descriptor of the connection context.
     * Typically the backend parses the received data and dispatches to the correct
     * callbacks if needed.
     *
     * This function is typically called whenever your eventloop detects that
     * data is available for read on the connection context's file descriptor.
     *
     * @return -1 when failed reading, other values are considered as success.
     * and depends on the backend implementation, typically the number of bytes
     * read are returned.
    */
    int read();

    /**
     * @brief from the amxp signal file descriptor.
     *
     * To be able to use this method it is recommended to implement an eventloop.
     *
     * @return 0 when successful, otherwise an error code
    */
    int read_signal();

    /**
     * @brief Initialize event handlers for Ambiorix fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool init_event_loop(std::shared_ptr<EventLoop> event_loop);

    /**
     * @brief Initialize event handlers for the ambiorix signals fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool init_signal_loop(std::shared_ptr<EventLoop> event_loop);

    /**
     * @brief Remove event handlers for Ambiorix fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool remove_event_loop(std::shared_ptr<EventLoop> event_loop);

    /**
     * @brief Remove event handlers for the ambiorix signals fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    bool remove_signal_loop(std::shared_ptr<EventLoop> event_loop);

    /**
     * @brief subscribe for event for a given object.
     *
     * @param[in] object_path: path to object.
     * @param[in] event_handler: event handler structure.
     * @param[in] filter: filter expression.
     * @return true on success, false otherwise.
     */
    bool subscribe_to_object_event(const std::string &object_path,
                                   std::shared_ptr<sAmbiorixEventHandler> &event_handler,
                                   const std::string &filter = {});

private:
    AmbiorixConnectionSmartPtr m_connection;
    std::vector<sAmbiorixSubscriptionInfo> m_subscriptions;
};

} // namespace wbapi
} // namespace beerocks

#endif
