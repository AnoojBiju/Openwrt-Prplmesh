/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_CONNECTION_H_
#define AMBIORIX_CONNECTION_H_

#include <ambiorix_variant.h>

#include <ambiorix_event.h>

#include <functional>

#include <mutex>

#include <vector>

#ifndef AMBIORIX_WBAPI_BACKEND_PATH
#define AMBIORIX_WBAPI_BACKEND_PATH "/usr/bin/mods/amxb/mod-amxb-ubus.so"
#endif
#ifndef AMBIORIX_WBAPI_BUS_URI
#define AMBIORIX_WBAPI_BUS_URI "ubus:/var/run/ubus.sock"
#endif

namespace beerocks {
namespace wbapi {

class AmbiorixConnection;
using AmbiorixConnectionSmartPtr = std::shared_ptr<AmbiorixConnection>;

/**
 * @class AmbiorixConnection
 * @brief This class defines all actions applicable on ambiorix bus connection.
 */
class AmbiorixConnection : AmbiorixVariantBaseAccess {
public:
    /**
     * @brief Class constructor.
     *
     * @param[in] amxb_backend: path to the ambiorix backend (ex: "/usr/bin/mods/amxb/mod-amxb-ubus.so").
     * @param[in] bus_uri: path to the bus in uri form (ex: "ubus:/var/run/ubus.sock").
     */
    AmbiorixConnection(const std::string &amxb_backend, const std::string &bus_uri);

    /**
     * @brief: no Copy constructor, neither assignment operator
     */
    AmbiorixConnection(const AmbiorixConnection &) = delete;
    AmbiorixConnection &operator=(const AmbiorixConnection &) = delete;

    /**
     * @brief Class destructor.
     */
    virtual ~AmbiorixConnection();

    /**
     * @brief connect to an ambiorix backend: load backend, connect to the bus
     *
     * @return True on success and false otherwise.
     */
    bool init();

    /**
     * @brief Factory method: creating smart pointer for established AmbiorixConnection
     * (created and initialized)
     *
     * @param[in] amxb_backend: path to the ambiorix backend (ex: "/usr/bin/mods/amxb/mod-amxb-ubus.so").
     * @param[in] bus_uri: path to the bus in uri form (ex: "ubus:/var/run/ubus.sock").
     * @return shared_ptr for newly established AmbiorixConnection object
     * or empty in case of error
     */
    static AmbiorixConnectionSmartPtr
    create(const std::string &amxb_backend = {AMBIORIX_WBAPI_BACKEND_PATH},
           const std::string &bus_uri      = {AMBIORIX_WBAPI_BUS_URI});

    /**
     * @brief Read and return content of matching objects.
     *
     * @param[in] object_path: search path to object.
     * @param[in] depth: indicates how many levels of child objects are returned
     * @param[in] only_first: it indicates if only first matching object is returned
     * @return smart pointer to AmbiorixVariant including table of object parameters and values
     */
    AmbiorixVariantSmartPtr get_object(const std::string &object_path, const int32_t depth,
                                       bool only_first);

    /**
     * @brief Read and return object parameter value.
     *
     * @param[in] object_path: search path to object.
     * @param[in] param_name: parameter name.
     * @return smart pointer to AmbiorixVariant including parameter value
     */
    AmbiorixVariantSmartPtr get_param(const std::string &object_path,
                                      const std::string &param_name);

    /**
     * @brief Resolve a search path, and retrieve all matching results.
     *
     * @param[in] search_path: search path to object/parameter.
     * @param[out] absolute_path_list: all resolved path strings, cleared when failing.
     * @return true when search path is resolved, false otherwise.
    */
    bool resolve_path(const std::string &search_path, std::vector<std::string> &absolute_path_list);

    /**
     * @brief Update a given object.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object_data: object content to be updated.
     * @return True on success and false otherwise.
     */
    bool update_object(const std::string &object_path, AmbiorixVariant &object_data);

    /**
     * @brief Add instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object: object_data: parameters and values of the new instance.
     * @param[out] instance_id: the new instance id.
     * @return True on success and false otherwise.
    */
    bool add_instance(const std::string &object_path, AmbiorixVariant &object_data,
                      int &instance_id);

    /**
     * @brief Remove instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] instance_id: the instance id to be deleted.
     * @return True on success and false otherwise.
     */
    bool remove_instance(const std::string &object_path, int instance_id);

    /**
     * @brief Invoke a data model function.
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
     * @brief Read data from the file descriptor of the connection context.
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
      * @brief Read event from the amxp signal pipe file descriptor.
      * To be able to use this method it is recommended to implement an eventloop.
      *
      * @return 0 when successful, otherwise an error code
      */
    int read_signal();

    /**
     * @brief Get the amxb file descriptor.
     * Use this function to add the file descriptor to your event loop.
     *
     * @return the valid file descriptor or -1 when no file descriptor is available.
     */
    int get_fd();

    /**
     * @brief Get the amxp signal file descriptor.
     *
     * @return the valid file descriptor or -1 when no file descriptor is available.
     */
    int get_signal_fd();

    /**
     * @brief Subscribe for event for a given object.
     *
     * @param[in] object_path: path to object.
     * @param[in] filter: filter expression.
     * @param[in] subscriptionInfo: event subscription structure.
     * @return true on success, false otherwise.
     */
    bool subscribe(const std::string &object_path, const std::string &filter,
                   sAmbiorixSubscriptionInfo &subscriptionInfo);
    /**
     * @brief Remove subscription for event for a given object.
     *
     * @param[in] subscriptionInfo: event subscription structure.
     * @return true on success, false otherwise.
     */
    bool unsubscribe(sAmbiorixSubscriptionInfo &subscriptionInfo);

    /**
     * @brief Return connection bus URI.
     */
    const std::string &uri() const;

private:
    std::recursive_mutex m_mutex;
    std::string m_amxb_backend;
    std::string m_bus_uri;
    amxb_bus_ctx_t *m_bus_ctx = nullptr;
    int m_fd                  = -1;
    int m_signal_fd           = -1;
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_CONNECTION_H_ */
