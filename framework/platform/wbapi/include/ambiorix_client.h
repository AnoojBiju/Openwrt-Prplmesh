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
#include <amxc/amxc.h>

#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

#ifndef AMBIORIX_WBAPI_BACKEND_PATH
#define AMBIORIX_WBAPI_BACKEND_PATH "/usr/bin/mods/amxb/mod-amxb-ubus.so"
#endif
#ifndef AMBIORIX_WBAPI_BUS_URI
#define AMBIORIX_WBAPI_BUS_URI "ubus:/var/run/ubus.sock"
#endif

constexpr uint8_t AMX_CL_DEF_TIMEOUT = 3;

constexpr char AMX_CL_WIFI_ROOT_NAME[]    = "WiFi";
constexpr char AMX_CL_RADIO_OBJ_NAME[]    = "Radio";
constexpr char AMX_CL_AP_OBJ_NAME[]       = "AccessPoint";
constexpr char AMX_CL_SSID_OBJ_NAME[]     = "SSID";
constexpr char AMX_CL_ENDPOINT_OBJ_NAME[] = "EndPoint";
constexpr char AMX_CL_OBJ_DELIMITER       = '.';

constexpr char AMX_CL_OBJECT_CHANGED_EVT[]   = "dm:object-changed";
constexpr char AMX_CL_OBJECT_ADDED_EVT[]     = "dm:object-added";
constexpr char AMX_CL_OBJECT_REMOVED_EVT[]   = "dm:object-removed";
constexpr char AMX_CL_INSTANCE_ADDED_EVT[]   = "dm:instance-added";
constexpr char AMX_CL_INSTANCE_CHANGED_EVT[] = "dm:instance-removed";
constexpr char AMX_CL_PERIODIC_INFORM_EVT[]  = "dm:periodic-inform";

using AmxClEventCb = std::function<void(amxc_var_t *event_data, void *context)>;

struct sAmxClEventCallback {
    AmxClEventCb callback_fn;
    std::string event_type;
    void *context;
};

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
    bool connect(const std::string &amxb_backend, const std::string &bus_uri);

    /**
     * @brief read and return a given object.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] depth: relative depth, if not zero it indicates how many levels of child objects are returned
     * @return amxc_var_t object.
    */
    amxc_var_t *get_object(const std::string &object_path, const int32_t depth);

    /**
     * @brief update a given object.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object: amxc_var_t object to update.
     * @return True on success and false otherwise.
    */
    bool update_object(const std::string &object_path, amxc_var_t *object);

    /**
     * @brief add instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object: amxc_var_t parameter: list of parameters values of the instance.
     * @param[out] instance_id: the new instance id.
     * @return True on success and false otherwise.
    */
    bool add_instance(const std::string &object_path, amxc_var_t *parameter, int &instance_id);

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
    bool call(const std::string &object_path, const char *method, amxc_var_t *args,
              amxc_var_t *result);

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
     * @param[in] filter: filter expression.
     * @param[in] event_callback: event callback structure.
     * @return true on success, false otherwise.
    */
    bool subscribe_to_object_event(const std::string &object_path,
                                   sAmxClEventCallback *event_callback);

private:
    amxb_bus_ctx_t *m_bus_ctx = nullptr;
};

} // namespace wbapi
} // namespace beerocks

#endif
