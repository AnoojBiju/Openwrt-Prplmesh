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

constexpr uint8_t AMX_CL_DEF_TIMEOUT = 3;

constexpr char AMX_CL_OBJECT_CHANGED_EVT[]   = "dm:object-changed";
constexpr char AMX_CL_OBJECT_ADDED_EVT[]     = "dm:object-added";
constexpr char AMX_CL_OBJECT_REMOVED_EVT[]   = "dm:object-removed";
constexpr char AMX_CL_INSTANCE_ADDED_EVT[]   = "dm:instance-added";
constexpr char AMX_CL_INSTANCE_CHANGED_EVT[] = "dm:instance-removed";
constexpr char AMX_CL_PERIODIC_INFORM_EVT[]  = "dm:periodic-inform";
constexpr char AMX_CL_WPS_PAIRING_DONE[]     = "pairingDone";

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
    /**
     * @brief Class destructor.
     */
    virtual ~AmbiorixClient() = default;

    /**
     * @brief read and return a given object.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] depth: relative depth, it indicates how many levels of child objects are returned
     * @param[in] only_first: it indicates if only first matching object is returned
     * @return amxc_var_t object.
    */
    virtual amxc_var_t *get_object(const std::string &object_path, const int32_t depth = 0,
                                   bool only_first = true) = 0;

    /**
     * @brief resolve a search path, and retrieve all matching results.
     *
     * @param[in] search_path: search path to object/parameter.
     * @param[out] abs_path_list: all resolved path strings, cleared when failing.
     * @return true when search path is resolved, false otherwise.
    */
    virtual bool resolve_path(const std::string &search_path,
                              std::vector<std::string> &abs_path_list) = 0;

    /**
     * @brief resolve a search path, and retrieve first matching result.
     *
     * @param[in] search_path: search path to object/parameter.
     * @param[out] abs_path: first resolved path string, empty when failing.
     * @return true when search path is resolved, false otherwise.
    */
    virtual bool resolve_path(const std::string &search_path, std::string &abs_path) = 0;

    /**
     * @brief update a given object.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object: amxc_var_t object to update.
     * @return True on success and false otherwise.
    */
    virtual bool update_object(const std::string &object_path, amxc_var_t *object) = 0;

    /**
     * @brief add instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] object: amxc_var_t parameter: list of parameters values of the instance.
     * @param[out] instance_id: the new instance id.
     * @return True on success and false otherwise.
    */
    virtual bool add_instance(const std::string &object_path, amxc_var_t *parameter,
                              int &instance_id) = 0;

    /**
     * @brief remove instance.
     *
     * @param[in] object_path: relative path to object.
     * @param[in] instance_id: the instance id.
     * @return True on success and false otherwise.
    */
    virtual bool remove_instance(const std::string &object_path, int instance_id) = 0;

    /**
     * @brief invokes a data model function.
     *
     * @param[in] object_path: object path to the object that contains the function.
     * @param[in] method: name of the function being called.
     * @param[in] args: the function arguments in a amxc variant htable type.
     * @param[out] result: will contain the return value(s) and/or the out arguments.
     * @return True on success and false otherwise.
    */
    virtual bool call(const std::string &object_path, const char *method, amxc_var_t *args,
                      amxc_var_t *result) = 0;

    /**
     * @brief get the amxb file descriptor.
     * Use this function to add the file descriptor to your event loop.
     *
     * @return the valid file descriptor or -1 when no file descriptor is available.
    */
    virtual int get_fd() = 0;

    /**
     * @brief get the amxp signal file descriptor.
     *
     * @return the valid file descriptor or -1 when no file descriptor is available.
    */
    virtual int get_signal_fd() = 0;

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
    virtual int read() = 0;

    /**
     * @brief from the amxp signal file descriptor.
     *
     * To be able to use this method it is recommended to implement an eventloop.
     *
     * @return 0 when successful, otherwise an error code
    */
    virtual int read_signal() = 0;

    /**
     * @brief Initialize event handlers for Ambiorix fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    virtual bool init_event_loop(std::shared_ptr<EventLoop> event_loop) = 0;

    /**
     * @brief Initialize event handlers for the ambiorix signals fd in the event loop.
     *
     * @return True on success and false otherwise.
     */
    virtual bool init_signal_loop(std::shared_ptr<EventLoop> event_loop) = 0;

    /**
     * @brief Remove event handlers for Ambiorix fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    virtual bool remove_event_loop(std::shared_ptr<EventLoop> event_loop) = 0;

    /**
     * @brief Remove event handlers for the ambiorix signals fd from the event loop.
     *
     * @return True on success and false otherwise.
     */
    virtual bool remove_signal_loop(std::shared_ptr<EventLoop> event_loop) = 0;

    /**
     * @brief subscribe for event for a given object.
     *
     * @param[in] object_path: path to object.
     * @param[in] event_callback: event callback structure.
     * @param[in] filter: filter expression.
     * @return true on success, false otherwise.
     */
    virtual bool subscribe_to_object_event(const std::string &object_path,
                                           sAmxClEventCallback *event_callback,
                                           const std::string &filter = {}) = 0;
};

} // namespace wbapi
} // namespace beerocks

#endif
