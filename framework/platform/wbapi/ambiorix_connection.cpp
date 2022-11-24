/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <easylogging++.h>

#include <bcl/beerocks_backport.h>

#include "include/ambiorix_connection.h"

#include <amxb/amxb_operators.h>

#include <amxd/amxd_path.h>

constexpr uint8_t AMX_CL_DEF_TIMEOUT = 3;

namespace beerocks {
namespace wbapi {

AmbiorixConnection::AmbiorixConnection(const std::string &amxb_backend, const std::string &bus_uri)
    : m_amxb_backend(amxb_backend), m_bus_uri(bus_uri)
{
}

AmbiorixConnection::~AmbiorixConnection() { amxb_free(&m_bus_ctx); }

const std::string &AmbiorixConnection::uri() const { return m_bus_uri; }

bool AmbiorixConnection::init()
{
    if (m_bus_ctx) {
        return true;
    }
    int ret = 0;
    // Load the backend .so file
    ret = amxb_be_load(m_amxb_backend.c_str());
    if (ret != 0) {
        LOG(ERROR) << "Failed to load the " << m_amxb_backend.c_str() << " backend";
        return false;
    }
    // Connect to the bus
    ret = amxb_connect(&m_bus_ctx, m_bus_uri.c_str());
    if (ret != 0) {
        LOG(ERROR) << "Failed to connect to the " << m_bus_uri.c_str() << " bus";
        return false;
    }
    m_fd        = amxb_get_fd(m_bus_ctx);
    m_signal_fd = amxp_signal_fd();
    return true;
}

AmbiorixConnectionSmartPtr AmbiorixConnection::create(const std::string &amxb_backend,
                                                      const std::string &bus_uri)
{
    auto cnx = std::make_shared<AmbiorixConnection>(amxb_backend, bus_uri);
    if (!cnx->init()) {
        return AmbiorixConnectionSmartPtr{};
    }
    return cnx;
}

AmbiorixVariantSmartPtr AmbiorixConnection::get_object(const std::string &object_path,
                                                       const int32_t depth, bool only_first)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    AmbiorixVariant result;
    int ret =
        amxb_get(m_bus_ctx, object_path.c_str(), depth, amxc_var_ptr(result), AMX_CL_DEF_TIMEOUT);
    auto entries = result.find_child(0);
    if (ret != AMXB_STATUS_OK || !entries) {
        LOG(ERROR) << "Request path [" << object_path << "] failed";
    } else if ((depth == 0) && only_first) {
        auto first_entry = entries->first_child();
        if (first_entry) {
            first_entry->detach();
        }
        return first_entry;
    } else {
        entries->detach();
    }
    return entries;
}

AmbiorixVariantSmartPtr AmbiorixConnection::get_param(const std::string &object_path,
                                                      const std::string &param_name)
{
    auto answer = get_object(object_path + param_name, 0, true);
    if (answer) {
        auto entry = answer->first_child();
        if (entry) {
            entry->detach();
        }
        return entry;
    }
    return answer;
}

bool AmbiorixConnection::resolve_path(const std::string &search_path,
                                      std::vector<std::string> &absolute_path_list)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    absolute_path_list.clear();
    amxd_path_t amxd_path;
    amxd_path_init(&amxd_path, search_path.c_str());
    AmbiorixVariant result;
    auto ret = amxb_resolve(m_bus_ctx, &amxd_path, amxc_var_ptr(result));
    amxd_path_clean(&amxd_path);
    if ((ret == 0) && (!result.empty()) && (result.get_type() == AMXC_VAR_ID_LIST)) {
        auto path_list = result.read_childs<AmbiorixVariantListSmartPtr>();
        if (!path_list) {
            return false;
        }
        for (auto &path : *path_list) {
            absolute_path_list.push_back(path);
        }
    }
    return (!absolute_path_list.empty());
}

bool AmbiorixConnection::update_object(const std::string &object_path, AmbiorixVariant &object_data)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    AmbiorixVariant result;
    int ret = amxb_set(m_bus_ctx, object_path.c_str(), amxc_var_ptr(object_data),
                       amxc_var_ptr(result), AMX_CL_DEF_TIMEOUT);
    LOG_IF(ret != AMXB_STATUS_OK, ERROR) << "update object [" << object_path << "] failed";
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixConnection::add_instance(const std::string &object_path, AmbiorixVariant &object_data,
                                      int &instance_id)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    AmbiorixVariant result;
    bool success = false;
    if (amxb_add(m_bus_ctx, object_path.c_str(), 0, NULL, amxc_var_ptr(object_data),
                 amxc_var_ptr(result), AMX_CL_DEF_TIMEOUT) == AMXB_STATUS_OK) {
        auto pID = result.find_child_deep("0.index");
        if (pID) {
            instance_id = pID->get<uint32_t>();
            success     = true;
        }
    }
    return success;
}

bool AmbiorixConnection::remove_instance(const std::string &object_path, int instance_id)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    AmbiorixVariant result;
    int ret = amxb_del(m_bus_ctx, object_path.c_str(), instance_id, NULL, amxc_var_ptr(result),
                       AMX_CL_DEF_TIMEOUT);
    LOG_IF(ret != AMXB_STATUS_OK, ERROR)
        << "remove instance [" << object_path << "." << std::to_string(instance_id) << "] failed";
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixConnection::call(const std::string &object_path, const char *method,
                              AmbiorixVariant &args, AmbiorixVariant &result)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    int ret = amxb_call(m_bus_ctx, object_path.c_str(), method, amxc_var_ptr(args),
                        amxc_var_ptr(result), AMX_CL_DEF_TIMEOUT);
    LOG_IF(ret != AMXB_STATUS_OK, ERROR)
        << "calling [" << object_path << "." << method << "] failed";
    return (ret == AMXB_STATUS_OK);
}

int AmbiorixConnection::read()
{
    m_mutex.lock();
    int ret = amxb_read(m_bus_ctx);
    m_mutex.unlock();
    if (ret > 0) {
        int ret2 = 0;
        do {
            m_mutex.lock();
            ret2 = amxb_read(m_bus_ctx);
            m_mutex.unlock();
        } while (ret2 > 0);
    }
    return ret;
}

int AmbiorixConnection::read_signal()
{
    int ret = amxp_signal_read();
    if (ret == 0) {
        while (amxp_signal_read() == 0) {
        }
    }
    return ret;
}

int AmbiorixConnection::get_fd() { return m_fd; }

int AmbiorixConnection::get_signal_fd() { return m_signal_fd; }

static void event_callback(const char *const sig_name, const amxc_var_t *const data,
                           void *const priv)
{
    sAmbiorixEventHandler *handler = static_cast<sAmbiorixEventHandler *>(priv);
    if (!handler || !data) {
        return;
    }
    std::string event_type;
    AmbiorixVariant event_obj((amxc_var_t *)data, false);
    if (event_obj.empty() || !event_obj.read_child<>(event_type, "notification")) {
        return;
    }
    if (handler->event_type == event_type) {
        if (handler->callback_fn) {
            handler->callback_fn(event_obj, handler->context);
        }
    }
}

bool AmbiorixConnection::subscribe(const std::string &object_path, const std::string &filter,
                                   sAmbiorixSubscriptionInfo &subscriptionInfo)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    int ret =
        amxb_subscription_new(&subscriptionInfo.subscription_ctx, m_bus_ctx, object_path.c_str(),
                              filter.c_str(), event_callback, subscriptionInfo.handler.get());
    LOG_IF(ret != AMXB_STATUS_OK, ERROR) << "subscribe to [" << object_path << "] failed";
    return (ret == AMXB_STATUS_OK);
}

bool AmbiorixConnection::unsubscribe(sAmbiorixSubscriptionInfo &subscriptionInfo)
{
    const std::lock_guard<std::recursive_mutex> lock(m_mutex);
    int ret = amxb_subscription_delete(&subscriptionInfo.subscription_ctx);
    LOG_IF(ret != AMXB_STATUS_OK, ERROR) << "unsubscribe failed";
    return (ret == AMXB_STATUS_OK);
}

} // namespace wbapi
} // namespace beerocks
