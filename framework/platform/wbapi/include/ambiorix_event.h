/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_EVENT_H_
#define AMBIORIX_EVENT_H_

#include <ambiorix_variant.h>

#include <functional>

constexpr char AMX_CL_OBJECT_CHANGED_EVT[]   = "dm:object-changed";
constexpr char AMX_CL_OBJECT_ADDED_EVT[]     = "dm:object-added";
constexpr char AMX_CL_OBJECT_REMOVED_EVT[]   = "dm:object-removed";
constexpr char AMX_CL_INSTANCE_ADDED_EVT[]   = "dm:instance-added";
constexpr char AMX_CL_INSTANCE_REMOVED_EVT[] = "dm:instance-removed";
constexpr char AMX_CL_PERIODIC_INFORM_EVT[]  = "dm:periodic-inform";

namespace beerocks {
namespace wbapi {

using AmbiorixEventCallbak = std::function<void(AmbiorixVariant &event_data, void *context)>;

/**
 * @struct sAmbiorixEventHandler
 */
struct sAmbiorixEventHandler {
    sAmbiorixEventHandler() {}
    sAmbiorixEventHandler(const sAmbiorixEventHandler &handler)
        : event_type(handler.event_type), callback_fn(handler.callback_fn), context(handler.context)
    {
    }

    std::string event_type;
    AmbiorixEventCallbak callback_fn;
    void *context = nullptr;
};

/**
 * @struct sAmbiorixSubscriptionInfo
 */
struct sAmbiorixSubscriptionInfo {
    sAmbiorixSubscriptionInfo() {}
    explicit sAmbiorixSubscriptionInfo(std::shared_ptr<sAmbiorixEventHandler> &handler_)
        : handler(handler_)
    {
    }
    sAmbiorixSubscriptionInfo(const sAmbiorixSubscriptionInfo &other) : handler(other.handler) {}

    std::shared_ptr<sAmbiorixEventHandler> handler;
    amxb_subscription_t *subscription_ctx = nullptr;
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_EVENT_H_ */
