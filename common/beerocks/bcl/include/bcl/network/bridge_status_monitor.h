/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_MONITOR_H_
#define BCL_NETWORK_BRIDGE_STATUS_MONITOR_H_

#include <functional>
#include <string>

namespace beerocks {
namespace net {

class BridgeStatusMonitor {
public:
    /**
     * Network bridge status-changed handler function.
     *
     * @param bridge_name Bridge name.
     * @param iface_name Interface name.
     * @param iface_state Interface status (true if it has been added to the bridge and false if it
     * has been removed from the bridge).
     */
    using StatusChangedHandler = std::function<void(
        const std::string &bridge_name, const std::string &iface_name, bool iface_status)>;

    /**
     * @brief Class destructor
     */
    virtual ~BridgeStatusMonitor() = default;

    /**
     * @brief Sets the status-changed event handler function.
     *
     * Sets the callback function to handle bridge status changes.
     * Use nullptr to remove previously installed callback function.
     *
     * If a handler is set, it will be called back whenever a bridge status changes, either because
     * a new interface is added to the bridge or because an interface is removed from the bridge.
     *
     * @param handler Status change handler function (or nullptr).
     */
    void set_handler(const StatusChangedHandler &handler) { m_handler = handler; }

    /**
     * @brief Clears previously set status-changed event handler function.
     *
     * Clears callback function previously set.
     * Behaves like set_handler(nullptr)
     */
    void clear_handler() { m_handler = nullptr; }

protected:
    /**
     * @brief Notifies a network bridge status-changed event.
     *
     * @param bridge_name Bridge name.
     * @param iface_name Interface name.
     * @param iface_state Interface status (true if it has been added to the bridge and false if it
     * has been removed from the bridge).
     */
    void notify_status_changed(const std::string &bridge_name, const std::string &iface_name,
                               bool iface_status) const
    {
        if (m_handler) {
            m_handler(bridge_name, iface_name, iface_status);
        }
    }

private:
    /**
     * Network bridge status-changed handler function that is called back whenever a bridge status
     * changes.
     */
    StatusChangedHandler m_handler;
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_MONITOR_H_ */
