/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_MANAGER_IMPL_H_
#define BCL_NETWORK_BRIDGE_STATUS_MANAGER_IMPL_H_

#include "bridge_status_manager.h"

#include <memory>
#include <unordered_map>

namespace beerocks {
namespace net {

/**
 * This class implements the BridgeStatusManager facade interface in terms of (by delegating to)
 * the BridgeStatusMonitor and BridgeStatusReader interfaces and performs additional
 * functionality before/after forwarding requests.
 */
class BridgeStatusManagerImpl : public BridgeStatusManager {
public:
    /**
     * @brief Class constructor
     *
     * This implementation delegates BridgeStatusMonitor and BridgeStatusReader requests to given
     * reader and monitor instances respectively.
     *
     * The bridge status monitor is used to monitor changes in the status of the network bridge
     * in an event-driven way, that is, without polling. The monitor will execute a callback handler
     * function whenever either a network interface is added to the bridge or removed from the
     * bridge.
     *
     * The bridge status reader is used to read the status of a network bridge (i.e.: the list of
     * network interfaces in the bridge) when it is not known yet (i.e. the first time the status is
     * queried).
     *
     * Installs a status-changed event handler on the monitor which stores received bridge status
     * information into the list of current interfaces for each known bridge. This way, when the
     * read_status() method is called, the cached status can be quickly returned instead of having
     * to query the network bridge using the reader.
     *
     * @param bridge_status_monitor Bridge status monitor.
     * @param bridge_status_reader Bridge status reader.
     */
    BridgeStatusManagerImpl(std::unique_ptr<BridgeStatusMonitor> bridge_status_monitor,
                            std::unique_ptr<BridgeStatusReader> bridge_status_reader);

    /**
     * @brief Class destructor
     *
     * Removes the status-changed event handler installed on the monitor.
     */
    ~BridgeStatusManagerImpl() override;

    /**
     * @brief Reads current status of a network bridge (i.e.: the list of network interfaces in the
     * bridge).
     *
     * If the bridge status is already known, then returns the cached status. Otherwise delegates to
     * BridgeStatusReader::read_status and caches obtained status. Cached status is continuously
     * updated with information about changes provided by the monitor.
     *
     * @see BridgeStatusReader::read_status
     */
    bool read_status(const std::string &bridge_name, std::set<std::string> &iface_names) override;

private:
    /**
     * Bridge status monitor used to monitor changes in the status of the network bridge.
     */
    std::unique_ptr<BridgeStatusMonitor> m_bridge_status_monitor;

    /**
     * Bridge status reader used to read the status of a network bridge when it is not known yet
     * (i.e. the first time the status is queried).
     */
    std::unique_ptr<BridgeStatusReader> m_bridge_status_reader;

    /**
     * Map containing the current status of each known bridge.
     * The map key is the bridge name and the map value is the bridge status (i.e.: the list of
     * interfaces in the bridge).
     */
    std::unordered_map<std::string, std::set<std::string>> m_bridge_statuses;

    /**
     * @brief Gets last known bridge status.
     *
     * @param[in] bridge_name Bridge name.
     * @param[out] iface_names Names of the interfaces in the network bridge.
     * @return true on success and false otherwise (i.e.: interface state is not known yet).
     */
    bool get_status(const std::string &bridge_name, std::set<std::string> &iface_names);

    /**
     * @brief Sets last known bridge status.
     *
     * @param[in] bridge_name Bridge name.
     * @param[out] iface_names Names of the interfaces in the network bridge.
     */
    void set_status(const std::string &bridge_name, const std::set<std::string> &iface_names);
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_MANAGER_IMPL_H_ */
