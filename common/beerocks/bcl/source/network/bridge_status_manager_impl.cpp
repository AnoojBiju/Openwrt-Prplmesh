/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/bridge_status_manager_impl.h>

#include <algorithm>

namespace beerocks {
namespace net {

BridgeStatusManagerImpl::BridgeStatusManagerImpl(
    std::unique_ptr<BridgeStatusMonitor> bridge_status_monitor,
    std::unique_ptr<BridgeStatusReader> bridge_status_reader)
    : m_bridge_status_monitor(std::move(bridge_status_monitor)),
      m_bridge_status_reader(std::move(bridge_status_reader))
{
    m_bridge_status_monitor->set_handler(
        [&](const std::string &bridge_name, const std::string &iface_name, bool iface_status) {
            // Get the cached list of interfaces in the given bridge, if it exists
            std::set<std::string> iface_names;
            if (get_status(bridge_name, iface_names)) {

                // If given interface has been added and it was not in the list, then add it.
                // Else, if given interface has been removed and it was in the list, then remove it
                bool iface_names_is_dirty = false;
                auto it = std::find(iface_names.begin(), iface_names.end(), iface_name);
                if (iface_status && (it == iface_names.end())) {
                    iface_names.emplace(iface_name);
                    iface_names_is_dirty = true;
                } else if ((!iface_status) && (it != iface_names.end())) {
                    iface_names.erase(it);
                    iface_names_is_dirty = true;
                }

                // If changed, update the cached list of interfaces and notify the change.
                if (iface_names_is_dirty) {
                    set_status(bridge_name, iface_names);
                    notify_status_changed(bridge_name, iface_name, iface_status);
                }
            }
        });
}

BridgeStatusManagerImpl::~BridgeStatusManagerImpl() { m_bridge_status_monitor->clear_handler(); }

bool BridgeStatusManagerImpl::read_status(const std::string &bridge_name,
                                          std::set<std::string> &iface_names)
{
    if (get_status(bridge_name, iface_names)) {
        return true;
    }

    if (!m_bridge_status_reader->read_status(bridge_name, iface_names)) {
        return false;
    }

    set_status(bridge_name, iface_names);

    return true;
}

bool BridgeStatusManagerImpl::get_status(const std::string &bridge_name,
                                         std::set<std::string> &iface_names)
{
    const auto &it = m_bridge_statuses.find(bridge_name);
    if (m_bridge_statuses.end() == it) {
        return false;
    }

    iface_names = it->second;

    return true;
}

void BridgeStatusManagerImpl::set_status(const std::string &bridge_name,
                                         const std::set<std::string> &iface_names)
{
    m_bridge_statuses[bridge_name] = iface_names;
}

} // namespace net
} // namespace beerocks
