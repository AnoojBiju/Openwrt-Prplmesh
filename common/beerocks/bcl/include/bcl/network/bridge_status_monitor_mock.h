/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_MONITOR_MOCK_H_
#define BCL_NETWORK_BRIDGE_STATUS_MONITOR_MOCK_H_

#include "bridge_status_monitor.h"

#include <gmock/gmock.h>

namespace beerocks {
namespace net {

class BridgeStatusMonitorMock : public BridgeStatusMonitor {
public:
    /**
     * This method was inherited as protected but we're changing it to public via a using
     * declaration so we can invoke it from unit tests to emulate that a status-changed event has
     * occurred.
     */
    using BridgeStatusMonitor::notify_status_changed;
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_MONITOR_MOCK_H_ */
