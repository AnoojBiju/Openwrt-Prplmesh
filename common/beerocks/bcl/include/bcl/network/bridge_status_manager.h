/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_MANAGER_H_
#define BCL_NETWORK_BRIDGE_STATUS_MANAGER_H_

#include "bridge_status_monitor.h"
#include "bridge_status_reader.h"

namespace beerocks {
namespace net {

/**
 * The BridgeStatusManager is a facade interface for both the BridgeStatusMonitor and
 * BridgeStatusReader interfaces together.
 */
class BridgeStatusManager : public BridgeStatusMonitor, public BridgeStatusReader {
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_MANAGER_H_ */
