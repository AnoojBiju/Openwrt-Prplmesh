/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_READER_IMPL_H_
#define BCL_NETWORK_BRIDGE_STATUS_READER_IMPL_H_

#include "bridge_status_reader.h"

namespace beerocks {
namespace net {

class BridgeStatusReaderImpl : public BridgeStatusReader {
public:
    /**
     * @brief Reads current status of a network bridge.
     *
     * @see BridgeStatusReader::read_status
     *
     * This implementation reads the contents of "/sys/class/net/" + bridge + "/brif" to obtain the
     * list of interfaces in the bridge.
     */
    bool read_status(const std::string &bridge_name, std::set<std::string> &iface_names) override;
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_READER_IMPL_H_ */
