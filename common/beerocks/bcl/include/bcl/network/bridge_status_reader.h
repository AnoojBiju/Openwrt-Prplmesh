/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_READER_H_
#define BCL_NETWORK_BRIDGE_STATUS_READER_H_

#include <set>
#include <string>

namespace beerocks {
namespace net {

class BridgeStatusReader {
public:
    virtual ~BridgeStatusReader() = default;

    /**
     * @brief Reads current status of a network bridge.
     *
     * Reads the names of the interfaces in given network bridge.
     *
     * @param[in] bridge_name Bridge name.
     * @param[out] iface_names Names of the interfaces in the network bridge.
     * @return true on success and false otherwise.
     */
    virtual bool read_status(const std::string &bridge_name,
                             std::set<std::string> &iface_names) = 0;
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_READER_H_ */
