/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_READER_MOCK_H_
#define BCL_NETWORK_BRIDGE_STATUS_READER_MOCK_H_

#include "bridge_status_reader.h"

#include <gmock/gmock.h>

namespace beerocks {
namespace net {

class BridgeStatusReaderMock : public BridgeStatusReader {
public:
    MOCK_METHOD(bool, read_status,
                (const std::string &bridge_name, std::set<std::string> &iface_names), (override));
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_READER_MOCK_H_ */
