/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CAC_STAUS_H_
#define _CAC_STAUS_H_

#include "tlvf/common/sMacAddr.h"
#include <chrono>
#include <map>
#include <vector>

namespace beerocks {

enum eCacCompletionStatus : uint8_t {
    SUCCESSFUL           = 0x0,
    RADAR_DETECTED       = 0x1,
    CAC_NOT_SUPPORTED    = 0x2,
    RADIO_TOO_BUSY       = 0x3,
    NOT_UNDER_REGULATION = 0x4,
    OTHER_ERROR          = 0x5,
    NOT_PERFORMED        = 0xff,
};

struct sCacStatus {
    uint8_t operating_class = 0;
    uint8_t channel         = 0;
    // duration is used based on the context
    std::chrono::seconds duration          = std::chrono::seconds(0);
    eCacCompletionStatus completion_status = eCacCompletionStatus::NOT_PERFORMED;
};

using CacAvailableChannels    = std::vector<sCacStatus>;
using CacNonOccupancyChannels = std::vector<sCacStatus>;
using CacActiveChannels       = std::vector<sCacStatus>;

// comletion status is:
//  * operating class + channel + completion status (duration has no meaning)
//  * a vector of operating class + channel that are overlapping with the first pair
//  of operating class and channel
using CacCompletionStatus = std::pair<sCacStatus, std::vector<std::pair<uint8_t, uint8_t>>>;

class CacStatusInterface {
public:
    virtual ~CacStatusInterface()                                                    = default;
    virtual std::vector<sMacAddr> get_cac_radios() const                             = 0;
    virtual CacAvailableChannels get_available_channels(const sMacAddr &radio) const = 0;
    virtual CacCompletionStatus get_completion_status(const sMacAddr &radio) const   = 0;
};

// utilities based on CacCapabilities interface

} // namespace beerocks

#endif
