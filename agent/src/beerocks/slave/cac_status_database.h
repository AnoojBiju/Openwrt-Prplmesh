/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CAC_STAUS_DATABASE_H_
#define _CAC_STAUS_DATABASE_H_

#include "cac_status_interface.h"

namespace beerocks {

class CacStatusDatabase : public CacStatusInterface {
public:
    std::vector<sMacAddr> get_cac_radios() const override;
    CacAvailableChannels get_availiable_channels(const sMacAddr &radio) const override;
    CacNonOccupancyChannels get_non_occupancy_channels(const sMacAddr &radio) const override;
    CacActiveChannels get_active_channels(const sMacAddr &radio) const override;
    CacCompletionStatus get_completion_status(const sMacAddr &radio) const override;
};

// utilities based on CacCapabilities interface

} // namespace beerocks

#endif
