/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_UTILS_WLAN_HAL_WHM_H_
#define _BWL_UTILS_WLAN_HAL_WHM_H_

#include <bcl/beerocks_defines.h>
#include <bwl/base_wlan_hal_types.h>

namespace bwl {
namespace whm {

class utils_wlan_hal_whm {

public:
    /**
     * @brief Converts a string-based radio state to an eRadioState.
     */
    static eRadioState radio_state_from_string(const std::string &state);
};

} // namespace whm
} // namespace bwl

#endif // _BWL_UTILS_WLAN_HAL_WHM_H_
