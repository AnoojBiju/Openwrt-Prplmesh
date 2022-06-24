/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "utils_wlan_hal_whm.h"
#include <easylogging++.h>

namespace bwl {
namespace whm {

eRadioState utils_wlan_hal_whm::radio_state_from_string(const std::string &state)
{
    if (state == "Disabled") {
        return eRadioState::DISABLED;
    } else if (state == "Enabled") {
        return eRadioState::ENABLED;
    } else {
        return eRadioState::UNKNOWN;
    }
}

} // namespace whm
} // namespace bwl
