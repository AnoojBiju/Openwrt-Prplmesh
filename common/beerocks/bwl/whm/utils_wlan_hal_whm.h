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

    /**
     * @brief Converts WiFiSec security type to string
     */
    static std::string security_type_to_string(const WiFiSec &security_type);

    /**
     * @brief Converts a string-based security type to WiFiSec
     */
    static WiFiSec security_type_from_string(const std::string &security_type);

    /**
     * @brief Decodes a base64 string 
     */
    static bool base64_decode(std::vector<uint8_t> &decoded_output,
                              const std::string &base64_input);

private:
    /**
     * @brief Convertion table of Security type from string to WiFiSec.
     */
    static const std::map<std::string, WiFiSec> security_type_table;
};

} // namespace whm
} // namespace bwl

#endif // _BWL_UTILS_WLAN_HAL_WHM_H_
