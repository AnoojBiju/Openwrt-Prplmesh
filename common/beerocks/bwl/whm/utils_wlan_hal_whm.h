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
#include <bwl/mon_wlan_hal_types.h>

namespace bwl {
namespace whm {

namespace utils_wlan_hal_whm {

/**
* @brief Converts a string-based radio state to an eRadioState.
*/
eRadioState radio_state_from_string(const std::string &state);

/**
 * @brief Convert from a bool radio.enable to eRadioState
 */
eRadioState radio_state_from_bool(const bool flag);

/**
 * @brief Converts WiFiSec security type to string
*/
std::string security_type_to_string(const WiFiSec &security_type);

/**
* @brief Converts a string-based security type to WiFiSec
*/
WiFiSec security_type_from_string(const std::string &security_type);

/**
* @brief converts int bandwith to eChannelScanResultChannelBandwidth
*/
bwl::eChannelScanResultChannelBandwidth get_bandwidth_from_int(const int32_t bw);

/**
* @brief converts eFreqType to eChannelScanResultOperatingFrequencyBand
*/
bwl::eChannelScanResultOperatingFrequencyBand
eFreqType_to_eCh_scan_Op_Fr_Ba(const beerocks::eFreqType freq_type);

/**
* @brief Decodes encryption_modes to a  vector of type eChannelScanResultEncryptionMode
*/
std::vector<eChannelScanResultEncryptionMode>
get_scan_result_encryption_modes_from_str(const std::string &encryption_modes);

/**
* @brief Decodes  standards to a vector of type eChannelScanResultStandards
*/
std::vector<eChannelScanResultStandards>
get_scan_result_operating_standards_from_str(const std::string &standards);

/**
* @brief Decodes  security_modes to a vector of type eChannelScanResultSecurityMode
*/
std::vector<eChannelScanResultSecurityMode>
get_scan_security_modes_from_str(const std::string &security_modes);

/**
* @brief Convertion table of Security type from string to WiFiSec.
*/
const std::map<std::string, WiFiSec> security_type_table;

} // namespace utils_wlan_hal_whm
} // namespace whm
} // namespace bwl

#endif // _BWL_UTILS_WLAN_HAL_WHM_H_
