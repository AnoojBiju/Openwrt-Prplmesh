/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CAC_CAPABILITIES_H_
#define _CAC_CAPABILITIES_H_

#include "tlvf/common/sMacAddr.h"
#include <country_codes.h>
#include <map>
#include <vector>

namespace beerocks {

enum class eCacMethod {
    CAC_METHOD_CONTINUES                      = 0x00,
    CAC_METHOD_CONTINUES_WITH_DEDICATED_RADIO = 0x01,
    CAC_METHOD_MIMO_DIMENTION_REDUCED         = 0x02,
    CAC_METHOD_TIME_SLICED                    = 0x03
};

class CacCapabilities {
public:
    virtual ~CacCapabilities() = default;

    /**
    * @brief iso 3166 country code this agent is running at.
    * @return a const reference to the structure
    */
    virtual const sCountryCode get_country_code() const = 0;

    /**
    * @brief get the radios that can perform cac
    * @return a vector of rdios (mac) that may perform cac
    */
    virtual std::vector<sMacAddr> get_cac_radios() const = 0;

    /**
    * @brief only counts the number of simultaneously cacs
    * for exampe if only one antena is available for cac then
    * this function returns 1. returning zero means
    * that this agent is unable to preform cac at all
    * @return the number of simultaneous cac 
    */
    virtual uint8_t get_cac_number_of_simultaneously() const = 0;

    /**
    * @brief indication about specific cac method support for 
    * specific radio
    * @param radio the mac of the radio in question
    * @param cac-method the cac method in quesiton
    * @return true if the requested cac is supported for this radio
    * false otherwise (including wrong radio for example)
    */
    virtual bool is_cac_method_supported(const sMacAddr &, eCacMethod) const = 0;

    /**
    * @brief cac duration
    * @param radio the mac of the radio in question
    * @param cac-method the cac method in quesiton
    * @return seconds the number of seconds it takes for the
    * given radio to complete cac scan using the given method
    */
    virtual uint32_t get_cac_completion_duration(const sMacAddr &, eCacMethod) const = 0;

    /**
    * @brief operating classes and channels
    * @param radio the mac of the radio in question
    * @param cac-method the cac method in quesiton
    * @return a map: key - operating class, value: array of channles
    * for given radio and given method
    */
    using CacOperatingClasses = std::map<uint8_t, std::vector<uint8_t>>;
    virtual CacOperatingClasses get_cac_operaintg_classes(const sMacAddr &, eCacMethod) const = 0;
};

// utilities based on CacCapabilities interface

/**
 * @brief a structure that holds for each radio its cac supported methods
 * an empty vector indicates that cac is not supported at all
 */
using CacMethodForRadio = std::vector<std::pair<sMacAddr, std::vector<eCacMethod>>>;

/**
* @brief build the entire radio to method capabilities structure
* @param Cac capabilities object
* @return CacMethodForRadio see above
*/
CacMethodForRadio get_radios_cac_methods(const CacCapabilities &);

} // namespace beerocks

#endif
