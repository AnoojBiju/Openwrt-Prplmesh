/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef CAC_CAPABILITIES__DUMMY_H_
#define CAC_CAPABILITIES__DUMMY_H_

#include <cac_capabilities.h>
#include <tlvf/tlvftypes.h>

namespace bwl {
namespace dummy {

class CacCapabilitiesDummy : public beerocks::CacCapabilities {
public:
    CacCapabilitiesDummy()
        : m_radios({tlvf::mac_from_string("aa:bb:cc:dd:ee:ff"),
                    tlvf::mac_from_string("00:11:22:33:44:55")})
    {
    }

    void set_cac_radios(std::vector<std::string> radios)
    {
        m_radios.clear();
        std::transform(radios.begin(), radios.end(), std::back_inserter(m_radios),
                       [](const std::string mac) { return tlvf::mac_from_string(mac); });
    }

public:
    /**
    * @brief iso 3166 country code this agent is running at.
    * @return a const reference to the structure
    */
    const beerocks::sCountryCode get_country_code() const override
    {
        return {"Montserrat", "MS", "MSR", "500"};
    }

    std::vector<sMacAddr> get_cac_radios() const override { return m_radios; }

    /**
    * @brief only counts the number of simultaneously cacs
    * for exampe if only one antena is available for cac then
    * this function returns 1. returning zero means
    * that this agent is unable to preform cac at all
    * @return the number of simultaneous cac 
    */
    uint8_t get_cac_number_of_simultaneously() const override { return 2; }

    /**
    * @brief indication about specific cac method support for 
    * specific radio
    * @param radio the mac of the radio in question
    * @param cac-method the cac method in quesiton
    * @return true if the requested cac is supported for this radio
    * false otherwise (including wrong radio for example)
    */
    bool is_cac_method_supported(const sMacAddr &, beerocks::eCacMethod method) const override
    {
        switch (method) {
        case beerocks::eCacMethod::CAC_METHOD_CONTINUES:
            return true;
        case beerocks::eCacMethod::CAC_METHOD_CONTINUES_WITH_DEDICATED_RADIO:
            return false;
        case beerocks::eCacMethod::CAC_METHOD_MIMO_DIMENTION_REDUCED:
            return true;
        case beerocks::eCacMethod::CAC_METHOD_TIME_SLICED:
            return false;
        }

        return false;
    }

    /**
    * @brief cac duration
    * @param radio the mac of the radio in question
    * @param cac-method the cac method in quesiton
    * @return seconds the number of seconds it takes for the
    * given radio to complete cac scan using the given method
    */
    uint32_t get_cac_completion_duration(const sMacAddr &,
                                         beerocks::eCacMethod method) const override
    {
        switch (method) {
        case beerocks::eCacMethod::CAC_METHOD_CONTINUES:
            return 90;
        case beerocks::eCacMethod::CAC_METHOD_CONTINUES_WITH_DEDICATED_RADIO:
            return 45;
        case beerocks::eCacMethod::CAC_METHOD_MIMO_DIMENTION_REDUCED:
            return 4;
        case beerocks::eCacMethod::CAC_METHOD_TIME_SLICED:
            return 180;
        }

        return 0;
    }

    /**
    * @brief operating classes and channels
    * @param radio the mac of the radio in question
    * @param cac-method the cac method in quesiton
    * @return a map: key - operating class, value: array of channles
    * for given radio and given method
    */
    using CacOperatingClasses = std::map<uint8_t, std::vector<uint8_t>>;
    CacOperatingClasses get_cac_operaintg_classes(const sMacAddr &,
                                                  beerocks::eCacMethod) const override
    {
        return {{100, {36}}, {102, {35, 44, 62}}};
    }

private:
    std::vector<sMacAddr> m_radios;
};

} // namespace dummy
} // namespace bwl

#endif
