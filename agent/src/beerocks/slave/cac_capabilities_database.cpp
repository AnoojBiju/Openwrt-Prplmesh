/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "cac_capabilities_database.h"
#include "agent_db.h"
#include <bcl/son/son_wireless_utils.h>
#include <tlvf/tlvftypes.h>

namespace beerocks {

const beerocks::CountryCode CacCapabilitiesDatabase::get_country_code() const
{
    return AgentDB::get()->device_conf.country_code;
}

std::vector<sMacAddr> CacCapabilitiesDatabase::get_cac_radios() const
{
    auto db = AgentDB::get();

    const auto &interfaces = db->get_radios_list();

    std::vector<AgentDB::sRadio *> radios_5g;

    // all 5g radios are cac radios
    std::copy_if(interfaces.begin(), interfaces.end(), std::back_inserter(radios_5g),
                 [&db](const AgentDB::sRadio *radio) {
                     if (!radio) {
                         return false;
                     }
                     return son::wireless_utils::is_frequency_band_5ghz(radio->freq_type);
                 });

    // copy just the mac
    std::vector<sMacAddr> ret;
    std::transform(radios_5g.begin(), radios_5g.end(), std::back_inserter(ret),
                   [](const AgentDB::sRadio *radio_5g) { return radio_5g->front.iface_mac; });
    return ret;
}

bool CacCapabilitiesDatabase::is_cac_method_supported(const sMacAddr &radio_mac,
                                                      beerocks::eCacMethod method) const
{
    auto db          = AgentDB::get();
    const auto radio = db->get_radio_by_mac(radio_mac);

    if (!radio) {
        // no radio therefore non of the cac methods is supported
        return false;
    }

    // make sure it is 5g radio
    if (!son::wireless_utils::is_frequency_band_5ghz(radio->freq_type)) {
        // not a 5g radio therefore non of the cac methods is supported
        return false;
    }

    // all 5g radios supports continues method
    if (method == beerocks::eCacMethod::CAC_METHOD_CONTINUOUS) {
        return true;
    }

    // zwdf existance means that de facto we support mimo dimension reduced
    if (method == beerocks::eCacMethod::CAC_METHOD_MIMO_DIMENSION_REDUCED) {
        return db->device_conf.zwdfs_enable;
    }

    // we don't support anything else
    return false;
}

uint32_t CacCapabilitiesDatabase::get_cac_completion_duration(const sMacAddr &radio_mac,
                                                              beerocks::eCacMethod method) const
{
    auto db          = AgentDB::get();
    const auto radio = db->get_radio_by_mac(radio_mac);

    if (!radio) {
        // no radio therefore the cac method is not supported and therefore
        // it takes zero to perform it
        return 0;
    }

    auto capabilities_for_method = radio->cac_capabilities.cac_method_capabilities.find(method);

    if (capabilities_for_method == radio->cac_capabilities.cac_method_capabilities.end()) {
        // when we don't have a record for this method
        // it means that we are not able to perform it, and therefore
        // the duration is 0;
        return 0;
    }

    return capabilities_for_method->second.cac_duration_sec;
}

CacCapabilities::CacOperatingClasses
CacCapabilitiesDatabase::get_cac_operating_classes(const sMacAddr &radio_mac,
                                                   beerocks::eCacMethod method) const
{
    auto db          = AgentDB::get();
    const auto radio = db->get_radio_by_mac(radio_mac);

    if (!radio) {
        // no radio therefore the cac method is not supported and therefore
        // we return an ampty list
        return CacOperatingClasses{};
    }

    auto capabilities_for_method = radio->cac_capabilities.cac_method_capabilities.find(method);

    if (capabilities_for_method == radio->cac_capabilities.cac_method_capabilities.end()) {
        // when we don't have a record for this method
        // it means that we are not able to perform it, and therefore
        // we return an empty list
        return CacOperatingClasses{};
    }

    return capabilities_for_method->second.operating_classes;
}

} // namespace beerocks
