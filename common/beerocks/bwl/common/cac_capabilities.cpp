/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <algorithm>
#include <cac_capabilities.h>

namespace beerocks {

CacMethodForRadio get_radios_cac_methods(const CacCapabilities &cac)
{
    // get the supported radios from the capabilities
    const auto &cac_radios = cac.get_cac_radios();
    CacMethodForRadio ret;

    // build a return with empty supported cac
    // method list for all supported radios
    std::transform(
        cac_radios.begin(), cac_radios.end(), std::back_inserter(ret),
        [](const sMacAddr &addr) { return std::make_pair(addr, std::vector<eCacMethod>()); });

    // helper structure
    const std::array<eCacMethod, 4> methods = {
        eCacMethod::CAC_METHOD_CONTINUES, eCacMethod::CAC_METHOD_CONTINUES_WITH_DEDICATED_RADIO,
        eCacMethod::CAC_METHOD_MIMO_DIMENTION_REDUCED, eCacMethod::CAC_METHOD_TIME_SLICED};

    // for each cac radio supported
    for (auto &radio : ret) {
        // copy the cac method if
        // the radio supports it
        copy_if(methods.begin(), methods.end(), std::back_inserter(radio.second),
                [&cac, &radio](const eCacMethod method) {
                    return cac.is_cac_method_supported(radio.first, method);
                });
    }

    return ret;
}

} // namespace beerocks
