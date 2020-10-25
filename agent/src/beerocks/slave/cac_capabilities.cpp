/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "cac_capabilities.h"
#include <algorithm>

namespace beerocks {

CacMethodForRadio get_radio_cac_methods(const CacCapabilities &cac, const sMacAddr &radio)
{
    // get the supported radios from the capabilities
    const auto &cac_radios = cac.get_cac_radios();
    CacMethodForRadio ret;

    // helper structure
    const std::array<eCacMethod, 4> methods = {
        eCacMethod::CAC_METHOD_CONTINUOUS, eCacMethod::CAC_METHOD_CONTINUOUS_WITH_DEDICATED_RADIO,
        eCacMethod::CAC_METHOD_MIMO_DIMENSION_REDUCED, eCacMethod::CAC_METHOD_TIME_SLICED};

    // copy the cac method if
    // the radio supports it
    copy_if(methods.begin(), methods.end(), std::back_inserter(ret.second),
            [&cac, &radio](const eCacMethod method) {
                return cac.is_cac_method_supported(radio, method);
            });

    return ret;
}

} // namespace beerocks
