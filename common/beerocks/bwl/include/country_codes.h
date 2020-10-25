/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _COUNTRY_CODES_H_
#define _COUNTRY_CODES_H_

#include <string>

// addopted from ISO 3166 [5] with mistakes

namespace beerocks {

struct sCountryCode {
    const std::string country_name;
    const std::string alpha_2;
    const std::string alpha_3;
    const std::string numeric_3;
};

} // namespace beerocks

#endif
