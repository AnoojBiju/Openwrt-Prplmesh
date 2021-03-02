/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "../dummy/cac_capabilities_dummy.h"
#include <cac_capabilities.h>
#include <tlvf/tlvftypes.h>

#include <gtest/gtest.h>

namespace {

TEST(cac_capabilities_test, get_cac_methods)
{
    bwl::dummy::CacCapabilitiesDummy cac;
    cac.set_cac_radios({"a1:b1:c1:d1:e1:f1", "00:00:11:11::22:22"});

    auto cac_methods = beerocks::get_radios_cac_methods(cac);

    EXPECT_EQ(cac_methods[1].second[0], beerocks::eCacMethod::CAC_METHOD_CONTINUES);
    EXPECT_EQ(cac_methods[1].second[1], beerocks::eCacMethod::CAC_METHOD_MIMO_DIMENTION_REDUCED);
}

} // namespace
