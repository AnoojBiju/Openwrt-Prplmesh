/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_utils.h>

#include <gtest/gtest.h>

#include <unordered_map>

namespace {

TEST(BeerocksUtilsTest, extract_prefix_from_iface_name)
{
    std::unordered_map<std::string, std::string> maps = {
        /* success cases */
        {"wl", "wl"},
        {"wlan0", "wlan"},
        {"wlan0.0", "wlan"},
        {"eth10.10", "eth"},
        {"eth1p0.10", "eth1p"},
        /* error cases */
        {"", ""},
        {"10", ""},
        {"eth10.x10", ""},
        {"eth10.10x", ""},
    };

    for (auto &it : maps) {
        ASSERT_STREQ(beerocks::utils::get_prefix_from_iface_string(it.first).c_str(),
                     it.second.c_str());
    }
}

TEST(BeerocksUtilsTest, check_allowed_iface_prefix)
{
    std::map<std::pair<std::string, bool>, bool> maps = {/* success cases */
                                                         {std::make_pair("wl", false), true},
                                                         {std::make_pair("wlan", false), true},
                                                         {std::make_pair("wl1.1", true), true},
                                                         {std::make_pair("wlan0", true), true},
                                                         {std::make_pair("wlx0", true), true},
                                                         /* error cases */
                                                         {std::make_pair("lwl", true), false},
                                                         {std::make_pair("wl0", false), false},
                                                         {std::make_pair("eth0", false), false},
                                                         {std::make_pair("eth0", true), false}};

    for (auto &it : maps) {
        ASSERT_EQ(beerocks::utils::is_allowed_ifname_prefix(it.first.first, it.first.second),
                  it.second);
    }
}

} // namespace
