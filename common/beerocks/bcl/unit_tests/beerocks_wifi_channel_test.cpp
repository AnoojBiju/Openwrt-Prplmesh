/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_wifi_channel.h>
#include <bcl/son/son_wireless_utils.h>
#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

namespace {

TEST(BeerocksWifiChannel, check_24ghz_getters_and_setters_are_valid)
{
    unsigned int channel        = 1;
    unsigned int center_freq    = 2422;
    beerocks::eWiFiBandwidth bw = beerocks::BANDWIDTH_20;

    beerocks::WifiChannel wc(channel, center_freq, bw);

    // check getter work properly after a object was constructed
    ASSERT_EQ(wc.get_channel(), channel);
    ASSERT_EQ(wc.get_center_frequency(), center_freq);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_freq_type(), beerocks::FREQ_24G);

    // check the bandwidth is set properly
    bw = beerocks::BANDWIDTH_40;
    wc.set_bandwidth(bw);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_center_frequency(),
              son::wireless_utils::channel_to_freq(channel + 2, beerocks::eFreqType::FREQ_24G));

    // check the channel and bandwidth are set properly
    channel = 6;
    bw      = beerocks::BANDWIDTH_20;
    wc.set_channel(channel);
    wc.set_bandwidth(bw);
    ASSERT_EQ(wc.get_channel(), channel);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_center_frequency(),
              son::wireless_utils::channel_to_freq(channel, beerocks::eFreqType::FREQ_24G));
}

TEST(BeerocksWifiChannel, check_5ghz_getters_and_setters_are_valid)
{
    unsigned int channel        = 36;
    unsigned int center_freq    = 5180;
    beerocks::eWiFiBandwidth bw = beerocks::BANDWIDTH_20;

    beerocks::WifiChannel wc(channel, center_freq, bw);

    // check getter work properly after a object was constructed
    ASSERT_EQ(wc.get_channel(), channel);
    ASSERT_EQ(wc.get_center_frequency(), center_freq);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_freq_type(), beerocks::FREQ_5G);
    ASSERT_EQ(wc.is_dfs_channel(), false);

    // check the bandwidth is set properly
    bw = beerocks::BANDWIDTH_40;
    wc.set_bandwidth(bw);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_center_frequency(),
              son::wireless_utils::channel_to_freq(channel + 2, beerocks::eFreqType::FREQ_5G));
    ASSERT_EQ(wc.is_dfs_channel(), false);

    /* check the channel and bandwidth are set properly */
    channel = 44;
    bw      = beerocks::BANDWIDTH_80;
    wc.set_channel(channel);
    wc.set_bandwidth(bw);
    ASSERT_EQ(wc.get_channel(), channel);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_center_frequency(),
              son::wireless_utils::channel_to_freq(channel - 2, beerocks::eFreqType::FREQ_5G));
    ASSERT_EQ(wc.get_ext_above_primary(), -1);
    ASSERT_EQ(wc.get_ext_above_secondary(), false);

    channel     = 116;
    center_freq = 5590;
    bw          = beerocks::BANDWIDTH_40;
    wc          = beerocks::WifiChannel(channel, center_freq, bw, true);
    ASSERT_EQ(wc.get_channel(), channel);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_center_frequency(),
              son::wireless_utils::channel_to_freq(channel + 2, beerocks::eFreqType::FREQ_5G));
    ASSERT_EQ(wc.get_ext_above_primary(), 1);
    ASSERT_EQ(wc.get_ext_above_secondary(), true);
    ASSERT_EQ(wc.is_dfs_channel(), true);
}

TEST(BeerocksWifiChannel, check_6ghz_getters_and_setters_are_valid)
{
    unsigned int channel        = 37;
    unsigned int center_freq    = 6185;
    beerocks::eWiFiBandwidth bw = beerocks::BANDWIDTH_160;

    beerocks::WifiChannel wc(channel, center_freq, bw);

    // check getter work properly after a object was constructed
    ASSERT_EQ(wc.get_channel(), channel);
    ASSERT_EQ(wc.get_center_frequency(), center_freq - 40);
    ASSERT_EQ(wc.get_center_frequency_2(), center_freq);
    ASSERT_EQ(wc.get_bandwidth(), bw);
    ASSERT_EQ(wc.get_freq_type(), beerocks::FREQ_6G);
    ASSERT_EQ(wc.is_dfs_channel(), false);
}

} // namespace
