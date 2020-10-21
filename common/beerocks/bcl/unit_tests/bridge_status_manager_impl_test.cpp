/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/bridge_status_manager_impl.h>
#include <bcl/network/bridge_status_monitor_mock.h>
#include <bcl/network/bridge_status_reader_mock.h>

#include <bcl/beerocks_backport.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;

/**
 * In this test, there is no bridge status information cached yet so it is obtained with an explicit
 * read using the bridge status reader.
 */
TEST(BridgeStatusManagerImpl, read_status_should_succeed_before_read)
{
    auto monitor = std::make_unique<StrictMock<beerocks::net::BridgeStatusMonitorMock>>();
    auto reader  = std::make_unique<StrictMock<beerocks::net::BridgeStatusReaderMock>>();

    const char *bridge_name = "test_bridge";
    std::set<std::string> expected_iface_names{"test_iface_0", "test_iface_1", "test_iface_2"};
    std::set<std::string> actual_iface_names;

    EXPECT_CALL(*reader, read_status(bridge_name, _))
        .WillOnce(
            Invoke([&](const std::string &bridge_name, std::set<std::string> &iface_names) -> bool {
                iface_names = expected_iface_names;
                return true;
            }));

    beerocks::net::BridgeStatusManagerImpl bridge_status_manager(std::move(monitor),
                                                                 std::move(reader));

    ASSERT_TRUE(bridge_status_manager.read_status(bridge_name, actual_iface_names));
    ASSERT_EQ(actual_iface_names, expected_iface_names);
}

/**
 * This test demonstrates that bridge status is cached and only one explicit read is performed
 * using the bridge status reader no matter how many times it is queried.
 */
TEST(BridgeStatusManagerImpl, read_status_should_succeed_after_read)
{
    auto monitor = std::make_unique<StrictMock<beerocks::net::BridgeStatusMonitorMock>>();
    auto reader  = std::make_unique<StrictMock<beerocks::net::BridgeStatusReaderMock>>();

    const char *bridge_name = "test_bridge";
    std::set<std::string> expected_iface_names{"test_iface_0", "test_iface_1", "test_iface_2"};
    std::set<std::string> actual_iface_names;

    EXPECT_CALL(*reader, read_status(bridge_name, _))
        .WillOnce(
            Invoke([&](const std::string &bridge_name, std::set<std::string> &iface_names) -> bool {
                iface_names = expected_iface_names;
                return true;
            }));

    beerocks::net::BridgeStatusManagerImpl bridge_status_manager(std::move(monitor),
                                                                 std::move(reader));

    ASSERT_TRUE(bridge_status_manager.read_status(bridge_name, actual_iface_names));
    ASSERT_EQ(actual_iface_names, expected_iface_names);

    ASSERT_TRUE(bridge_status_manager.read_status(bridge_name, actual_iface_names));
    ASSERT_EQ(actual_iface_names, expected_iface_names);
}

TEST(BridgeStatusManagerImpl, notify_status_changed_should_succeed)
{
    auto monitor = std::make_unique<StrictMock<beerocks::net::BridgeStatusMonitorMock>>();
    auto reader  = std::make_unique<StrictMock<beerocks::net::BridgeStatusReaderMock>>();

    const char *bridge_name = "test_bridge";
    const char *iface_name  = "test_iface";
    std::set<std::string> initial_iface_names{"test_iface_0", "test_iface_1", "test_iface_2"};
    std::set<std::string> updated_iface_names = initial_iface_names;
    updated_iface_names.emplace(iface_name);
    std::set<std::string> iface_names;

    EXPECT_CALL(*reader, read_status(bridge_name, _))
        .WillOnce(
            Invoke([&](const std::string &bridge_name, std::set<std::string> &iface_names) -> bool {
                iface_names = initial_iface_names;
                return true;
            }));

    // The monitor mock is needed to emulate that a status-changed event has occurred.
    // Since the unique_ptr to the monitor mock is moved into the bridge status manager, it
    // is not available later. To overcome this problem, we use the raw pointer instead.
    auto monitor_raw_ptr = monitor.get();

    beerocks::net::BridgeStatusManagerImpl bridge_status_manager(std::move(monitor),
                                                                 std::move(reader));

    bridge_status_manager.set_handler(
        [&](const std::string &bridge_name, const std::string &iface_name, bool iface_status) {
            if (iface_status) {
                iface_names.emplace(iface_name);
            } else {
                iface_names.erase(iface_name);
            }
        });

    ASSERT_TRUE(bridge_status_manager.read_status(bridge_name, iface_names));
    ASSERT_EQ(iface_names, initial_iface_names);

    // Emulate that a new interface is added to the bridge
    monitor_raw_ptr->notify_status_changed(bridge_name, iface_name, true);
    ASSERT_NE(std::find(iface_names.begin(), iface_names.end(), iface_name), iface_names.end());

    // Verify that cache has been updated and now it contains the new interface
    ASSERT_TRUE(bridge_status_manager.read_status(bridge_name, iface_names));
    ASSERT_EQ(iface_names, updated_iface_names);

    // Emulate that an existing interface is removed from the bridge
    monitor_raw_ptr->notify_status_changed(bridge_name, iface_name, false);
    ASSERT_EQ(std::find(iface_names.begin(), iface_names.end(), iface_name), iface_names.end());

    // Verify that cache has been updated and now it does not contain the removed interface
    ASSERT_TRUE(bridge_status_manager.read_status(bridge_name, iface_names));
    ASSERT_EQ(iface_names, initial_iface_names);
}
