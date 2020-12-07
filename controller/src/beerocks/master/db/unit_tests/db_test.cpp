/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_event_loop_mock.h>

#include "ambiorix_mock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "../db.h"

using ::testing::_;
using ::testing::Matcher;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrEq;
using ::testing::StrictMock;

namespace {

constexpr auto g_device_path                = "Controller.Network.Device";
constexpr auto g_controller_data_model_path = "config/odl/controller.odl";
constexpr auto g_bridge_mac                 = "46:55:66:77:00:00";
constexpr auto g_radio_mac_1                = "46:55:66:77:00:21";
constexpr auto g_radio_mac_2                = "46:55:66:77:00:22";
constexpr auto g_radio_identifier           = "46:55:66:77:00:02";
constexpr auto g_vap_id_1                   = 1;
constexpr auto g_bssid_1                    = "46:55:66:77:00:03";
constexpr auto g_ssid_1                     = "dummy_ssid";

class DbTest : public ::testing::Test {

protected:
    std::shared_ptr<StrictMock<beerocks::nbapi::AmbiorixMock>> m_ambiorix;
    std::shared_ptr<son::db> m_db;

private:
    void SetUp() override
    {
        m_ambiorix = std::make_shared<StrictMock<beerocks::nbapi::AmbiorixMock>>();

        beerocks::config_file::sConfigMaster beerocks_master_conf;
        son::db::sDbMasterConfig master_conf;
        beerocks::logging logger("logger", beerocks_master_conf.sLog);
        logger.set_log_level_state(beerocks::LOG_LEVEL_ERROR, true);

        m_db = std::make_shared<son::db>(master_conf, logger, g_bridge_mac, m_ambiorix);

        ASSERT_TRUE(m_db != nullptr);

        EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_bridge_mac)).WillRepeatedly(Return(0));
        EXPECT_CALL(*m_ambiorix, add_instance(g_device_path)).WillOnce(Return(1));
        EXPECT_CALL(*m_ambiorix, set(std::string(g_device_path) + ".1", "ID",
                                     Matcher<const std::string &>(g_bridge_mac)))
            .WillOnce(Return(true));

        m_db->set_prplmesh(tlvf::mac_from_string(g_bridge_mac));
    }
};

TEST_F(DbTest, dm_should_have_controller_bridge)
{
    EXPECT_TRUE(m_db->has_node(tlvf::mac_from_string(g_bridge_mac)));
}

TEST_F(DbTest, test_add_node_radio)
{
    const std::string radio_path = std::string(g_device_path) + ".1.Radio";

    //radio node and path may not exist
    EXPECT_FALSE(m_db->has_node(tlvf::mac_from_string(g_radio_mac_1)));

    EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_bridge_mac)).WillRepeatedly(Return(1));
    EXPECT_CALL(*m_ambiorix, add_instance(std::string(radio_path))).WillOnce(Return(1));
    EXPECT_CALL(*m_ambiorix, set(std::string(radio_path) + ".1", "ID",
                                 Matcher<const std::string &>(g_radio_mac_1)))
        .WillOnce(Return(true));

    //add radio node
    EXPECT_TRUE(m_db->add_node_radio(tlvf::mac_from_string(g_radio_mac_1),
                                     tlvf::mac_from_string(g_bridge_mac),
                                     tlvf::mac_from_string(g_radio_identifier)));

    //radio node and path must exist
    EXPECT_TRUE(m_db->has_node(tlvf::mac_from_string(g_radio_mac_1)));
}

TEST_F(DbTest, test_add_vap)
{
    const std::string radio_path = std::string(g_device_path) + ".1.Radio";
    const std::string bss_path   = radio_path + ".1.BSS";

    //device always exists
    EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_bridge_mac)).WillRepeatedly(Return(1));

    //BSS node and path may not exist
    EXPECT_FALSE(m_db->has_node(tlvf::mac_from_string(g_radio_mac_1)));

    //must fail because radio does not exist
    EXPECT_FALSE(m_db->add_vap(g_radio_mac_1, g_vap_id_1, g_bssid_1, g_ssid_1, false));

    //expectations for add_node_radio
    EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_radio_mac_1)).WillRepeatedly(Return(1));
    EXPECT_CALL(*m_ambiorix, add_instance(std::string(radio_path))).WillOnce(Return(1));
    EXPECT_CALL(*m_ambiorix, set(std::string(radio_path) + ".1", "ID",
                                 Matcher<const std::string &>(g_radio_mac_1)))
        .WillOnce(Return(true));

    //prepare scenario
    EXPECT_TRUE(m_db->add_node_radio(tlvf::mac_from_string(g_radio_mac_1),
                                     tlvf::mac_from_string(g_bridge_mac),
                                     tlvf::mac_from_string(g_radio_identifier)));
    EXPECT_TRUE(m_db->has_node(tlvf::mac_from_string(g_radio_mac_1)));

    //expectations for add_vap
    EXPECT_CALL(*m_ambiorix, add_instance(bss_path)).WillOnce(Return(1));

    EXPECT_CALL(*m_ambiorix,
                set(std::string(bss_path) + ".1", "BSSID", Matcher<const std::string &>(g_bssid_1)))
        .WillOnce(Return(true));

    EXPECT_CALL(*m_ambiorix,
                set(std::string(bss_path) + ".1", "SSID", Matcher<const std::string &>(g_ssid_1)))
        .WillOnce(Return(true));

    EXPECT_CALL(*m_ambiorix,
                set(std::string(bss_path) + ".1", "Enabled", Matcher<const bool &>(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix,
                set(std::string(bss_path) + ".1", "LastChange", Matcher<const uint64_t &>(_)))
        .WillOnce(Return(true));
    const std::string TimeStamp = "2020-11-26T12:52:57";
    EXPECT_CALL(*m_ambiorix, get_datamodel_time_format()).WillOnce(Return(TimeStamp));
    EXPECT_CALL(*m_ambiorix, set(std::string(bss_path) + ".1", "TimeStamp",
                                 Matcher<const std::string &>(TimeStamp)))
        .WillOnce(Return(true));

    //add virtual AP to radio
    EXPECT_TRUE(m_db->add_vap(g_radio_mac_1, g_vap_id_1, g_bssid_1, g_ssid_1, false));

    //BSS node and path must exist
    EXPECT_TRUE(m_db->has_node(tlvf::mac_from_string(g_bssid_1)));
}

TEST_F(DbTest, test_set_ap_ht_capabilities)
{
    const std::string radio_path_1     = std::string(g_device_path) + ".1.Radio.1";
    const std::string radio_path_2     = std::string(g_device_path) + ".1.Radio.2";
    const std::string capabilities1    = radio_path_1 + ".Capabilities";
    const std::string capabilities2    = radio_path_2 + ".Capabilities";
    const std::string ht_capabilities1 = capabilities1 + ".HTCapabilities";
    const std::string ht_capabilities2 = capabilities2 + ".HTCapabilities";

    wfa_map::tlvApHtCapabilities::sFlags flags1    = {};
    flags1.reserved                                = 0;
    flags1.ht_support_40mhz                        = 1;
    flags1.short_gi_support_40mhz                  = 0;
    flags1.short_gi_support_20mhz                  = 1;
    flags1.max_num_of_supported_rx_spatial_streams = 2;
    flags1.max_num_of_supported_tx_spatial_streams = 3;

    wfa_map::tlvApHtCapabilities::sFlags flags2    = {};
    flags2.reserved                                = 0;
    flags2.ht_support_40mhz                        = 0;
    flags2.short_gi_support_40mhz                  = 1;
    flags2.short_gi_support_20mhz                  = 0;
    flags2.max_num_of_supported_rx_spatial_streams = 1;
    flags2.max_num_of_supported_tx_spatial_streams = 2;

    //device always exists
    EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_bridge_mac)).WillRepeatedly(Return(1));

    //cannot set capabilities to not existent radio
    EXPECT_FALSE(m_db->set_ap_ht_capabilities(tlvf::mac_from_string(g_radio_mac_1), flags1));
    EXPECT_FALSE(m_db->set_ap_ht_capabilities(tlvf::mac_from_string(g_radio_mac_2), flags2));

    //expectations for add_node_radios
    EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_radio_mac_1)).WillRepeatedly(Return(1));
    EXPECT_CALL(*m_ambiorix, get_instance_index(_, g_radio_mac_2)).WillRepeatedly(Return(2));
    EXPECT_CALL(*m_ambiorix, add_instance(std::string(g_device_path) + ".1.Radio"))
        .WillOnce(Return(1))
        .WillOnce(Return(2));
    EXPECT_CALL(*m_ambiorix,
                set(std::string(radio_path_1), "ID", Matcher<const std::string &>(g_radio_mac_1)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix,
                set(std::string(radio_path_2), "ID", Matcher<const std::string &>(g_radio_mac_2)))
        .WillOnce(Return(true));

    //prepare scenario
    EXPECT_TRUE(m_db->add_node_radio(tlvf::mac_from_string(g_radio_mac_1),
                                     tlvf::mac_from_string(g_bridge_mac),
                                     tlvf::mac_from_string(g_radio_identifier)));
    EXPECT_TRUE(m_db->add_node_radio(tlvf::mac_from_string(g_radio_mac_2),
                                     tlvf::mac_from_string(g_bridge_mac),
                                     tlvf::mac_from_string(g_radio_identifier)));

    // expectations for set_ap_ht_capabilities
    EXPECT_CALL(*m_ambiorix, add_optional_subobject(capabilities1, "HTCapabilities"))
        .WillOnce(Return(true));

    EXPECT_CALL(*m_ambiorix, add_optional_subobject(capabilities2, "HTCapabilities"))
        .WillOnce(Return(true));

    EXPECT_CALL(*m_ambiorix, set(ht_capabilities1, "GI_20_MHz", Matcher<const bool &>(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix, set(ht_capabilities1, "GI_40_MHz", Matcher<const bool &>(false)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix, set(ht_capabilities1, "HT_40_Mhz", Matcher<const bool &>(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix,
                set(ht_capabilities1, "tx_spatial_streams",
                    Matcher<const int32_t &>(flags1.max_num_of_supported_tx_spatial_streams + 1)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix,
                set(ht_capabilities1, "rx_spatial_streams",
                    Matcher<const int32_t &>(flags1.max_num_of_supported_rx_spatial_streams + 1)))
        .WillOnce(Return(true));

    EXPECT_CALL(*m_ambiorix, set(ht_capabilities2, "GI_20_MHz", Matcher<const bool &>(false)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix, set(ht_capabilities2, "GI_40_MHz", Matcher<const bool &>(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix, set(ht_capabilities2, "HT_40_Mhz", Matcher<const bool &>(false)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix,
                set(ht_capabilities2, "tx_spatial_streams",
                    Matcher<const int32_t &>(flags2.max_num_of_supported_tx_spatial_streams + 1)))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_ambiorix,
                set(ht_capabilities2, "rx_spatial_streams",
                    Matcher<const int32_t &>(flags2.max_num_of_supported_rx_spatial_streams + 1)))
        .WillOnce(Return(true));

    //execute test
    EXPECT_TRUE(m_db->set_ap_ht_capabilities(tlvf::mac_from_string(g_radio_mac_1), flags1));
    EXPECT_TRUE(m_db->set_ap_ht_capabilities(tlvf::mac_from_string(g_radio_mac_2), flags2));
}

} // namespace
