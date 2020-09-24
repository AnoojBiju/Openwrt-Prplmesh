/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/cmdu_parser_stream_impl.h>

#include <bcl/beerocks_backport.h>
#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_message_structs.h>
#include <bcl/network/buffer_mock.h>
#include <bcl/network/net_struct.h>

#include <tlvf/CmduMessageTx.h>
#include <tlvf/ieee_1905_1/eMessageType.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;

namespace {

constexpr size_t size_of_uds_header = sizeof(beerocks::message::sUdsHeader);

class cmdu_parser_stream_impl : public ::testing::Test {
protected:
    cmdu_parser_stream_impl() : cmdu_rx(rx_buffer, sizeof(rx_buffer)) {}

    uint32_t iface_index = 0;
    sMacAddr dst_mac;
    sMacAddr src_mac;

    uint8_t rx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageRx cmdu_rx;

    StrictMock<beerocks::net::BufferMock> buffer;

    beerocks::net::CmduParserStreamImpl parser;
};

TEST_F(cmdu_parser_stream_impl, parse_cmdu_should_fail_with_incomplete_header)
{
    // Header is not complete
    const size_t length = size_of_uds_header - 1;

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
    }

    ASSERT_FALSE(parser.parse_cmdu(buffer, iface_index, dst_mac, src_mac, cmdu_rx));
}

TEST_F(cmdu_parser_stream_impl, parse_cmdu_should_fail_with_incomplete_message)
{
    beerocks::message::sUdsHeader uds_header;
    uds_header.length = 1;

    // Only the header has been received
    const size_t length = size_of_uds_header;

    uint8_t data[size_of_uds_header + uds_header.length];
    std::copy_n(reinterpret_cast<uint8_t *>(&uds_header), size_of_uds_header, data);
    std::fill_n(data + size_of_uds_header, uds_header.length, 0);

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));
    }

    ASSERT_FALSE(parser.parse_cmdu(buffer, iface_index, dst_mac, src_mac, cmdu_rx));
}

TEST_F(cmdu_parser_stream_impl, parse_cmdu_should_fail_with_invalid_message)
{
    beerocks::message::sUdsHeader uds_header;
    uds_header.length = 1;

    // Message is invalid (one byte length only)
    const size_t length = size_of_uds_header + uds_header.length;

    uint8_t data[size_of_uds_header + uds_header.length];
    std::copy_n(reinterpret_cast<uint8_t *>(&uds_header), size_of_uds_header, data);
    std::fill_n(data + size_of_uds_header, uds_header.length, 0);

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));
        EXPECT_CALL(buffer, shift(length)).Times(1);
    }

    ASSERT_FALSE(parser.parse_cmdu(buffer, iface_index, dst_mac, src_mac, cmdu_rx));
}

TEST_F(cmdu_parser_stream_impl, parse_cmdu_should_succeed)
{
    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));

    cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_QUERY_MESSAGE);
    cmdu_tx.finalize();

    const uint32_t expected_iface_index = 1;
    const sMacAddr expected_dst_mac     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    const sMacAddr expected_src_mac     = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};

    beerocks::message::sUdsHeader uds_header;
    uds_header.if_index = expected_iface_index;
    std::copy_n(expected_dst_mac.oct, beerocks::net::MAC_ADDR_LEN, uds_header.dst_bridge_mac);
    std::copy_n(expected_src_mac.oct, beerocks::net::MAC_ADDR_LEN, uds_header.src_bridge_mac);
    uds_header.length = cmdu_tx.getMessageLength();

    const size_t length = size_of_uds_header + uds_header.length;

    uint8_t data[size_of_uds_header + uds_header.length];
    std::copy_n(reinterpret_cast<uint8_t *>(&uds_header), size_of_uds_header, data);
    std::copy_n(tx_buffer, uds_header.length, data + size_of_uds_header);

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));
        EXPECT_CALL(buffer, shift(length)).Times(1);
    }

    ASSERT_TRUE(parser.parse_cmdu(buffer, iface_index, dst_mac, src_mac, cmdu_rx));
    ASSERT_EQ(iface_index, expected_iface_index);
    ASSERT_EQ(dst_mac, expected_dst_mac);
    ASSERT_EQ(src_mac, expected_src_mac);
    ASSERT_EQ(cmdu_tx.getMessageType(), cmdu_rx.getMessageType());
}
} // namespace
