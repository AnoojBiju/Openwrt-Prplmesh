/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/cmdu_serializer_stream_impl.h>

#include <bcl/network/buffer_mock.h>
#include <bcl/network/network_utils.h>

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

class cmdu_serializer_stream_impl : public ::testing::Test {
protected:
    StrictMock<beerocks::net::BufferMock> buffer;

    beerocks::net::CmduSerializerStreamImpl serializer;
};

TEST_F(cmdu_serializer_stream_impl, serialize_cmdu_should_fail_with_invalid_cmdu)
{
    sMacAddr dst_mac = beerocks::net::network_utils::ZERO_MAC;
    sMacAddr src_mac = beerocks::net::network_utils::ZERO_MAC;

    // Invalid CMDU
    ieee1905_1::CmduMessageTx cmdu_tx(nullptr, 0);

    ASSERT_FALSE(serializer.serialize_cmdu(dst_mac, src_mac, cmdu_tx, buffer));
}

TEST_F(cmdu_serializer_stream_impl, serialize_cmdu_should_fail_with_invalid_src_mac)
{
    // Invalid parameters: destination MAC address is given but source MAC address is not
    sMacAddr dst_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    sMacAddr src_mac = beerocks::net::network_utils::ZERO_MAC;

    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));

    cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_QUERY_MESSAGE);

    ASSERT_FALSE(serializer.serialize_cmdu(dst_mac, src_mac, cmdu_tx, buffer));
}

TEST_F(cmdu_serializer_stream_impl, serialize_cmdu_should_fail_with_buffer_too_small)
{
    sMacAddr dst_mac = beerocks::net::network_utils::ZERO_MAC;
    sMacAddr src_mac = beerocks::net::network_utils::ZERO_MAC;

    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));

    cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_QUERY_MESSAGE);

    // Buffer size is too small (there is no room for the message payload, only for the header)
    size_t size = size_of_uds_header;

    {
        InSequence sequence;

        EXPECT_CALL(buffer, size()).WillOnce(Return(size));
    }

    ASSERT_FALSE(serializer.serialize_cmdu(dst_mac, src_mac, cmdu_tx, buffer));
}

TEST_F(cmdu_serializer_stream_impl, serialize_cmdu_should_succeed)
{
    sMacAddr dst_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    sMacAddr src_mac = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};

    uint8_t tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx cmdu_tx(tx_buffer, sizeof(tx_buffer));

    cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_QUERY_MESSAGE);

    size_t size = size_of_uds_header + beerocks::message::MESSAGE_BUFFER_LENGTH;
    uint8_t data[size]{};
    size_t length = 0;

    {
        InSequence sequence;

        EXPECT_CALL(buffer, size()).WillOnce(Return(size));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));
        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
    }

    ASSERT_TRUE(serializer.serialize_cmdu(dst_mac, src_mac, cmdu_tx, buffer));

    const size_t expected_length = size_of_uds_header + cmdu_tx.getMessageLength();
    ASSERT_EQ(length, expected_length);

    auto uds_header = reinterpret_cast<beerocks::message::sUdsHeader *>(data);
    ASSERT_EQ(0, memcmp(dst_mac.oct, uds_header->dst_bridge_mac, beerocks::net::MAC_ADDR_LEN));
    ASSERT_EQ(0, memcmp(src_mac.oct, uds_header->src_bridge_mac, beerocks::net::MAC_ADDR_LEN));
    ASSERT_EQ(uds_header->length, cmdu_tx.getMessageLength());
}

} // namespace
