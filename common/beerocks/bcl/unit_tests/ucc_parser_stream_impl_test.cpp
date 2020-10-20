/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_ucc_parser_stream_impl.h>

#include <bcl/network/buffer_mock.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;

namespace {

TEST(UccParserStreamImplTest, parse_command_should_fail_without_trailer)
{
    StrictMock<beerocks::net::BufferMock> buffer;
    std::string command;

    beerocks::UccParserStreamImpl parser;

    // Command is not ended with a trailer character
    uint8_t data[]{'h', 'e', 'l', 'l', 'o'};
    size_t length = sizeof(data);

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));

        // Buffer is not full
        EXPECT_CALL(buffer, size()).WillOnce(Return(length + 1));
    }

    ASSERT_FALSE(parser.parse_command(buffer, command));
}

TEST(UccParserStreamImplTest, parse_command_should_fail_without_trailer_and_buffer_full)
{
    StrictMock<beerocks::net::BufferMock> buffer;
    std::string command;

    beerocks::UccParserStreamImpl parser;

    // Command is not ended with a trailer character
    uint8_t data[]{'h', 'e', 'l', 'l', 'o'};
    size_t length = sizeof(data);

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));

        // Buffer is full
        EXPECT_CALL(buffer, size()).WillOnce(Return(length));
        EXPECT_CALL(buffer, clear()).Times(1);
    }

    ASSERT_FALSE(parser.parse_command(buffer, command));
}

TEST(UccParserStreamImplTest, parse_command_should_succeed)
{
    StrictMock<beerocks::net::BufferMock> buffer;
    std::string command;

    beerocks::UccParserStreamImpl parser;

    // Command is ended with a trailer character
    uint8_t data[]{'h', 'e', 'l', 'l', 'o', '\n'};
    size_t length = sizeof(data);

    {
        InSequence sequence;

        EXPECT_CALL(buffer, length()).WillOnce(ReturnRef(length));
        EXPECT_CALL(buffer, data()).WillOnce(Return(data));

        EXPECT_CALL(buffer, shift(length)).Times(1);
    }

    ASSERT_TRUE(parser.parse_command(buffer, command));
    ASSERT_EQ(reinterpret_cast<const char *>(data), command);
}
} // namespace
