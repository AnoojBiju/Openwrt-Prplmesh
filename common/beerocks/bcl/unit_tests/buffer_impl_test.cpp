/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/buffer_impl.h>

#include <gtest/gtest.h>

namespace {
constexpr size_t buffer_size = 16;

class buffer_impl : public ::testing::Test {
protected:
    void fill_buffer_with_test_data(beerocks::net::Buffer &buffer)
    {
        uint8_t *data = buffer.data();
        for (size_t i = 0; i < buffer.size(); i++) {
            data[i] = i;
        }
        buffer.length() = buffer.size();
    }

    beerocks::net::BufferImpl<buffer_size> buffer;
};

TEST_F(buffer_impl, clear_should_succeed)
{
    fill_buffer_with_test_data(buffer);

    buffer.clear();

    for (size_t i = 0; i < buffer.size(); i++) {
        ASSERT_EQ(0, buffer.data()[i]);
    }
}

TEST_F(buffer_impl, shift_should_succeed)
{
    fill_buffer_with_test_data(buffer);

    const size_t count = 1;
    ASSERT_TRUE(buffer.shift(count));

    ASSERT_EQ(buffer.length(), buffer.size() - count);
    for (size_t i = 0; i < buffer.size(); i++) {
        if (i < (buffer.size() - count)) {
            ASSERT_EQ(i + count, buffer.data()[i]);
        } else {
            ASSERT_EQ(0, buffer.data()[i]);
        }
    }
}

TEST_F(buffer_impl, shift_should_fail_if_count_greater_than_length)
{
    fill_buffer_with_test_data(buffer);

    const size_t count = buffer.length() + 1;
    ASSERT_FALSE(buffer.shift(count));
}
} // namespace
