/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_timer_manager_impl.h>

#include <bcl/beerocks_event_loop_mock.h>
#include <bcl/beerocks_timer_factory_mock.h>
#include <bcl/network/timer_mock.h>

#include <gtest/gtest.h>

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace {

class TimerManagerImplTest : public ::testing::Test {
protected:
    std::shared_ptr<StrictMock<beerocks::TimerFactoryMock>> m_timer_factory =
        std::make_shared<StrictMock<beerocks::TimerFactoryMock>>();
    std::shared_ptr<StrictMock<beerocks::EventLoopMock>> m_event_loop =
        std::make_shared<StrictMock<beerocks::EventLoopMock>>();
};

TEST_F(TimerManagerImplTest, add_timer_should_succeed)
{
    auto timer = new StrictMock<beerocks::net::TimerMock<>>();

    constexpr int timer_fd = 1;
    constexpr auto delay   = std::chrono::milliseconds(1);
    constexpr auto period  = std::chrono::milliseconds(2);

    beerocks::EventLoop::EventHandlers timer_handlers;

    ON_CALL(*timer, fd()).WillByDefault(Return(timer_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_timer_factory, create_instance_proxy()).WillOnce(Return(timer));
        EXPECT_CALL(*timer, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(timer_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&timer_handlers), Return(true)));
        EXPECT_CALL(*timer, schedule(delay, period)).WillOnce(Return(true));

        EXPECT_CALL(*timer, read(_)).WillOnce(Invoke([](uint64_t &number_of_expirations) {
            number_of_expirations = 0;
            return true;
        }));

        EXPECT_CALL(*timer, cancel()).WillOnce(Return(true));
        EXPECT_CALL(*m_event_loop, remove_handlers(timer_fd)).WillOnce(Return(true));
    }

    beerocks::TimerManagerImpl timer_manager(m_timer_factory, m_event_loop);

    uint32_t count                            = 0;
    beerocks::EventLoop::EventHandler handler = [&](int fd, beerocks::EventLoop &loop) {
        count++;
        return true;
    };

    ASSERT_EQ(timer_fd, timer_manager.add_timer(delay, period, handler));

    // Emulate the timer has elapsed
    timer_handlers.on_read(timer_fd, *m_event_loop);

    ASSERT_TRUE(timer_manager.remove_timer(timer_fd));
    ASSERT_EQ(1U, count);
}

TEST_F(TimerManagerImplTest, remove_timer_should_fail_with_unknown_socket_fd)
{
    constexpr int unknown_socket_fd = 2;

    beerocks::TimerManagerImpl timer_manager(m_timer_factory, m_event_loop);

    ASSERT_FALSE(timer_manager.remove_timer(unknown_socket_fd));
}

TEST_F(TimerManagerImplTest, destructor_should_remove_remaining_timers)
{
    auto timer = new StrictMock<beerocks::net::TimerMock<>>();

    constexpr int timer_fd = 1;
    constexpr auto delay   = std::chrono::milliseconds(1);
    constexpr auto period  = std::chrono::milliseconds(2);

    ON_CALL(*timer, fd()).WillByDefault(Return(timer_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_timer_factory, create_instance_proxy()).WillOnce(Return(timer));
        EXPECT_CALL(*timer, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(timer_fd, _)).WillOnce(Return(true));
        EXPECT_CALL(*timer, schedule(delay, period)).WillOnce(Return(true));

        EXPECT_CALL(*timer, cancel()).WillOnce(Return(true));
        EXPECT_CALL(*m_event_loop, remove_handlers(timer_fd)).WillOnce(Return(true));
    }

    beerocks::TimerManagerImpl timer_manager(m_timer_factory, m_event_loop);

    uint32_t count                            = 0;
    beerocks::EventLoop::EventHandler handler = [&](int fd, beerocks::EventLoop &loop) {
        count++;
        return true;
    };

    // Add timer but do not explicitly remove it.
    // If timer has not been explicitly removed at the time destructor is executed then destructor
    // has to do it
    ASSERT_EQ(timer_fd, timer_manager.add_timer(delay, period, handler));

    ASSERT_EQ(0U, count);
}

} // namespace
