/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_timer_manager_impl.h>
#include <bcl/network/timer_impl.h>

#include <deque>

#include <easylogging++.h>

namespace beerocks {

TimerManagerImpl::TimerManagerImpl(std::shared_ptr<TimerFactory> timer_factory,
                                   std::shared_ptr<EventLoop> event_loop)
    : m_timer_factory(timer_factory), m_event_loop(event_loop)
{
    LOG_IF(!m_timer_factory, FATAL) << "Timer factory is a null pointer!";
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";
}

TimerManagerImpl::~TimerManagerImpl()
{
    while (!m_timers.empty()) {
        int fd = m_timers.begin()->first;
        remove_timer(fd);
    }
}

int TimerManagerImpl::add_timer(std::chrono::milliseconds delay, std::chrono::milliseconds period,
                                const EventLoop::EventHandler &handler)
{
    // In case of error in one of the steps of this method, we have to undo all the previous steps
    // (like when rolling back a database transaction, where either all steps get executed or none
    // of them gets executed)
    std::deque<std::function<void()>> rollback_actions;
    auto rollback = [&]() {
        for (const auto &action : rollback_actions) {
            action();
        }
    };

    // 1.- Create the timer instance
    auto timer = m_timer_factory->create_instance();
    if (!timer) {
        LOG(ERROR) << "Failed to create timer instance!";
        return beerocks::net::FileDescriptor::invalid_descriptor;
    }

    // 2.- Check if timer file descriptor was successfully created
    int fd = timer->fd();
    if (beerocks::net::FileDescriptor::invalid_descriptor != fd) {
        LOG(ERROR) << "Failed to create timer descriptor!";
        return beerocks::net::FileDescriptor::invalid_descriptor;
    }

    // 3.- Register handlers for the timer in the event loop
    EventLoop::EventHandlers handlers{
        .on_read =
            [&](int fd, EventLoop &loop) {
                uint64_t number_of_expirations;
                if (timer->read(number_of_expirations)) {
                    // If a timer has expired more than once, it means that there is some delay in
                    // processing events, so print a warning
                    if (number_of_expirations > 1) {
                        LOG(WARNING)
                            << "Timer overrun (number of expirations: " << number_of_expirations
                            << "), fd = " << fd;
                    }

                    // Invoke the handler function
                    handler(fd, loop);
                }

                return true;
            },
    };

    if (!m_event_loop->register_handlers(fd, handlers)) {
        LOG(ERROR) << "Failed to register event handlers for the timer!, fd = " << fd;
        return beerocks::net::FileDescriptor::invalid_descriptor;
    }

    rollback_actions.emplace_front([&]() { m_event_loop->remove_handlers(fd); });

    // 4.- Schedule the timer with given frequency
    if (!timer->schedule(delay, period)) {
        LOG(ERROR) << "Failed to schedule the timer!, fd = " << fd;
        rollback();
        return beerocks::net::FileDescriptor::invalid_descriptor;
    }

    rollback_actions.emplace_front([&]() { timer->cancel(); });

    // 5.- Add the timer to the list of timers (so it can be automatically removed in destructor)
    auto result = m_timers.emplace(fd, std::move(timer));
    if (!result.second) {
        LOG(ERROR) << "Failed to add timer to the timers map!, fd = " << fd;
        rollback();
        return beerocks::net::FileDescriptor::invalid_descriptor;
    }

    return fd;
}

bool TimerManagerImpl::remove_timer(int fd)
{
    auto it = m_timers.find(fd);
    if (m_timers.end() == it) {
        LOG(ERROR) << "Timer not found!, fd = " << fd;
        return false;
    }

    auto &timer = it->second;

    if (!timer->cancel()) {
        LOG(ERROR) << "Failed to cancel timer!, fd = " << fd;
    }

    if (!m_event_loop->remove_handlers(fd)) {
        LOG(ERROR) << "Failed to remove handlers for the timer!, fd = " << fd;
    }

    if (0 == m_timers.erase(fd)) {
        LOG(ERROR) << "Failed to remove timer from the map!, fd = " << fd;
    }

    return true;
}

} // namespace beerocks
