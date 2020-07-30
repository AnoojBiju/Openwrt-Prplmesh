/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_SOCKET_EVENT_LOOP_H_
#define _BEEROCKS_SOCKET_EVENT_LOOP_H_

#include "beerocks_event_loop.h"
#include "network/socket.h"

#include <chrono>
#include <memory>
#include <unordered_map>

namespace beerocks {

/**
 * @brief ePoll based implementation of the EventLoop interface.
 * @see EventLoop
 * 
 * This class uses the Linux epoll APIs for monitoring the provided sockets for I/O operations.
 */
class SocketEventLoop : public EventLoop<std::shared_ptr<Socket>> {
public:
    /**
     * @brief Class constructor.
     * 
     * Initializes an epoll file descriptor.
     * 
     * @param [in] timeout Sets the master timeout (in milliseconds) for the event loop.
     */
    explicit SocketEventLoop(std::chrono::milliseconds timeout = std::chrono::milliseconds::min());

    /**
     * @brief Class destructor.
     */
    virtual ~SocketEventLoop();

    /**
     * @see EventPoll::add_event
     */
    virtual bool add_event(EventType socket, EventHandlers handlers) override;

    /**
     * @see EventPoll::del_event
     */
    virtual bool del_event(EventType socket) override;

    /**
     * @brief Main event loop method.
     * @see EventPoll::run
     * 
     * Executes the epoll_wait() function and processes ocurred events.
     */
    virtual int run() override;

private:
    /**
     * epoll file descriptor.
     */
    int m_epoll_fd = -1;

    /**
     * Event loop master timeout (used for the epoll_wait function).
     */
    std::chrono::milliseconds m_timeout = std::chrono::milliseconds::min();

    /**
     * @brief Data structure representing a socket added to the poll.
     * This structure groups all the information required for processing socket events.
     */
    struct EventData {
        /**
         * Socket event handler functions structure.
         */
        EventHandlers handlers;

        /**
         * Shared pointer to the socket object.
         */
        EventType socket = nullptr;
    };

    /**
     * Map file descriptors to EventData structure instances.
     */
    std::unordered_map<int, std::shared_ptr<EventData>> m_fd_to_event_data;
};

} // namespace beerocks

#endif // _BEEROCKS_SOCKET_EVENT_LOOP_H_
