/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_BRIDGE_STATUS_MONITOR_IMPL_H_
#define BCL_NETWORK_BRIDGE_STATUS_MONITOR_IMPL_H_

#include "bridge_status_monitor.h"
#include "buffer_impl.h"
#include "sockets_impl.h"

#include <memory>

namespace beerocks {

class EventLoop;

namespace net {

class BridgeStatusMonitorImpl : public BridgeStatusMonitor {
    static constexpr size_t netlink_buffer_size = 8192;

public:
    /**
     * @brief Class constructor
     *
     * @param connection Netlink socket connection for kernel/user-space communication.
     * @param event_loop Event loop to wait for I/O events.
     */
    BridgeStatusMonitorImpl(const std::shared_ptr<Socket::Connection> &connection,
                            const std::shared_ptr<EventLoop> &event_loop);

    /**
     * @brief Class destructor
     */
    ~BridgeStatusMonitorImpl() override;

private:
    /**
     * Buffer to hold data received through socket connection
     */
    BufferImpl<netlink_buffer_size> m_buffer;

    /**
     * Socket connection through which bridge status information is received.
     */
    std::shared_ptr<Socket::Connection> m_connection;

    /**
     * Application event loop used by the monitor to wait for I/O events.
     */
    std::shared_ptr<EventLoop> m_event_loop;

    /**
     * @brief Parses data received through the Netlink socket connection.
     *
     * The array of bytes contains a list of Netlink messages.
     *
     * @param buffer Buffer with the array of netlink messages to parse.
     */
    void parse(const Buffer &buffer) const;

    /**
     * @brief Parses message received through the Netlink socket connection.
     *
     * If the type of the Netlink message is RTM_NEWLINK or RTM_DELLINK then reads the interface
     * index and the IFLA_MASTER attribute and then notifies a change in the bridge status.
     *
     * @param msg_hdr Netlink message to parse.
     */
    void parse(const nlmsghdr *msg_hdr) const;
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_BRIDGE_STATUS_MONITOR_IMPL_H_ */
