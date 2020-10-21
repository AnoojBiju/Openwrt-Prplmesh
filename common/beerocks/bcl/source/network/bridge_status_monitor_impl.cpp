/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_event_loop.h>
#include <bcl/network/bridge_status_monitor_impl.h>

#include <net/if.h>

using namespace beerocks;

namespace beerocks {
namespace net {

BridgeStatusMonitorImpl::BridgeStatusMonitorImpl(
    const std::shared_ptr<Socket::Connection> &connection,
    const std::shared_ptr<EventLoop> &event_loop)
    : m_connection(connection), m_event_loop(event_loop)
{
    EventLoop::EventHandlers handlers;
    handlers.on_read = [&](int fd, EventLoop &loop) -> bool {
        if (m_connection->receive(m_buffer) > 0) {
            parse(m_buffer);
        }

        return true;
    };

    m_event_loop->register_handlers(m_connection->socket()->fd(), handlers);
}

BridgeStatusMonitorImpl::~BridgeStatusMonitorImpl()
{
    m_event_loop->remove_handlers(m_connection->socket()->fd());
}

void BridgeStatusMonitorImpl::parse(const Buffer &buffer) const
{
    const nlmsghdr *msg_hdr = reinterpret_cast<const nlmsghdr *>(buffer.data());
    size_t length           = buffer.length();
    while (NLMSG_OK(msg_hdr, length)) {
        parse(msg_hdr);
        msg_hdr = NLMSG_NEXT(msg_hdr, length);
    }
}

void BridgeStatusMonitorImpl::parse(const nlmsghdr *msg_hdr) const
{
    switch (msg_hdr->nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
        const ifinfomsg *ifi = static_cast<const ifinfomsg *>(NLMSG_DATA(msg_hdr));

        if ((ifi->ifi_family != AF_BRIDGE) && (ifi->ifi_family != AF_UNSPEC)) {
            break;
        }

        int length = msg_hdr->nlmsg_len;
        length -= NLMSG_LENGTH(sizeof(ifinfomsg));
        if (length < 0) {
            break;
        }

        for (const rtattr *attribute = IFLA_RTA(ifi); RTA_OK(attribute, length);
             attribute               = RTA_NEXT(attribute, length)) {
            switch (attribute->rta_type) {
            case IFLA_MASTER:
                uint32_t bridge_index = *reinterpret_cast<uint32_t *>(RTA_DATA(attribute));
                char bridge_name[IFNAMSIZ]{};

                uint32_t iface_index = ifi->ifi_index;
                char iface_name[IFNAMSIZ]{};

                if ((0 != if_indextoname(bridge_index, bridge_name)) &&
                    (0 != if_indextoname(iface_index, iface_name))) {
                    notify_status_changed(bridge_name, iface_name,
                                          (msg_hdr->nlmsg_type == RTM_NEWLINK));
                    return;
                }
                break;
            }
        }

        break;
    }
}

} // namespace net
} // namespace beerocks
