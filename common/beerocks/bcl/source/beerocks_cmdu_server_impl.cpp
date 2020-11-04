/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_cmdu_server_impl.h>

#include <bcl/network/network_utils.h>
#include <bcl/network/sockets_impl.h>

#include <easylogging++.h>

namespace beerocks {

CmduServerImpl::CmduServerImpl(std::unique_ptr<beerocks::net::ServerSocket> server_socket,
                               std::shared_ptr<beerocks::net::CmduParser> cmdu_parser,
                               std::shared_ptr<beerocks::net::CmduSerializer> cmdu_serializer,
                               std::shared_ptr<beerocks::EventLoop> event_loop)
    : m_server_socket(std::move(server_socket)), m_cmdu_parser(cmdu_parser),
      m_cmdu_serializer(cmdu_serializer), m_event_loop(event_loop)
{
    LOG_IF(!m_server_socket, FATAL) << "Server socket is a null pointer!";
    LOG_IF(!m_cmdu_parser, FATAL) << "CMDU parser is a null pointer!";
    LOG_IF(!m_cmdu_serializer, FATAL) << "CMDU serializer is a null pointer!";
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";

    // Register event handlers for the server socket
    beerocks::EventLoop::EventHandlers handlers{
        // Accept incoming connections
        .on_read =
            [&](int fd, EventLoop &loop) {
                handle_connect(fd);
                return true;
            },

        // Not implemented
        .on_write = nullptr,

        // Fail on server socket disconnection or error
        .on_disconnect =
            [&](int fd, EventLoop &loop) {
                LOG(ERROR) << "Server socket disconnected!";
                return false;
            },
        .on_error =
            [&](int fd, EventLoop &loop) {
                LOG(ERROR) << "Server socket error!";
                return false;
            },
    };

    LOG_IF(!m_event_loop->register_handlers(m_server_socket->socket()->fd(), handlers), FATAL)
        << "Failed to register event handlers for the server socket!";
}

CmduServerImpl::~CmduServerImpl()
{
    // Remove all connections and their installed event handlers
    while (m_connections.size() > 0) {
        const auto &it = m_connections.begin();

        int fd = it->first;

        if (!remove_connection(fd, true)) {
            m_connections.erase(it);
        }
    }

    // Remove installed event handlers for the server socket
    m_event_loop->remove_handlers(m_server_socket->socket()->fd());
}

bool CmduServerImpl::disconnect(int fd)
{
    // Find context information for given socket connection
    auto it = m_connections.find(fd);
    if (m_connections.end() == it) {
        LOG(ERROR) << "Failed to close an unknown connection! fd = " << fd;
        return false;
    }

    return remove_connection(fd, true);
}

bool CmduServerImpl::send_cmdu(int fd, ieee1905_1::CmduMessageTx &cmdu_tx)
{
    // Find context information for given socket connection
    auto it = m_connections.find(fd);
    if (m_connections.end() == it) {
        LOG(ERROR) << "Failed to send CMDU through an unknown connection! fd = " << fd;
        return false;
    }

    auto &context = it->second;

    // Serialize CMDU into a byte array
    sMacAddr dst_mac = beerocks::net::network_utils::ZERO_MAC;
    sMacAddr src_mac = beerocks::net::network_utils::ZERO_MAC;
    beerocks::net::BufferImpl<message::MESSAGE_BUFFER_LENGTH> buffer;
    if (!m_cmdu_serializer->serialize_cmdu(dst_mac, src_mac, cmdu_tx, buffer)) {
        LOG(ERROR) << "Failed to serialize CMDU! fd = " << fd;
        return false;
    }

    // Send data
    return context.connection->send(buffer);
}

bool CmduServerImpl::add_connection(int fd,
                                    std::unique_ptr<beerocks::net::Socket::Connection> connection,
                                    const beerocks::EventLoop::EventHandlers &handlers)
{
    // LOG(DEBUG) << "Adding new connection, fd = " << fd;

    // Register event handlers for the connected socket
    if (!m_event_loop->register_handlers(fd, handlers)) {
        LOG(ERROR) << "Failed to register event handlers for the accepted socket! fd = " << fd;
        return false;
    }

    // Add a new connection to the map of current connections.
    auto result = m_connections.emplace(fd, sConnectionContext(std::move(connection)));
    LOG_IF(!result.second, FATAL) << "File descriptor was already in the connections map! fd = "
                                  << fd;

    // Notify that a new client has connected to this server
    notify_client_connected(fd);

    return true;
}

bool CmduServerImpl::remove_connection(int fd, bool remove_handlers)
{
    // LOG(DEBUG) << "Removing connection, fd = " << fd;

    // Find context information for given socket connection
    auto it = m_connections.find(fd);
    if (m_connections.end() == it) {
        LOG(ERROR) << "Failed to find connection! fd = " << fd;
        return false;
    }

    // If requested, remove event handlers for the connected socket
    if (remove_handlers && (!m_event_loop->remove_handlers(fd))) {
        LOG(ERROR) << "Failed to remove event handlers for the connected socket! fd = " << fd;
        return false;
    }

    // Remove connection from the map of current connections.
    m_connections.erase(it);

    // Notify that a client has disconnected from this server
    notify_client_disconnected(fd);

    return true;
}

void CmduServerImpl::handle_connect(int fd)
{
    // LOG(DEBUG) << "Accepting connection, fd = " << fd;

    beerocks::net::UdsAddress address;
    auto connection = m_server_socket->accept(address);

    if (!connection) {
        LOG(ERROR) << "Failed to accept incoming connection request! fd = " << fd;
        return;
    }

    int connected_socket = connection->socket()->fd();
    LOG(INFO) << "Client connected, fd = " << connected_socket;

    beerocks::EventLoop::EventHandlers handlers;
    handlers.on_read = [&](int fd, beerocks::EventLoop &loop) {
        handle_read(fd);
        return true;
    };
    handlers.on_disconnect = [&](int fd, beerocks::EventLoop &loop) {
        handle_close(fd);
        return true;
    };
    handlers.on_error = handlers.on_disconnect;

    if (!add_connection(connected_socket, std::move(connection), handlers)) {
        LOG(ERROR) << "Failed to add connection! fd = " << fd;
    }
}

void CmduServerImpl::handle_read(int fd)
{
    // Find context information for given socket connection
    auto it = m_connections.find(fd);
    if (m_connections.end() == it) {
        LOG(ERROR) << "Failed to find connection! fd = " << fd;
        return;
    }

    auto &context = it->second;

    // Read available bytes into buffer
    int bytes_received = context.connection->receive(context.buffer);
    if (bytes_received <= 0) {
        LOG(ERROR) << "Failed to received data! bytes received: " << bytes_received
                   << ", fd = " << fd;
        return;
    }

    // These parameters are obtained from the UDS header. Sender process will fill them in only
    // if CMDU was originally received by a remote process and then forwarded to this process.
    uint32_t iface_index;
    sMacAddr dst_mac;
    sMacAddr src_mac;

    // Buffer for the received CMDU and received CMDU itself
    uint8_t cmdu_rx_buffer[message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageRx cmdu_rx(cmdu_rx_buffer, sizeof(cmdu_rx_buffer));

    // CMDU parsing & handling loop
    // Note: must be done in a loop because data received through a stream-oriented socket might
    // contain more than one CMDU. If data was received through a message-oriented socket, then
    // only one message would be received at a time and the loop would be iterated only once.
    while ((context.buffer.length() > 0) &&
           m_cmdu_parser->parse_cmdu(context.buffer, iface_index, dst_mac, src_mac, cmdu_rx)) {
        notify_cmdu_received(fd, iface_index, dst_mac, src_mac, cmdu_rx);
    }
}

void CmduServerImpl::handle_close(int fd)
{
    // Remove connection on the given client socket
    remove_connection(fd);
}

} // namespace beerocks
