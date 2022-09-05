/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <btl/broker_client_factory_impl.h>
#include <btl/broker_client_impl.h>

#include <bcl/beerocks_backport.h>
#include <bcl/network/sockets_impl.h>

#include <easylogging++.h>

#include <chrono>

namespace beerocks {
namespace btl {

BrokerClientFactoryImpl::BrokerClientFactoryImpl(
    const std::string &uds_path, std::shared_ptr<MessageParser> message_parser,
    std::shared_ptr<MessageSerializer> message_serializer,
    std::shared_ptr<beerocks::EventLoop> event_loop)
    : m_uds_path(uds_path), m_message_parser(message_parser),
      m_message_serializer(message_serializer), m_event_loop(event_loop)
{
    LOG_IF(m_uds_path.empty(), FATAL) << "UDS path is an empty string!";
    LOG_IF(!m_message_parser, FATAL) << "Message parser is a null pointer!";
    LOG_IF(!m_message_serializer, FATAL) << "Message serializer is a null pointer!";
    LOG_IF(!m_event_loop, FATAL) << "Event loop is a null pointer!";
}

std::unique_ptr<BrokerClient> BrokerClientFactoryImpl::create_instance()
{
    // Create UDS socket
    auto socket = std::make_shared<beerocks::net::UdsSocket>();

    // Create UDS client socket to connect to server socket
    using UdsClientSocket = beerocks::net::ClientSocketImpl<beerocks::net::UdsSocket>;
    auto client_socket    = std::make_unique<UdsClientSocket>(socket);

    LOG_IF(!client_socket, FATAL) << "Unable to create client_socket!";

    // Connect client socket to server socket
    beerocks::net::UdsAddress address(m_uds_path);
    LOG(DEBUG) << "Connecting to Broker";

    std::unique_ptr<net::Socket::Connection> connection;
    constexpr auto broker_client_connection_timeout = std::chrono::seconds(10);
    auto timeout = std::chrono::steady_clock::now() + broker_client_connection_timeout;

    // When prplMesh processes are brought up, it is possible that broker clients will try to
    // connect before the transport process is up.
    // On the client side, failure to connect the transport process means FATAL.
    // To prevent random FATAL when prplMesh is started, return error only if the client failed to
    // connect the transport for more than 'broker_client_connection_timeout' seconds.
    while (!connection) {
        connection = client_socket->connect(address);
        if (connection) {
            break;
        }
        if (std::chrono::steady_clock::now() < timeout) {
            UTILS_SLEEP_MSEC(100);
            continue;
        }
        LOG(ERROR) << "Unable to connect client socket to '" << address.path() + "'";
        return nullptr;
    }

    LOG(DEBUG) << "Broker client created with fd = " << connection->socket()->fd();
    auto broker_client = std::make_unique<BrokerClientImpl>(std::move(connection), m_message_parser,
                                                            m_message_serializer, m_event_loop);
    if (!broker_client) {
        LOG(ERROR) << "Unable to create broker client connected to '" << address.path() + "'";
        return nullptr;
    }

    return broker_client;
}

} // namespace btl

} // namespace beerocks
