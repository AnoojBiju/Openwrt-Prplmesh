/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_cmdu_server_impl.h>

#include <bcl/beerocks_event_loop_mock.h>
#include <bcl/network/cmdu_parser_mock.h>
#include <bcl/network/cmdu_serializer_mock.h>
#include <bcl/network/sockets_mock.h>

#include <bcl/beerocks_backport.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace {

class CmduServerImplTest : public ::testing::Test {
protected:
    CmduServerImplTest() : m_cmdu_tx(m_tx_buffer, sizeof(m_tx_buffer)) {}

    uint8_t m_tx_buffer[beerocks::message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx m_cmdu_tx;

    std::shared_ptr<StrictMock<beerocks::net::SocketMock>> m_socket =
        std::make_shared<StrictMock<beerocks::net::SocketMock>>();
    std::unique_ptr<StrictMock<beerocks::net::ServerSocketMock>> m_server_socket =
        std::make_unique<StrictMock<beerocks::net::ServerSocketMock>>();
    std::shared_ptr<StrictMock<beerocks::net::CmduParserMock>> m_cmdu_parser =
        std::make_shared<StrictMock<beerocks::net::CmduParserMock>>();
    std::shared_ptr<StrictMock<beerocks::net::CmduSerializerMock>> m_cmdu_serializer =
        std::make_shared<StrictMock<beerocks::net::CmduSerializerMock>>();
    std::shared_ptr<StrictMock<beerocks::EventLoopMock>> m_event_loop =
        std::make_shared<StrictMock<beerocks::EventLoopMock>>();
};

TEST_F(CmduServerImplTest, destructor_should_remove_remaining_connections)
{
    auto connection       = new StrictMock<beerocks::net::SocketConnectionMock>();
    auto connected_socket = std::make_shared<StrictMock<beerocks::net::SocketMock>>();

    constexpr int server_socket_fd    = 1;
    constexpr int connected_socket_fd = 2;

    beerocks::EventLoop::EventHandlers server_socket_handlers;
    beerocks::EventLoop::EventHandlers connected_socket_handlers;

    // Expectations that use this default return value increase the `use_count` of shared_ptr
    // `socket`. To avoid a leak detection when test ends, `socket` must be destroyed at (or before)
    // the end of TEST.
    // In order to work around this, call `VerifyAndClearExpectations` right before the end of
    // the test.
    ON_CALL(*m_server_socket, socket()).WillByDefault(Return(m_socket));
    ON_CALL(*m_socket, fd()).WillByDefault(Return(server_socket_fd));

    // The same concern applies to shared_ptr `connected_socket`
    ON_CALL(*connection, socket()).WillByDefault(Return(connected_socket));
    ON_CALL(*connected_socket, fd()).WillByDefault(Return(connected_socket_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(server_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&server_socket_handlers), Return(true)));

        EXPECT_CALL(*m_server_socket, accept_proxy(_)).WillOnce(Return(connection));

        EXPECT_CALL(*connection, socket()).Times(1);
        EXPECT_CALL(*connected_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(connected_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&connected_socket_handlers), Return(true)));

        // Destructor removes event handlers for remaining connections
        EXPECT_CALL(*m_event_loop, remove_handlers(connected_socket_fd)).WillOnce(Return(true));

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, remove_handlers(server_socket_fd)).WillOnce(Return(true));
    }

    // Destructor of `cmdu_server` must be executed before calling `VerifyAndClearExpectations` so
    // all expectations for methods called in such destructor are satisfied.
    {
        beerocks::CmduServerImpl cmdu_server(std::move(m_server_socket), m_cmdu_parser,
                                             m_cmdu_serializer, m_event_loop);

        // Emulate a new client is connected to the server socket.
        // Client remains connected when destructor is executed.
        server_socket_handlers.on_read(connected_socket_fd, *m_event_loop);
    }

    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_socket.get()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(connected_socket.get()));
}

TEST_F(CmduServerImplTest, receive_cmdu_should_succeed)
{
    auto connection       = new StrictMock<beerocks::net::SocketConnectionMock>();
    auto connected_socket = std::make_shared<StrictMock<beerocks::net::SocketMock>>();

    constexpr int server_socket_fd    = 1;
    constexpr int connected_socket_fd = 2;
    constexpr int bytes_received      = 256;

    beerocks::EventLoop::EventHandlers server_socket_handlers;
    beerocks::EventLoop::EventHandlers connected_socket_handlers;

    // Expectations that use this default return value increase the `use_count` of shared_ptr
    // `socket`. To avoid a leak detection when test ends, `socket` must be destroyed at (or before)
    // the end of TEST.
    // In order to work around this, call `VerifyAndClearExpectations` right before the end of
    // the test.
    ON_CALL(*m_server_socket, socket()).WillByDefault(Return(m_socket));
    ON_CALL(*m_socket, fd()).WillByDefault(Return(server_socket_fd));

    // The same concern applies to shared_ptr `connected_socket`
    ON_CALL(*connection, socket()).WillByDefault(Return(connected_socket));
    ON_CALL(*connected_socket, fd()).WillByDefault(Return(connected_socket_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(server_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&server_socket_handlers), Return(true)));

        EXPECT_CALL(*m_server_socket, accept_proxy(_)).WillOnce(Return(connection));

        EXPECT_CALL(*connection, socket()).Times(1);
        EXPECT_CALL(*connected_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(connected_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&connected_socket_handlers), Return(true)));

        EXPECT_CALL(*connection, receive(_)).WillOnce(Invoke([&](beerocks::net::Buffer &buffer) {
            buffer.length() += bytes_received;
            return bytes_received;
        }));

        EXPECT_CALL(*m_cmdu_parser, parse_cmdu(_, _, _, _, _))
            .WillOnce(
                Invoke([&](beerocks::net::Buffer &buffer, uint32_t &iface_index, sMacAddr &dst_mac,
                           sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx) {
                    buffer.length() = 0;
                    return true;
                }));

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, remove_handlers(server_socket_fd)).WillOnce(Return(true));
    }

    // Destructor of `cmdu_server` must be executed before calling `VerifyAndClearExpectations` so
    // all expectations for methods called in such destructor are satisfied.
    {
        beerocks::CmduServerImpl cmdu_server(std::move(m_server_socket), m_cmdu_parser,
                                             m_cmdu_serializer, m_event_loop);

        // Flags to assert that events were actually fired
        bool client_connected    = false;
        bool client_disconnected = false;
        bool cmdu_received       = false;

        // Install the event handler functions
        beerocks::CmduServer::EventHandlers handlers{
            .on_client_connected =
                [&](int fd) {
                    if (fd == connected_socket_fd) {
                        client_connected = true;
                    }
                },
            .on_client_disconnected =
                [&](int fd) {
                    if (fd == connected_socket_fd) {
                        client_disconnected = true;
                    }
                },
            .on_cmdu_received =
                [&](int fd, uint32_t iface_index, const sMacAddr &dst_mac, const sMacAddr &src_mac,
                    ieee1905_1::CmduMessageRx &cmdu_rx) {
                    if (fd == connected_socket_fd) {
                        cmdu_received = true;
                    }
                },
        };
        cmdu_server.set_handlers(handlers);

        // Emulate a new client is connected to the server socket
        server_socket_handlers.on_read(connected_socket_fd, *m_event_loop);

        // Assert that client-connected event handler function has been called back
        ASSERT_TRUE(client_connected);

        // Emulate the client sends a CMDU message
        connected_socket_handlers.on_read(connected_socket_fd, *m_event_loop);

        // Assert that CMDU-received event handler function has been called back
        ASSERT_TRUE(cmdu_received);

        // Emulate the client gets disconnected from the server socket
        connected_socket_handlers.on_disconnect(connected_socket_fd, *m_event_loop);

        // Assert that client-disconnected event handler function has been called back
        ASSERT_TRUE(client_disconnected);
    }

    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_socket.get()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(connected_socket.get()));
}

TEST_F(CmduServerImplTest, send_cmdu_should_succeed)
{
    auto connection       = new StrictMock<beerocks::net::SocketConnectionMock>();
    auto connected_socket = std::make_shared<StrictMock<beerocks::net::SocketMock>>();

    constexpr int server_socket_fd    = 1;
    constexpr int connected_socket_fd = 2;

    beerocks::EventLoop::EventHandlers server_socket_handlers;
    beerocks::EventLoop::EventHandlers connected_socket_handlers;

    // Expectations that use this default return value increase the `use_count` of shared_ptr
    // `socket`. To avoid a leak detection when test ends, `socket` must be destroyed at (or before)
    // the end of TEST.
    // In order to work around this, call `VerifyAndClearExpectations` right before the end of
    // the test.
    ON_CALL(*m_server_socket, socket()).WillByDefault(Return(m_socket));
    ON_CALL(*m_socket, fd()).WillByDefault(Return(server_socket_fd));

    // The same concern applies to shared_ptr `connected_socket`
    ON_CALL(*connection, socket()).WillByDefault(Return(connected_socket));
    ON_CALL(*connected_socket, fd()).WillByDefault(Return(connected_socket_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(server_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&server_socket_handlers), Return(true)));

        EXPECT_CALL(*m_server_socket, accept_proxy(_)).WillOnce(Return(connection));

        EXPECT_CALL(*connection, socket()).Times(1);
        EXPECT_CALL(*connected_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(connected_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&connected_socket_handlers), Return(true)));

        EXPECT_CALL(*m_cmdu_serializer, serialize_cmdu(_, _, _, _)).WillOnce(Return(true));

        EXPECT_CALL(*connection, send(_)).WillOnce(Return(true));

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, remove_handlers(server_socket_fd)).WillOnce(Return(true));
    }

    // Destructor of `cmdu_server` must be executed before calling `VerifyAndClearExpectations` so
    // all expectations for methods called in such destructor are satisfied.
    {
        beerocks::CmduServerImpl cmdu_server(std::move(m_server_socket), m_cmdu_parser,
                                             m_cmdu_serializer, m_event_loop);

        // Emulate a new client is connected to the server socket
        server_socket_handlers.on_read(connected_socket_fd, *m_event_loop);

        // Method `send_cmdu` should succeed on a connected socket
        ASSERT_TRUE(cmdu_server.send_cmdu(connected_socket_fd, m_cmdu_tx));

        // Emulate the client gets disconnected from the server socket
        connected_socket_handlers.on_disconnect(connected_socket_fd, *m_event_loop);
    }

    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_socket.get()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(connected_socket.get()));
}

TEST_F(CmduServerImplTest, send_cmdu_should_fail_if_serialize_cmdu_fails)
{
    auto connection       = new StrictMock<beerocks::net::SocketConnectionMock>();
    auto connected_socket = std::make_shared<StrictMock<beerocks::net::SocketMock>>();

    constexpr int server_socket_fd    = 1;
    constexpr int connected_socket_fd = 2;

    beerocks::EventLoop::EventHandlers server_socket_handlers;
    beerocks::EventLoop::EventHandlers connected_socket_handlers;

    // Expectations that use this default return value increase the `use_count` of shared_ptr
    // `socket`. To avoid a leak detection when test ends, `socket` must be destroyed at (or before)
    // the end of TEST.
    // In order to work around this, call `VerifyAndClearExpectations` right before the end of
    // the test.
    ON_CALL(*m_server_socket, socket()).WillByDefault(Return(m_socket));
    ON_CALL(*m_socket, fd()).WillByDefault(Return(server_socket_fd));

    // The same concern applies to shared_ptr `connected_socket`
    ON_CALL(*connection, socket()).WillByDefault(Return(connected_socket));
    ON_CALL(*connected_socket, fd()).WillByDefault(Return(connected_socket_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(server_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&server_socket_handlers), Return(true)));

        EXPECT_CALL(*m_server_socket, accept_proxy(_)).WillOnce(Return(connection));

        EXPECT_CALL(*connection, socket()).Times(1);
        EXPECT_CALL(*connected_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(connected_socket_fd, _))
            .WillOnce(DoAll(SaveArg<1>(&connected_socket_handlers), Return(true)));

        // Serialization fails!
        EXPECT_CALL(*m_cmdu_serializer, serialize_cmdu(_, _, _, _)).WillOnce(Return(false));

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, remove_handlers(server_socket_fd)).WillOnce(Return(true));
    }

    // Destructor of `cmdu_server` must be executed before calling `VerifyAndClearExpectations` so
    // all expectations for methods called in such destructor are satisfied.
    {
        beerocks::CmduServerImpl cmdu_server(std::move(m_server_socket), m_cmdu_parser,
                                             m_cmdu_serializer, m_event_loop);

        // Emulate a new client is connected to the server socket
        server_socket_handlers.on_read(connected_socket_fd, *m_event_loop);

        // Method `send_cmdu` should fail if serialization fails
        ASSERT_FALSE(cmdu_server.send_cmdu(connected_socket_fd, m_cmdu_tx));

        // Emulate the client gets disconnected from the server socket
        connected_socket_handlers.on_disconnect(connected_socket_fd, *m_event_loop);
    }

    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_socket.get()));
    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(connected_socket.get()));
}

TEST_F(CmduServerImplTest, send_cmdu_should_fail_with_unknown_socket_fd)
{
    constexpr int server_socket_fd  = 1;
    constexpr int unknown_socket_fd = 2;

    // Expectations that use this default return value increase the `use_count` of shared_ptr
    // `socket`. To avoid a leak detection when test ends, `socket` must be destroyed at (or before)
    // the end of TEST.
    // In order to work around this, call `VerifyAndClearExpectations` right before the end of
    // the test.
    ON_CALL(*m_server_socket, socket()).WillByDefault(Return(m_socket));
    ON_CALL(*m_socket, fd()).WillByDefault(Return(server_socket_fd));

    {
        InSequence sequence;

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, register_handlers(server_socket_fd, _)).WillOnce(Return(true));

        EXPECT_CALL(*m_server_socket, socket()).Times(1);
        EXPECT_CALL(*m_socket, fd()).Times(1);
        EXPECT_CALL(*m_event_loop, remove_handlers(server_socket_fd)).WillOnce(Return(true));
    }

    // Destructor of `cmdu_server` must be executed before calling `VerifyAndClearExpectations` so
    // all expectations for methods called in such destructor are satisfied.
    {
        beerocks::CmduServerImpl cmdu_server(std::move(m_server_socket), m_cmdu_parser,
                                             m_cmdu_serializer, m_event_loop);

        // Method `send_cmdu` should fail if socket is not connected
        ASSERT_FALSE(cmdu_server.send_cmdu(unknown_socket_fd, m_cmdu_tx));
    }

    EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_socket.get()));
}

} // namespace
