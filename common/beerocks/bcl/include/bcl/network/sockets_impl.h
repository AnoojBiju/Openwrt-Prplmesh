/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BCL_NETWORK_SOCKETS_IMPL_H_
#define BCL_NETWORK_SOCKETS_IMPL_H_

#include "sockets.h"

#include <bcl/beerocks_backport.h>
#include <bcl/beerocks_string_utils.h>

#include <tlvf/common/sMacAddr.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/un.h>

namespace beerocks {
namespace net {

/**
 * One possible Buffer implementation
 */
template <size_t Size> class BufferImpl : public Buffer {
public:
    const uint8_t *data() const override { return m_data; }
    size_t size() const override { return sizeof(m_data); }
    void clear() override { std::fill_n(m_data, size(), 0); }

private:
    uint8_t m_data[Size]{};
};

/**
 * Abstract base class for all types of sockets: Raw, UDP, TCP, UDS, ...
 * This implementation class aggregates a FileDescriptor implementation so it has a file
 * descriptor. Methods overridden from FileDescriptor interface delegate on the aggregated
 * implementation.
 * Derived classes provide the file descriptor obtained with a call to socket(), using different
 * family, type and protocol parameters.
 * This class aggregates a FileDescriptor instead of inheriting from one of its implementations to
 * follow the principle of "Favor Aggregation over Inheritance".
 * See https://wiki.c2.com/?UseCompositionAndInterfacesWithoutClassInheritance
 */
class SocketAbstractImpl : public Socket {
public:
    /**
     * @brief Returns the socket file descriptor.
     *
     * @return Socket file descriptor.
     */
    int fd() override { return m_descriptor.fd(); }

protected:
    /**
     * @brief Class constructor.
     *
     * Constructor is protected so only derived classes can call it.
     */
    explicit SocketAbstractImpl(int fd) : m_descriptor(fd) {}

private:
    /**
     * File descriptor (i.e.: wrapper to `int fd` that closes descriptor on destructor)
     */
    FileDescriptorImpl m_descriptor;
};

class UdsAddress : public Socket::Address {
public:
    UdsAddress(const std::string &path = "")
    {
        m_address.sun_family = AF_UNIX;
        string_utils::copy_string(m_address.sun_path, path.c_str(), sizeof(m_address.sun_path));
        m_length = path.length();
    }

    std::string path() const { return m_address.sun_path; }

    const struct sockaddr *sockaddr() const override
    {
        return reinterpret_cast<const struct sockaddr *>(&m_address);
    }
    const socklen_t &length() const override { return m_length; }
    socklen_t size() const override { return m_size; }

private:
    sockaddr_un m_address  = {};
    socklen_t m_length     = 0;
    const socklen_t m_size = sizeof(m_address);
};

class InternetAddress : public Socket::Address {
public:
    explicit InternetAddress(uint16_t port, uint32_t address = INADDR_ANY)
    {
        m_address.sin_family      = AF_INET;
        m_address.sin_addr.s_addr = address;
        m_address.sin_port        = htons(port);
    }

    const struct sockaddr *sockaddr() const override
    {
        return reinterpret_cast<const struct sockaddr *>(&m_address);
    }
    const socklen_t &length() const override { return m_length; }
    socklen_t size() const override { return m_size; }

private:
    sockaddr_in m_address  = {};
    socklen_t m_length     = sizeof(m_address);
    const socklen_t m_size = sizeof(m_address);
};

class LinkLevelAddress : public Socket::Address {
public:
    LinkLevelAddress(uint32_t iface_index, const sMacAddr &mac)
    {
        m_address.sll_family  = AF_PACKET;
        m_address.sll_ifindex = iface_index;
        m_address.sll_halen   = sizeof(sMacAddr);
        std::copy_n(mac.oct, sizeof(sMacAddr), m_address.sll_addr);
    }

    const struct sockaddr *sockaddr() const override
    {
        return reinterpret_cast<const struct sockaddr *>(&m_address);
    }
    const socklen_t &length() const override { return m_length; }
    socklen_t size() const override { return m_size; }

private:
    sockaddr_ll m_address  = {};
    socklen_t m_length     = sizeof(m_address);
    const socklen_t m_size = sizeof(m_address);
};

class NetlinkAddress : public Socket::Address {
public:
    explicit NetlinkAddress(uint32_t groups = 0)
    {
        m_address.nl_family = AF_NETLINK;
        m_address.nl_groups = groups;
    }

    const struct sockaddr *sockaddr() const override
    {
        return reinterpret_cast<const struct sockaddr *>(&m_address);
    }
    const socklen_t &length() const override { return m_length; }
    socklen_t size() const override { return m_size; }

private:
    sockaddr_nl m_address  = {};
    socklen_t m_length     = sizeof(m_address);
    const socklen_t m_size = sizeof(m_address);
};

/**
 * This class is a wrapper for the socket file descriptor obtained with the accept() system call.
 */
class ConnectedSocket : public SocketAbstractImpl {
public:
    explicit ConnectedSocket(int fd) : SocketAbstractImpl(fd) {}
};

class RawSocket : public SocketAbstractImpl {
public:
    explicit RawSocket(uint16_t protocol = ETH_P_ALL)
        : SocketAbstractImpl(socket(AF_PACKET, SOCK_RAW, htons(protocol)))
    {
    }
};

class UdpSocket : public SocketAbstractImpl {
public:
    UdpSocket() : SocketAbstractImpl(socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) {}
};

class TcpSocket : public SocketAbstractImpl {
public:
    TcpSocket() : SocketAbstractImpl(socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) {}
};

class UdsSocket : public SocketAbstractImpl {
public:
    /**
     * Class constructor.
     *
     * Creates a Unix Domain Socket for exchanging data between processes executing on the same
     * host operating system.
     *
     * Valid socket types in the UNIX domain are:
     * - SOCK_STREAM (compare to TCP) – for a stream-oriented socket.
     * - SOCK_DGRAM (compare to UDP) – for a datagram-oriented socket that preserves message
     * boundaries (as on most UNIX implementations, UNIX domain datagram sockets are always
     * reliable and don't reorder datagrams).
     * - SOCK_SEQPACKET (compare to SCTP) – for a sequenced-packet socket that is connection-
     * oriented, preserves message boundaries, and delivers messages in the order that they were
     * sent.
     *
     * Stream socket allows for reading an arbitrary number of bytes, but still preserving byte
     * sequence. In other words, a sender might write 4K of data to the socket, and the receiver
     * can consume that data byte by byte. The other way around is true too - the sender can write
     * several small messages to the socket that the receiver can consume in one read. Stream
     * socket does not preserve message boundaries.
     *
     * Datagram socket, on the other hand, does preserve these boundaries - one write by the
     * sender always corresponds to one read by the receiver (even if the receiver's buffer given
     * to read(2) or recv(2) is smaller than that message).
     *
     * So if your application protocol has small messages with known upper bound on message size
     * you are better off with SOCK_DGRAM since that's easier to manage.
     *
     * If your protocol calls for arbitrary long message payloads, or is just an unstructured
     * stream (like raw audio or something), then pick SOCK_STREAM and do the required buffering.
     *
     * @param type Socket type (i.e.: communication style).
     */
    explicit UdsSocket(int type = SOCK_DGRAM) : SocketAbstractImpl(socket(AF_UNIX, type, 0)) {}
};

class NetlinkSocket : public SocketAbstractImpl {
protected:
    explicit NetlinkSocket(uint16_t protocol)
        : SocketAbstractImpl(socket(AF_NETLINK, SOCK_RAW, protocol))
    {
    }
};

class NetlinkRouteSocket : public NetlinkSocket {
public:
    NetlinkRouteSocket() : NetlinkSocket(NETLINK_ROUTE) {}
};

/**
 * This class implements the Socket::Connection interface with methods that wrap the system calls
 * to send and receive both bytes and packets in stream-oriented and packet-oriented sockets
 * respectively.
 */
class SocketConnectionImpl : public Socket::Connection {
public:
    explicit SocketConnectionImpl(const std::shared_ptr<Socket> &socket) : m_socket(socket) {}

    /**
     * @brief Returns the underlying socket used by this connection.
     *
     * @see Connection::socket
     */
    std::shared_ptr<Socket> socket() override { return m_socket; }

    /**
     * @brief Receives data through the socket connection.
     *
     * @see Connection::receive
     *
     * This implementation uses the recv() system call.
     */
    int receive(Buffer &buffer, size_t offset = 0) override
    {
        if (offset >= buffer.size()) {
            return -1;
        }
        return ::recv(m_socket->fd(), buffer.data() + offset, buffer.size() - offset, MSG_DONTWAIT);
    }

    /**
     * @brief Receives data through the socket connection.
     *
     * @see Connection::receive_from
     *
     * This implementation uses the recvfrom() system call.
     */
    int receive_from(Buffer &buffer, Socket::Address &address) override
    {
        address.length() = address.size();
        return ::recvfrom(m_socket->fd(), buffer.data(), buffer.size(), MSG_DONTWAIT,
                          address.sockaddr(), &address.length());
    }

    /**
     * @brief Sends data through the socket connection.
     *
     * @see Connection::send
     *
     * This implementation uses the send() system call.
     */
    int send(const Buffer &buffer, size_t length) override
    {
        if (length > buffer.size()) {
            return -1;
        }
        return ::send(m_socket->fd(), buffer.data(), length, MSG_NOSIGNAL);
    }

    /**
     * @brief Sends data through the socket connection.
     *
     * @see Connection::send_to
     *
     * This implementation uses the sendto() system call.
     */
    int send_to(const Buffer &buffer, size_t length, const Socket::Address &address) override
    {
        return ::sendto(m_socket->fd(), buffer.data(), buffer.size(), 0, address.sockaddr(),
                        address.length());
    }

private:
    /**
     * Connected socket used by this connection object.
     */
    std::shared_ptr<Socket> m_socket;
};

class ServerSocketAbstractImpl : public ServerSocket {
public:
    bool bind(const Socket::Address &address)
    {
        if (0 != ::bind(m_socket->fd(), address.sockaddr(), address.length())) {
            LOG(ERROR) << "Unable to bind server socket: " << strerror(errno);
            return false;
        }

        return true;
    }

    bool listen(int backlog)
    {
        if (0 != ::listen(m_socket->fd(), backlog)) {
            LOG(ERROR) << "Unable to listen for incoming connections: " << strerror(errno);
            return false;
        }

        return true;
    }

    std::unique_ptr<Socket::Connection> accept(Socket::Address &address) override
    {
        address.length()     = address.size();
        int connected_socket = ::accept(m_socket->fd(), address.sockaddr(), &address.length());
        if (FileDescriptor::invalid_descriptor == connected_socket) {
            LOG(ERROR) << "Unable to accept socket connection: " << strerror(errno);
            return nullptr;
        }

        return std::make_unique<SocketConnectionImpl>(
            std::make_shared<ConnectedSocket>(connected_socket));
    }

protected:
    explicit ServerSocketAbstractImpl(const std::shared_ptr<Socket> &socket) : m_socket(socket) {}
    std::shared_ptr<Socket> m_socket;
};

class ClientSocketAbstractImpl : public ClientSocket {
public:
    bool bind(const Socket::Address &address)
    {
        if (0 != ::bind(m_socket->fd(), address.sockaddr(), address.length())) {
            LOG(ERROR) << "Unable to bind client socket: " << strerror(errno);
            return false;
        }

        return true;
    }

    std::unique_ptr<Socket::Connection> connect(const Socket::Address &address) override
    {
        if (0 != ::connect(m_socket->fd(), address.sockaddr(), address.length())) {
            LOG(ERROR) << "Unable to connect client socket: " << strerror(errno);
            return nullptr;
        }

        return std::make_unique<SocketConnectionImpl>(m_socket);
    }

protected:
    explicit ClientSocketAbstractImpl(const std::shared_ptr<Socket> &socket) : m_socket(socket) {}
    std::shared_ptr<Socket> m_socket;
};

template <class SocketType> class ServerSocketImpl : public ServerSocketAbstractImpl {
public:
    explicit ServerSocketImpl(const std::shared_ptr<SocketType> &socket)
        : ServerSocketAbstractImpl(socket)
    {
    }
};

template <class SocketType> class ClientSocketImpl : public ClientSocketAbstractImpl {
public:
    explicit ClientSocketImpl(const std::shared_ptr<SocketType> &socket)
        : ClientSocketAbstractImpl(socket)
    {
    }
};

} // namespace net
} // namespace beerocks

#endif /* BCL_NETWORK_SOCKETS_IMPL_H_ */
