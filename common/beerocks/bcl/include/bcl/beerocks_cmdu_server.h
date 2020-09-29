/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_CMDU_SERVER_H_
#define _BEEROCKS_CMDU_SERVER_H_

#include <tlvf/CmduMessageRx.h>
#include <tlvf/CmduMessageTx.h>
#include <tlvf/common/sMacAddr.h>

namespace beerocks {

/**
 * @brief The CMDU server is a component to send and receive CMDU messages between local processes.
 *
 * This component acts as the server side end-point of the connection between communicating
 * processes while the @see CmduClient plays the client role.
 *
 * Users of this component register a handler to process received CMDU messages and send CMDU
 * messages in response.
 */
class CmduServer {
public:
    /**
     * @brief Client-connected event handler function.
     *
     * @param fd File descriptor of the accepted socket connection.
     */
    using ClientConnectedHandler = std::function<void(int fd)>;

    /**
     * @brief Client-disconnected event handler function.
     *
     * @param fd File descriptor of the disconnected socket.
     */
    using ClientDisconnectedHandler = std::function<void(int fd)>;

    /**
     * @brief CMDU-received event handler function.
     *
     * Note: parameters iface_index, dst_mac and src_mac are only filled in if CMDU was originally
     * sent by a remote process and then forwarded by the local process that receives it to this
     * process.
     *
     * @param fd File descriptor of the socket connection the CMDU was received through.
     * @param iface_index Index of the network interface that the CMDU message was received on.
     * @param dst_mac Destination MAC address.
     * @param src_mac Source MAC address.
     * @param cmdu_rx The CMDU message received.
     */
    using CmduReceivedHandler =
        std::function<void(int fd, uint32_t iface_index, const sMacAddr &dst_mac,
                           const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)>;

    /**
     * Default destructor.
     */
    virtual ~CmduServer() = default;

    /**
     * @brief Sets the client-connected event handler function.
     *
     * Sets the callback function to be executed whenever a new client connects to this server.
     * Use nullptr to remove previously installed callback function.
     *
     * @param handler Client-connected event handler function (or nullptr).
     */
    void set_client_connected_handler(const ClientConnectedHandler &handler)
    {
        m_client_connected_handler = handler;
    }

    /**
     * @brief Clears previously set client-connected event handler function.
     *
     * Clears callback function previously set. Behaves like calling the set method with nullptr.
     */
    void clear_client_connected_handler() { m_client_connected_handler = nullptr; }

    /**
     * @brief Sets the client-disconnected event handler function.
     *
     * Sets the callback function to be executed whenever a client disconnects from this server.
     * Use nullptr to remove previously installed callback function.
     *
     * @param handler Client-disconnected event handler function (or nullptr).
     */
    void set_client_disconnected_handler(const ClientDisconnectedHandler &handler)
    {
        m_client_disconnected_handler = handler;
    }

    /**
     * @brief Clears previously set client-disconnected event handler function.
     *
     * Clears callback function previously set. Behaves like calling the set method with nullptr.
     */
    void clear_client_disconnected_handler() { m_client_disconnected_handler = nullptr; }

    /**
     * @brief Sets the CMDU-received event handler function.
     *
     * Sets the callback function to handle CMDU messages received. Use nullptr to remove
     * previously installed callback function.
     *
     * If a handler is set, it will be called back whenever a CMDU message is received at the
     * server.
     *
     * @param handler CMDU-received event handler function (or nullptr).
     */
    void set_cmdu_received_handler(const CmduReceivedHandler &handler)
    {
        m_cmdu_received_handler = handler;
    }

    /**
     * @brief Clears previously set CMDU-received event handler function.
     *
     * Clears callback function previously set. Behaves like calling the set method with nullptr.
     */
    void clear_cmdu_received_handler() { m_cmdu_received_handler = nullptr; }

    /**
     * @brief Sends a CMDU message.
     *
     * Sends a CMDU message to a client through the given socket connection.
     *
     * @param fd File descriptor of the socket connection to send CMDU through.
     * @param cmdu_tx The CMDU message to send.
     * @return true on success and false otherwise.
     */
    virtual bool send_cmdu(int fd, ieee1905_1::CmduMessageTx &cmdu_tx) = 0;

protected:
    /**
     * @brief Notifies a client-connected event.
     *
     * @param fd File descriptor of the socket connection the CMDU was received through.
     */
    void notify_client_connected(int fd) const
    {
        if (m_client_connected_handler) {
            m_client_connected_handler(fd);
        }
    }

    /**
     * @brief Notifies a client-disconnected event.
     *
     * @param fd File descriptor of the socket connection the CMDU was received through.
     */
    void notify_client_disconnected(int fd) const
    {
        if (m_client_disconnected_handler) {
            m_client_disconnected_handler(fd);
        }
    }

    /**
     * @brief Notifies a CMDU-received event.
     *
     * @param fd File descriptor of the socket connection the CMDU was received through.
     * @param iface_index Index of the network interface that the CMDU message was received on.
     * @param dst_mac Destination MAC address.
     * @param src_mac Source MAC address.
     * @param cmdu_rx The CMDU message received.
     */
    void notify_cmdu_received(int fd, uint32_t iface_index, const sMacAddr &dst_mac,
                              const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx) const
    {
        if (m_cmdu_received_handler) {
            m_cmdu_received_handler(fd, iface_index, dst_mac, src_mac, cmdu_rx);
        }
    }

private:
    /**
     * Client-connected event handler function that is called back whenever a new client is
     * connected to this server.
     */
    ClientConnectedHandler m_client_connected_handler;

    /**
     * Client-disconnected event handler function that is called back whenever a new client is
     * disconnected from this server.
     */
    ClientDisconnectedHandler m_client_disconnected_handler;

    /**
     * CMDU-received event handler function that is called back whenever a CMDU message is received
     * at this server.
     */
    CmduReceivedHandler m_cmdu_received_handler;
};

} // namespace beerocks

#endif // _BEEROCKS_CMDU_SERVER_H_
