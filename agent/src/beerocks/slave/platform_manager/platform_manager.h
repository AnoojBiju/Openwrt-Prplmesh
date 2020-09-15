/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PLATFORM_MANAGER_H
#define _PLATFORM_MANAGER_H

#include <bcl/beerocks_async_work_queue.h>
#include <bcl/beerocks_config_file.h>
#include <bcl/beerocks_event_loop.h>
#include <bcl/beerocks_logging.h>
#include <bcl/network/buffer_impl.h>
#include <bcl/network/cmdu_parser.h>
#include <bcl/network/cmdu_serializer.h>
#include <bcl/network/sockets.h>
#include <bcl/network/timer.h>

#include "beerocks/tlvf/beerocks_message_common.h"

#include <bpl/bpl_arp.h>
#include <bpl/bpl_cfg.h>

#include <atomic>
#include <unordered_map>
#include <unordered_set>

namespace beerocks {

class platform_manager {

public:
    /**
     * @brief Queries platform for a given parameter value.
     *
     * Platform configuration is read through BPL.
     *
     * @param parameter Parameter name. Possible values are "is_master", "is_gateway" and
     * "is_onboarding".
     * @return Requested parameter value on success and error message on error (i.e.: if unable to
     * initialize BPL or if parameter name is invalid).
     */
    static std::string query_db(const std::string &parameter);

    platform_manager(const config_file::sConfigSlave &config_,
                     const std::unordered_map<int, std::string> &interfaces_map, logging &logger_,
                     std::unique_ptr<beerocks::net::Timer<>> clean_old_arp_entries_timer,
                     std::unique_ptr<beerocks::net::Timer<>> check_wlan_params_changed_timer,
                     std::unique_ptr<beerocks::net::ServerSocket> server_socket,
                     std::shared_ptr<beerocks::net::CmduParser> cmdu_parser,
                     std::shared_ptr<beerocks::net::CmduSerializer> cmdu_serializer,
                     std::shared_ptr<beerocks::EventLoop> event_loop);

    /**
     * @brief Starts platform manager.
     *
     * @return true on success and false otherwise.
     */
    bool start();

    /**
     * @brief Stops platform manager.
     *
     * @return true on success and false otherwise.
     */
    bool stop();

protected:
    bool handle_arp_monitor();
    bool handle_arp_raw();

private:
    /**
     * @brief Adds a new connection.
     *
     * Registers given event handlers for the connected socket so the appropriate action is taken
     * whenever data is received or socket is disconnected.
     *
     * Adds the connection object to the list of current socket connections so event handlers
     * that have been registered in the event loop can be removed on exit.
     *
     * @param fd File descriptor of the socket used by the connection.
     * @param connection Connection object used to send/receive data.
     * @param handlers Event handlers to install into the event loop to handle blocking I/O events.
     * @return true on success and false otherwise.
     */
    bool add_connection(int fd, std::unique_ptr<beerocks::net::Socket::Connection> connection,
                        const beerocks::EventLoop::EventHandlers &handlers);

    /**
     * @brief Removes connection.
     *
     * Removes event handlers for the connected socket and removes the connection from the list of
     * current connections.
     *
     * This method gets called when connection is closed, an error occurs on the socket or platform
     * manager is stopped.
     *
     * @param fd File descriptor of the socket used by the connection.
     * @return true on success and false otherwise.
     */
    bool remove_connection(int fd);

    /**
     * @brief Handles the read event in a client socket connected to the UDS server socket.
     *
     * Reads data received through the socket and parses CMDU messages out of the bytes received.
     * Valid CMDU messages received are processed by calling the `handle_cmdu()` method.
     *
     * @param fd File descriptor of the socket.
     */
    void handle_read(int fd);

    /**
     * @brief Handles the disconnect and error events in a client socket connected to the UDS
     * server socket.
     *
     * Removes connection from the list of current connections.
     *
     * @param fd File descriptor of the socket.
     */
    void handle_close(int fd);

    /**
     * @brief Handles received CMDU message.
     *
     * @param fd File descriptor of the socket that the CMDU was received through.
     * @param cmdu_rx Received CMDU to be handled.
     * @return true on success and false otherwise.
     */
    bool handle_cmdu(int fd, ieee1905_1::CmduMessageRx &cmdu_rx);

    void add_slave_socket(int fd, const std::string &iface_name);
    void del_slave_socket(int fd);
    bool send_cmdu_safe(int fd, ieee1905_1::CmduMessageTx &cmdu_tx);
    bool send_cmdu(int fd, ieee1905_1::CmduMessageTx &cmdu_tx);
    int get_slave_socket_from_hostap_iface_name(const std::string &iface);
    bool socket_disconnected(int fd);

    int get_backhaul_socket();
    void load_iface_params(const std::string &strIface, beerocks::eArpSource eType);
    std::string bridge_iface_from_mac(const sMacAddr &sMac);
    void send_dhcp_notification(const std::string &op, const std::string &mac,
                                const std::string &ip, const std::string &hostname);

    /**
     * @brief Clean old ARP table entries.
     *
     * Iterates over the list of ARP entries and removes those that have been inactive for a period
     * longer than the ARP notification interval.
     */
    void clean_old_arp_entries();
    bool init_dhcp_monitor();
    void stop_dhcp_monitor();
    bool init_arp_monitor();
    void stop_arp_monitor();
    bool restart_arp_monitor();

    /**
     * @brief Checks if WLAN parameters have changed.
     *
     * For each of the slaves, performs a check on the `band_enabled` and `channel` parameters and,
     * if changed, sends a ACTION_PLATFORM_WLAN_PARAMS_CHANGED_NOTIFICATION message to the slave
     * including the new settings.
     *
     * @return true if WLAN parameters have changed for any of the slaves.
     */
    bool check_wlan_params_changed();

private:
    const int PLATFORM_READ_CONF_RETRY_SEC    = 5;
    const int PLATFORM_READ_CONF_MAX_ATTEMPTS = 10;

    /**
     * Buffer to hold CMDU to be transmitted.
     */
    uint8_t m_tx_buffer[message::MESSAGE_BUFFER_LENGTH];

    /**
     * CMDU to be transmitted.
     */
    ieee1905_1::CmduMessageTx m_cmdu_tx;

    /**
     * Flag to ask asynchronous code (running in a background worker thread) to stop.
     */
    std::atomic<bool> m_should_stop{false};

    config_file::sConfigSlave config;
    const std::unordered_map<int, std::string> interfaces_map;

    struct SIfaceParams {
        beerocks::eArpSource eType;
    };

    struct SArpEntry {
        uint32_t ip;
        int iface_index;
        std::chrono::steady_clock::time_point last_seen;
    };

    // Connected slaves map (socket file descriptor/interface name)
    std::unordered_map<int, std::string> m_mapSlaves; // value=iface_name
    std::mutex m_mtxSlaves;

    // Interfaces
    std::unordered_map<std::string, SIfaceParams> m_mapIfaces; // key=iface_name

    // ARP entries by source MAC (uint64_t) address
    std::unordered_map<sMacAddr, std::shared_ptr<SArpEntry>> m_mapArpEntries;
    std::chrono::steady_clock::time_point m_tpArpEntriesCleanup;

    /**
     * File descriptor of the socket connecting to the backhaul manager
     */
    int m_backhaul_manager_socket = beerocks::net::FileDescriptor::invalid_descriptor;

    bpl::BPL_ARP_MON_CTX m_ctxArpMon = nullptr;

    uint32_t m_uiArpMonIP   = 0;
    uint32_t m_uiArpMonMask = 0;

    logging &logger;
    bool enable_arp_monitor    = false;
    bool is_onboarding_on_init = false;

    std::string master_version;
    std::string slave_version;

    beerocks::async_work_queue work_queue;

    std::unordered_map<std::string, std::shared_ptr<beerocks_message::sWlanSettings>>
        bpl_iface_wlan_params_map;
    std::unordered_set<std::string> ap_ifaces;

    /**
     * Timer to periodically clean old ARP table entries.
     */
    std::unique_ptr<beerocks::net::Timer<>> m_clean_old_arp_entries_timer;

    /**
     * Timer to periodically check if WLAN parameters have changed.
     */
    std::unique_ptr<beerocks::net::Timer<>> m_check_wlan_params_changed_timer;

    /**
     * Server socket used to accept incoming connection requests from clients that will
     * communicate with platform manager by exchanging CMDU messages through that connections.
     */
    std::unique_ptr<beerocks::net::ServerSocket> m_server_socket;

    /**
     * CMDU parser used to get CMDU messages out of a byte array received through a socket
     * connection.
     */
    std::shared_ptr<beerocks::net::CmduParser> m_cmdu_parser;

    /**
     * CMDU serializer used to put CMDU messages into a byte array to be sent through a socket
     * connection.
     */
    std::shared_ptr<beerocks::net::CmduSerializer> m_cmdu_serializer;

    /**
     * Application event loop used by the process to wait for I/O events.
     */
    std::shared_ptr<EventLoop> m_event_loop;

    /**
     * Structure to hold context information for each ongoing socket connection.
     */
    struct sConnectionContext {
        /**
         * Accepted socket connection, used to send and receive data to/from the socket.
         * Connections are stored so event handlers that have been registered in the event loop
         * can be removed on exit.
         */
        std::unique_ptr<beerocks::net::Socket::Connection> connection;

        /**
         * Buffer to hold data received through the socket connection.
         * If connection uses a stream-oriented socket, it needs its own buffer to hold received
         * data.
         * A stream-oriented socket provides a stream of bytes, it is not message-oriented, and
         * does not provide boundaries. One write call could take several read calls to get that
         * data. Data from several write calls could be read by one read call. And anything in
         * between is also possible.
         * If connection uses a message-oriented socket instead, this buffer and the code that
         * uses it is also valid.
         */
        beerocks::net::BufferImpl<message::MESSAGE_BUFFER_LENGTH> buffer;

        /**
         * @brief Struct constructor.
         *
         * @param connection Socket connection.
         */
        explicit sConnectionContext(std::unique_ptr<beerocks::net::Socket::Connection> connection)
            : connection(std::move(connection)){};
    };

    /**
     * Map of current socket connections.
     * Key value is the file descriptor of the accepted socket and the object value is the
     * context information of the connection.
     */
    std::unordered_map<int, sConnectionContext> m_connections;

    /**
     * File descriptor of the ARP raw socket
     */
    int m_arp_raw_socket = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * File descriptor of the ARP monitor socket
     */
    int m_arp_mon_socket = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * File descriptor of the DHCP monitor socket
     */
    int m_dhcp_mon_socket = beerocks::net::FileDescriptor::invalid_descriptor;
};

} // namespace beerocks

#endif // _PLATFORM_MANAGER_H
