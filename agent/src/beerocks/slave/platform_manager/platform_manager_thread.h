/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PLATFORM_MANAGER_THREAD_H
#define _PLATFORM_MANAGER_THREAD_H

#include <bcl/beerocks_async_work_queue.h>
#include <bcl/beerocks_config_file.h>
#include <bcl/beerocks_event_loop.h>
#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_socket_thread.h>
#include <bcl/network/buffer_impl.h>
#include <bcl/network/cmdu_parser.h>
#include <bcl/network/cmdu_serializer.h>
#include <bcl/network/sockets.h>

#include "beerocks/tlvf/beerocks_message_common.h"

#include <bpl/bpl_arp.h>
#include <bpl/bpl_cfg.h>

#include <unordered_map>
#include <unordered_set>

namespace beerocks {
namespace platform_manager {

extern std::string extern_query_db(const std::string &parameter);

class main_thread : public socket_thread {

public:
    main_thread(const config_file::sConfigSlave &config_,
                const std::unordered_map<int, std::string> &interfaces_map, logging &logger_,
                std::unique_ptr<beerocks::net::ServerSocket> server_socket,
                std::shared_ptr<beerocks::net::CmduParser> cmdu_parser,
                std::shared_ptr<beerocks::net::CmduSerializer> cmdu_serializer,
                std::shared_ptr<beerocks::EventLoop> event_loop);
    ~main_thread();

    virtual bool init() override;
    virtual bool work() override;

    /**
     * @brief Starts platform manager.
     *
     * @return true on success and false otherwise.
     */
    bool to_be_renamed_to_start();

    /**
     * @brief Stops platform manager.
     *
     * @return true on success and false otherwise.
     */
    bool to_be_renamed_to_stop();

protected:
    virtual bool handle_cmdu(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx) override;
    virtual void after_select(bool timeout);
    virtual void on_thread_stop() override;
    virtual bool socket_disconnected(Socket *sd) override;
    virtual std::string print_cmdu_types(const beerocks::message::sUdsHeader *cmdu_header) override;

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
    void arp_entries_cleanup();
    bool init_dhcp_monitor();
    bool init_arp_monitor();
    void stop_arp_monitor();
    bool restart_arp_monitor();
    bool wlan_params_changed_check();

private:
    const int PLATFORM_READ_CONF_RETRY_SEC    = 5;
    const int PLATFORM_READ_CONF_MAX_ATTEMPTS = 10;

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

    // File descriptor of the backhaul manager slave
    int m_pBackhaulManagerSlave = beerocks::net::FileDescriptor::invalid_descriptor;

    bpl::BPL_ARP_MON_CTX m_ctxArpMon = nullptr;
    Socket *m_pArpMonSocket          = nullptr;
    Socket *m_pArpRawSocket          = nullptr;
    Socket *m_pDHCPMonSocket         = nullptr;

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
     * Map of file descriptors to pointers to Socket class instances.
     * This member variable is temporary and will be removed at the end of PPM-591
     */
    std::unordered_map<int, Socket *> m_fd_to_socket_map;
};

} // namespace platform_manager
} // namespace beerocks

#endif // _PLATFORM_MANAGER_THREAD_H
