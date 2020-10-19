/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _SON_MASTER_THREAD_H
#define _SON_MASTER_THREAD_H

#include "controller_ucc_listener.h"
#include "db/db.h"
#include "periodic/periodic_operation_pool.h"
#include "tasks/optimal_path_task.h"
#include "tasks/task_pool.h"

#include "../../../common/beerocks/bwl/include/bwl/base_wlan_hal.h"
#include <bcl/beerocks_cmdu_server.h>
#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_event_loop.h>
#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_message_structs.h>
#include <bcl/beerocks_socket_thread.h>
#include <bcl/beerocks_timer_manager.h>
#include <bcl/beerocks_ucc_server.h>
#include <bcl/network/file_descriptor.h>
#include <bcl/network/network_utils.h>
#include <btl/broker_client.h>

#include <btl/broker_client_factory.h>

#include <mapf/common/encryption.h>
#include <tlvf/WSC/configData.h>
#include <tlvf/WSC/m1.h>
#include <tlvf/WSC/m2.h>
#include <tlvf/ieee_1905_1/tlvWsc.h>
#include <tlvf/wfa_map/tlvApRadioBasicCapabilities.h>

#include <btl/btl.h>

#include <cstddef>
#include <ctime>
#include <stdint.h>

namespace son {
class master_thread : public beerocks::btl::transport_socket_thread {

public:
    master_thread(const std::string &master_uds_, db &database_,
                  std::shared_ptr<beerocks::btl::BrokerClientFactory> broker_client_factory,
                  std::unique_ptr<beerocks::UccServer> ucc_server,
                  std::unique_ptr<beerocks::CmduServer> cmdu_server,
                  std::shared_ptr<beerocks::TimerManager> timer_manager,
                  std::shared_ptr<beerocks::EventLoop> event_loop);
    virtual ~master_thread();

    /**
     * @brief Starts controller.
     *
     * @return true on success and false otherwise.
     */
    bool to_be_renamed_to_start();

    /**
     * @brief Stops controller.
     *
     * @return true on success and false otherwise.
     */
    bool to_be_renamed_to_stop();

    virtual bool init() override;
    virtual bool work() override;

    /**
     * @brief Sends given CMDU message through the specified socket connection.
     *
     * @param fd File descriptor of the connected socket.
     * @param cmdu_tx CMDU message to send.
     * @return true on success and false otherwise.
     */
    bool send_cmdu(int fd, ieee1905_1::CmduMessageTx &cmdu_tx);

    /**
     * @brief Sends given CMDU message to the broker server running in the transport process to be
     * forwarded to another device or multicast.
     *
     * @param cmdu_tx CMDU message to send.
     * @param dst_mac Destination MAC address (must not be empty).
     * @param src_mac Source MAC address (must not be empty).
     * @param iface_name Name of the network interface to use (set to empty string to send on all
     * available interfaces).
     * @return true on success and false otherwise.
     */
    bool send_cmdu_to_broker(ieee1905_1::CmduMessageTx &cmdu_tx, const sMacAddr &dst_mac,
                             const sMacAddr &src_mac, const std::string &iface_name = "");

protected:
    virtual bool handle_cmdu(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx) override;
    virtual bool socket_disconnected(Socket *sd) override;
    virtual void before_select() override;
    virtual void after_select(bool timeout) override;
    virtual std::string print_cmdu_types(const beerocks::message::sUdsHeader *cmdu_header) override;

private:
    /**
     * @brief Handles the client-connected event in the CMDU server.
     *
     * @param fd File descriptor of the socket that got connected.
     */
    void handle_connected(int fd);

    /**
     * @brief Handles the client-disconnected event in the CMDU server.
     *
     * @param fd File descriptor of the socket that got disconnected.
     */
    void handle_disconnected(int fd);

    /**
     * @brief Handles received CMDU message.
     *
     * @param fd File descriptor of the socket connection the CMDU was received through.
     * @param iface_index Index of the network interface that the CMDU message was received on.
     * @param dst_mac Destination MAC address.
     * @param src_mac Source MAC address.
     * @param cmdu_rx Received CMDU to be handled.
     * @return true on success and false otherwise.
     */
    bool handle_cmdu(int fd, uint32_t iface_index, const sMacAddr &dst_mac, const sMacAddr &src_mac,
                     ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles CMDU message received from broker.
     *
     * This handler is slightly different than the handler for CMDU messages received from other
     * processes as it checks the source and destination MAC addresses set by the original sender.
     * It also filters out messages that are not addressed to the controller.
     *
     * @param iface_index Index of the network interface that the CMDU message was received on.
     * @param dst_mac Destination MAC address.
     * @param src_mac Source MAC address.
     * @param cmdu_rx Received CMDU to be handled.
     * @return true on success and false otherwise.
     */
    bool handle_cmdu_from_broker(uint32_t iface_index, const sMacAddr &dst_mac,
                                 const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    bool handle_cmdu_1905_1_message(const std::string &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_control_message(const std::string &src_mac,
                                     std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    void handle_cmdu_control_ieee1905_1_message(const std::string &src_mac,
                                                ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_intel_slave_join(const std::string &src_mac,
                                 std::shared_ptr<wfa_map::tlvApRadioBasicCapabilities> radio_caps,
                                 beerocks::beerocks_header &beerocks_header,
                                 ieee1905_1::CmduMessageTx &cmdu_tx);
    bool
    handle_non_intel_slave_join(const std::string &src_mac,
                                std::shared_ptr<wfa_map::tlvApRadioBasicCapabilities> radio_caps,
                                WSC::m1 &m1, std::string bridge_mac, std::string radio_mac,
                                ieee1905_1::CmduMessageTx &cmdu_tx);

    bool construct_combined_infra_metric();

    // 1905 messages handlers
    bool handle_cmdu_1905_autoconfiguration_search(const std::string &src_mac,
                                                   ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_autoconfiguration_WSC(const std::string &src_mac,
                                                ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_link_metric_response(const std::string &src_mac,
                                               ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_ap_metric_response(const std::string &src_mac,
                                             ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_ap_capability_report(const std::string &src_mac,
                                               ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_channel_preference_report(const std::string &src_mac,
                                                    ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_channel_selection_response(const std::string &src_mac,
                                                     ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_operating_channel_report(const std::string &src_mac,
                                                   ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_ack_message(const std::string &src_mac,
                                      ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_higher_layer_data_message(const std::string &src_mac,
                                                    ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_steering_completed_message(const std::string &src_mac,
                                                     ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_client_steering_btm_report_message(const std::string &src_mac,
                                                             ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_client_capability_report_message(const std::string &src_mac,
                                                           ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_topology_notification(const std::string &src_mac,
                                                ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_topology_response(const std::string &src_mac,
                                            ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_beacon_response(const std::string &src_mac,
                                          ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_backhaul_sta_steering_response(const std::string &src_mac,
                                                         ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_tunnelled_message(const std::string &src_mac,
                                            ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_1905_failed_connection_message(const std::string &src_mac,
                                                    ieee1905_1::CmduMessageRx &cmdu_rx);
    bool autoconfig_wsc_parse_radio_caps(
        std::string radio_mac, std::shared_ptr<wfa_map::tlvApRadioBasicCapabilities> radio_caps);
    // Autoconfig encryption support
    bool autoconfig_wsc_add_m2(WSC::m1 &m1, const wireless_utils::sBssInfoConf *bss_info_conf);
    bool autoconfig_wsc_add_m2_encrypted_settings(WSC::m2::config &m2_cfg,
                                                  WSC::configData &config_data, uint8_t authkey[32],
                                                  uint8_t keywrapkey[16]);
    bool autoconfig_wsc_authentication(WSC::m1 &m1, WSC::m2 &m2, uint8_t authkey[32]);
    void autoconfig_wsc_calculate_keys(WSC::m1 &m1, WSC::m2::config &m2_cfg,
                                       const mapf::encryption::diffie_hellman &dh,
                                       uint8_t authkey[32], uint8_t keywrapkey[16]);

    db &database;
    task_pool tasks;
    periodic_operation_pool operations;
    beerocks::controller_ucc_listener m_controller_ucc_listener;

    /**
     * Factory to create broker client instances connected to broker server.
     * Broker client instances are used to exchange CMDU messages with remote processes running in
     * other devices in the network via the broker server running in the transport process.
     */
    std::shared_ptr<beerocks::btl::BrokerClientFactory> m_broker_client_factory;

    /**
     * CMDU server to exchange CMDU messages with clients through socket connections.
     */
    std::shared_ptr<beerocks::CmduServer> m_cmdu_server;

    /**
     * Timer manager to help using application timers.
     */
    std::shared_ptr<beerocks::TimerManager> m_timer_manager;

    /**
     * Application event loop used by the process to wait for I/O events.
     */
    std::shared_ptr<beerocks::EventLoop> m_event_loop;

    /**
     * Map of file descriptors to pointers to Socket class instances.
     * This member variable is temporary and will be removed at the end of PPM-591
     */
    std::unordered_map<int, Socket *> m_fd_to_socket_map;

    /**
     * File descriptor of the timer to run internal tasks periodically.
     */
    int m_tasks_timer = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * File descriptor of the timer to run periodic operations.
     */
    int m_operations_timer = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * Broker client to exchange CMDU messages with broker server running in transport process.
     */
    std::unique_ptr<beerocks::btl::BrokerClient> m_broker_client;
};

} // namespace son

#endif
