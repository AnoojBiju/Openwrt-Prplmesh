/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BACKHAUL_MANAGER_THREAD_H
#define _BACKHAUL_MANAGER_THREAD_H

#include "../tasks/task_pool.h"
#include "wan_monitor.h"

#include <bcl/beerocks_backport.h>
#include <bcl/beerocks_cmdu_client_factory.h>
#include <bcl/beerocks_cmdu_server.h>
#include <bcl/beerocks_config_file.h>
#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_event_loop.h>
#include <bcl/beerocks_socket_thread.h>
#include <bcl/beerocks_timer_manager.h>
#include <bcl/beerocks_ucc_server.h>
#include <bcl/network/file_descriptor.h>
#include <bcl/network/network_utils.h>
#include <btl/broker_client.h>
#include <btl/broker_client_factory.h>
#include <btl/btl.h>
#include <bwl/sta_wlan_hal.h>

#include <beerocks/tlvf/beerocks_message_header.h>

#include <tlvf/ieee_1905_1/eLinkMetricsType.h>
#include <tlvf/ieee_1905_1/eMediaType.h>

#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvErrorCode.h>

#include "../agent_db.h"
#include "../agent_ucc_listener.h"
#include "../helpers/link_metrics/link_metrics.h"

#include <future>
#include <list>

namespace beerocks {

namespace bpl {
enum class eErrorCode;
}

class ChannelSelectionTask;

class backhaul_manager : public btl::transport_socket_thread {

public:
    backhaul_manager(
        const config_file::sConfigSlave &config, const std::set<std::string> &slave_ap_ifaces_,
        const std::set<std::string> &slave_sta_ifaces_, int stop_on_failure_attempts_,
        std::unique_ptr<beerocks::btl::BrokerClientFactory> broker_client_factory,
        std::unique_ptr<beerocks::CmduClientFactory> platform_manager_cmdu_client_factory,
        std::unique_ptr<beerocks::UccServer> ucc_server,
        std::unique_ptr<beerocks::CmduServer> cmdu_server,
        std::shared_ptr<beerocks::TimerManager> timer_manager,
        std::shared_ptr<beerocks::EventLoop> event_loop);
    ~backhaul_manager();

    /**
     * @brief Starts backhaul manager.
     *
     * @return true on success and false otherwise.
     */
    bool to_be_renamed_to_start();

    /**
     * @brief Stops backhaul manager.
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
     * @brief Forwards given received CMDU message through the specified socket connection.
     *
     * @param fd File descriptor of the connected socket.
     * @param iface_index Index of the network interface that the CMDU message was received on.
     * @param dst_mac Destination MAC address.
     * @param src_mac Source MAC address.
     * @param cmdu_rx Received CMDU message to forward.
     * @return true on success and false otherwise.
     */
    bool forward_cmdu_to_uds(int fd, uint32_t iface_index, const sMacAddr &dst_mac,
                             const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    // For agent_ucc_listener
    /**
     * @brief get radio mac (ruid) of registered slave based on frequency type
     * 
     * @param freq radio frequency to search
     * @return radio mac of the found slave if found, otherwise empty string
     */
    const std::string freq_to_radio_mac(eFreqType freq) const;

    /**
     * @brief start WPS PBC
     * 
     * @param radio_mac radio mac of the radio on which to start WPS
     * @return true on success, false on failure
     */
    bool start_wps_pbc(const sMacAddr &radio_mac);

    // Forward declaration
    struct sRadioInfo;

private:
    std::shared_ptr<bwl::sta_wlan_hal> get_selected_backhaul_sta_wlan_hal();

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

    virtual bool handle_cmdu(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx) override;
    virtual void before_select() override;
    virtual void after_select(bool timeout) override;
    virtual void on_thread_stop() override;
    virtual void socket_connected(Socket *sd) override;
    virtual bool socket_disconnected(Socket *sd) override;
    virtual std::string print_cmdu_types(const beerocks::message::sUdsHeader *cmdu_header) override;

    bool backhaul_fsm_main(bool &skip_select);
    bool backhaul_fsm_wired(bool &skip_select);
    bool backhaul_fsm_wireless(bool &skip_select);
    bool is_front_radio(std::string mac);
    bool
    finalize_slaves_connect_state(bool fConnected,
                                  std::shared_ptr<sRadioInfo> pSocket = nullptr); // cmdu_duplicate

    /**
     * @brief Creates Backhaul STA Steering Response message with 2 tlvs Steering Response
     *        and Error Code.
     *
     * @param error_code One of the error codes presented in wfa_map::tlvErrorCode::eReasonCode.
     * @return True on success and false otherwise
     */
    bool create_backhaul_steering_response(const wfa_map::tlvErrorCode::eReasonCode &error_code);

    // cmdu handlers
    bool handle_master_message(ieee1905_1::CmduMessageRx &cmdu_rx,
                               std::shared_ptr<beerocks_message::cACTION_HEADER> beerocks_header);
    bool handle_slave_backhaul_message(std::shared_ptr<sRadioInfo> soc,
                                       ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_slave_1905_1_message(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                                     const sMacAddr &dst_mac, const sMacAddr &src_mac);
    bool handle_1905_1_message(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                               const sMacAddr &dst_mac, const sMacAddr &src_mac, int &forward_to);
    // 1905 messages handlers
    bool handle_slave_failed_connection_message(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                const sMacAddr &src_mac);
    bool handle_backhaul_steering_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                          const sMacAddr &src_mac);

    //bool sta_handle_event(const std::string &iface,const std::string& event_name, void* event_obj);
    bool hal_event_handler(bwl::base_wlan_hal::hal_event_ptr_t event_ptr, std::string iface);

    bool is_eth_link_up();
    void get_scan_measurement();
    bool select_bssid();
    void platform_notify_error(bpl::eErrorCode code, const std::string &error_data);
    bool send_slaves_enable();

    std::shared_ptr<bwl::sta_wlan_hal> get_wireless_hal(std::string iface = "");

private:
    const std::string &beerocks_temp_path;

    struct SBackhaulConfig {
        std::string ssid;
        std::string pass;
        std::string preferred_bssid;
        beerocks::eIfaceType wire_iface_type;
        beerocks::eIfaceType wireless_iface_type;
        bwl::WiFiSec security_type;
        bool mem_only_psk;
        eFreqType backhaul_preferred_radio_band;

        // Slave handling the active wireless connection
        // std::shared_ptr<bwl::sta_wlan_hal> active_slave_hal;
        std::unordered_map<std::string, std::shared_ptr<sRadioInfo>> slave_iface_socket;

    } m_sConfig;

    int m_unassociated_measurement_slave_soc    = beerocks::net::FileDescriptor::invalid_descriptor;
    int unassociated_rssi_measurement_header_id = -1;

    //comes from config file
    const std::set<std::string> slave_ap_ifaces;
    const std::set<std::string> slave_sta_ifaces;

    //used for several states independently
    std::set<std::string> pending_slave_ifaces;
    std::set<std::string> pending_slave_sta_ifaces;

public:
    std::list<std::shared_ptr<sRadioInfo>> slaves_sockets;

private:
    std::list<std::shared_ptr<sRadioInfo>> m_slaves_sockets_to_finalize;

    // TODO: Temporary change, will be removed on Unified Agent PPM-351.
    // Key: front radio iface name, Value: sRadioInfo object
    std::unordered_map<std::string, std::shared_ptr<sRadioInfo>> m_disabled_slave_sockets;

    std::shared_ptr<SocketClient> m_scPlatform;
    net::network_utils::iface_info bridge_info;

    int configuration_stop_on_failure_attempts;
    const std::string config_const_bh_slave;

    int stop_on_failure_attempts;
    bool onboarding = true;

    //backlist bssid and timers (remove con(or wrong passphrase) ap from select bssid for limited time )
    struct ap_blacklist_entry {
        std::chrono::steady_clock::time_point timestamp;
        int attempts = 0;
    };
    std::unordered_map<std::string, ap_blacklist_entry> ap_blacklist;

    wan_monitor wan_mon;

    // Future to hold the DHCP client process exit code
    std::future<int> m_ftDHCPRetCode;

    // state switch mechanism
    const int SELECT_TIMEOUT_MSC                      = 500;
    const int DEVICE_QUERY_RESPONSE_TIMEOUT_SECONDS   = 3;
    const int WAIT_FOR_SCAN_RESULTS_TIMEOUT_SECONDS   = 20;
    const int WPA_ATTACH_TIMEOUT_SECONDS              = 5;
    const int CONNECTING_TO_MASTER_TIMEOUT_SECONDS    = 30;
    const int MAX_FAILED_SCAN_ATTEMPTS                = 3;
    const int MAX_FAILED_ROAM_SCAN_ATTEMPTS           = 4;
    const int MAX_FAILED_DHCP_ATTEMPTS                = 2;
    const int MAX_WIRELESS_ASSOCIATE_TIMEOUT_SECONDS  = 10;
    const int MAX_WIRELESS_ASSOCIATE_3ADDR_ATTEMPTS   = 2;
    const int POLL_TIMER_TIMEOUT_MS                   = 1000;
    const int WIRELESS_WAIT_FOR_RECONNECT_TIMEOUT     = 2;
    const int RSSI_POLL_INTERVAL_MS                   = 1000;
    const int STATE_WAIT_ENABLE_TIMEOUT_SECONDS       = 600;
    const int STATE_WAIT_WPS_TIMEOUT_SECONDS          = 600;
    const int AP_BLACK_LIST_TIMEOUT_SECONDS           = 120;
    const int AP_BLACK_LIST_FAILED_ATTEMPTS_THRESHOLD = 2;
    const int INTERFACE_BRING_UP_TIMEOUT_SECONDS      = 600;
    const int DEAUTH_REASON_PASSPHRASE_MISMACH        = 2;

    std::chrono::steady_clock::time_point state_time_stamp_timeout;
    int state_attempts;

    bool hidden_ssid = false;

    std::string selected_bssid;
    int selected_bssid_channel;
    std::string roam_selected_bssid;
    int roam_selected_bssid_channel;
    bool roam_flag = false;
    std::unordered_map<std::string, net::sScanResult> scan_measurement_list;

    const int RSSI_THRESHOLD_5GHZ       = -80;
    const int RSSI_BAND_DELTA_THRESHOLD = 5;

    std::chrono::steady_clock::time_point rssi_poll_timer;
    std::chrono::steady_clock::time_point eth_link_poll_timer;
    bool m_eth_link_up  = false;
    bool pending_enable = false;

    std::string bssid_bridge_mac;

    std::unique_ptr<beerocks::agent_ucc_listener> m_agent_ucc_listener;

    TaskPool m_task_pool;
    friend ChannelSelectionTask;

public:
    /**
     * Unsuccessful Association Policy
     */
    struct sUnsuccessfulAssociationPolicy {
        /* The values in this struct are set by the controller through a Multi-AP Policy Config Request message,
         * inside the Unsuccessful Association Policy TLV.
         */

        /**
         * Report or Don't report unsuccessful associations of clients
         */
        bool report_unsuccessful_association = false;

        /**
         * Maximum Reporting Rate of failed associations in attempts per minute
         */
        uint32_t maximum_reporting_rate = 0;

        /**
         * Time point at which failed associatoin was reported for the last time.
         */
        std::chrono::steady_clock::time_point last_reporting_time_point =
            std::chrono::steady_clock::time_point::min(); // way in the past

        /**
         * Number of reports in the last minute
         */
        uint32_t number_of_reports_in_last_minute = 0;
    } unsuccessful_association_policy;

    /**
     * @brief Information gathered about a radio (= slave).
     *
     * Radio information is obtained from messages sent by slave threads and is used to build
     * the TLVs to include in notification messages or responses to CDMU query messages.
     */
    struct sRadioInfo {
        int slave = beerocks::net::FileDescriptor::
            invalid_descriptor; /**< File descriptor of the socket connection established from the slave to the CMDU server. */
        sMacAddr radio_mac;       /**< Radio ID (= radio MAC address) */
        std::string hostap_iface; /**< Name of the radio interface */
        std::string sta_iface;    /**< Name of the bSTA interface on the radio (if any) */
        bool slave_is_backhaul_manager = false;

        std::shared_ptr<bwl::sta_wlan_hal> sta_wlan_hal;
        Socket *sta_hal_ext_events = nullptr;
        Socket *sta_hal_int_events = nullptr;
    };

public:
    /**
     * @brief Gets radio info for the radio with given MAC address
     *
     * @param[in] radio_mac MAC address of the radio
     * @return shared pointer to radio info in case of success or nullptr otherwise
     */
    std::shared_ptr<sRadioInfo> get_radio(const sMacAddr &radio_mac) const;

private:
    bool m_backhaul_sta_steering_enable = false;

    /*
 * State Machines
 */
private:
// Helper MACROs for Enum/String generation
#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

#define FOREACH_STATE(STATE)                                                                       \
    STATE(INIT)                                                                                    \
    STATE(WAIT_ENABLE)                                                                             \
    STATE(ENABLED)                                                                                 \
                                                                                                   \
    STATE(_WIRELESS_START_)                                                                        \
    STATE(INIT_HAL)                                                                                \
    STATE(WPA_ATTACH)                                                                              \
    STATE(INITIATE_SCAN)                                                                           \
    STATE(WAIT_WPS)                                                                                \
    STATE(WAIT_FOR_SCAN_RESULTS)                                                                   \
    STATE(WIRELESS_CONFIG_4ADDR_MODE)                                                              \
    STATE(WIRELESS_ASSOCIATE_4ADDR)                                                                \
    STATE(WIRELESS_ASSOCIATE_4ADDR_WAIT)                                                           \
    STATE(WIRELESS_WAIT_FOR_RECONNECT)                                                             \
    STATE(_WIRELESS_END_)                                                                          \
                                                                                                   \
    STATE(MASTER_DISCOVERY)                                                                        \
    STATE(WAIT_FOR_AUTOCONFIG_COMPLETE)                                                            \
    STATE(CONNECT_TO_MASTER)                                                                       \
    STATE(CONNECTED)                                                                               \
    STATE(OPERATIONAL)                                                                             \
    STATE(RESTART)                                                                                 \
    STATE(STOPPED)

    // States ENUM
    enum class EState { FOREACH_STATE(GENERATE_ENUM) };

    // States Strings Array
    static const char *s_arrStates[];

    EState m_eFSMState;

    /**
     * Factory to create broker client instances connected to broker server.
     * Broker client instances are used to exchange CMDU messages with remote processes running in
     * other devices in the network via the broker server running in the transport process.
     */
    std::unique_ptr<beerocks::btl::BrokerClientFactory> m_broker_client_factory;

    /**
     * Factory to create CMDU client instances connected to CMDU server running in platform manager.
     */
    std::unique_ptr<beerocks::CmduClientFactory> m_platform_manager_cmdu_client_factory;

    /**
     * UCC server to exchange commands and replies with UCC certification application.
     */
    std::unique_ptr<beerocks::UccServer> m_ucc_server;

    /**
     * CMDU server to exchange CMDU messages with clients through socket connections.
     */
    std::unique_ptr<beerocks::CmduServer> m_cmdu_server;

    /**
     * Timer manager to help using application timers.
     */
    std::shared_ptr<beerocks::TimerManager> m_timer_manager;

    /**
     * Application event loop used by the process to wait for I/O events.
     */
    std::shared_ptr<EventLoop> m_event_loop;

    /**
     * Map of file descriptors to pointers to Socket class instances.
     * This member variable is temporary and will be removed at the end of PPM-753
     */
    std::unordered_map<int, Socket *> m_fd_to_socket_map;

    /**
     * File descriptor of the timer to run internal tasks periodically.
     */
    int m_tasks_timer = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * File descriptor of the timer to run the Finite State Machine.
     */
    int m_fsm_timer = beerocks::net::FileDescriptor::invalid_descriptor;

    /**
     * Broker client to exchange CMDU messages with broker server running in transport process.
     */
    std::unique_ptr<beerocks::btl::BrokerClient> m_broker_client;
};

} // namespace beerocks

#endif // _BACKHAUL_MANAGER_THREAD_H
