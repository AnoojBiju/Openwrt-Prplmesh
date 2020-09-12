/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _SON_SLAVE_THREAD_H
#define _SON_SLAVE_THREAD_H

#include <bcl/beerocks_backport.h>
#include <bcl/beerocks_logging.h>
#include <bcl/beerocks_socket_thread.h>
#include <bcl/son/son_wireless_utils.h>

#include <beerocks/tlvf/beerocks_header.h>

#include <mapf/common/encryption.h>
#include <tlvf/WSC/configData.h>
#include <tlvf/WSC/m1.h>
#include <tlvf/WSC/m2.h>
#include <tlvf/ieee_1905_1/tlvWsc.h>

namespace beerocks {
namespace bpl {
enum class eErrorCode;
}
} // namespace beerocks

namespace son {
class slave_thread : public beerocks::socket_thread {

public:
    typedef struct {
        // from slave config file //
        std::string temp_path;
        std::string vendor;
        std::string model;
        uint16_t ucc_listener_port;
        std::string bridge_iface;
        int stop_on_failure_attempts;
        bool enable_repeater_mode;
        std::string backhaul_wire_iface;
        std::string backhaul_wireless_iface;
        bool backhaul_wireless_iface_filter_low;
        std::string backhaul_preferred_bssid;
        std::string hostap_iface;
        beerocks::eIfaceType hostap_iface_type;
        int hostap_ant_gain;
        std::string radio_identifier; //mAP RUID
    } sSlaveConfig;

    typedef struct {
        std::string gw_ipv4;
        std::string gw_bridge_mac;
        std::string bridge_ipv4;
        std::string backhaul_iface;
        std::string backhaul_mac;
        std::string backhaul_ipv4;
        std::string backhaul_bssid;
        uint32_t backhaul_freq;
        uint8_t backhaul_channel;
        uint8_t backhaul_is_wireless;
        uint8_t backhaul_iface_type;
        beerocks::net::sScanResult
            backhaul_scan_measurement_list[beerocks::message::BACKHAUL_SCAN_MEASUREMENT_MAX_LENGTH];
    } sSlaveBackhaulParams;

    enum eSlaveState {
        STATE_WAIT_BERFORE_INIT = 0,
        STATE_INIT,
        STATE_CONNECT_TO_PLATFORM_MANAGER,
        STATE_WAIT_FOR_PLATFORM_MANAGER_ONBOARD_QUERY_RESPONSE,
        STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE,
        STATE_WAIT_FOR_PLATFORM_MANAGER_CREDENTIALS_UPDATE_RESPONSE,
        STATE_CONNECT_TO_BACKHAUL_MANAGER,
        STATE_WAIT_RETRY_CONNECT_TO_BACKHAUL_MANAGER,
        STATE_WAIT_FOR_BACKHAUL_MANAGER_REGISTER_RESPONSE,
        STATE_JOIN_INIT,
        STATE_WAIT_FOR_FRONTHAUL_THREADS_JOINED,
        STATE_BACKHAUL_ENABLE,
        STATE_SEND_BACKHAUL_MANAGER_ENABLE,
        STATE_WAIT_FOR_BACKHAUL_MANAGER_CONNECTED_NOTIFICATION,
        STATE_BACKHAUL_MANAGER_CONNECTED,
        STATE_WAIT_BACKHAUL_MANAGER_BUSY,
        STATE_WAIT_BEFORE_JOIN_MASTER,
        STATE_JOIN_MASTER,
        STATE_WAIT_FOR_JOINED_RESPONSE,
        STATE_UPDATE_MONITOR_SON_CONFIG,
        STATE_OPERATIONAL,
        STATE_VERSION_MISMATCH,
        STATE_SSID_MISMATCH,
        STATE_STOPPED,
    };

    slave_thread(sSlaveConfig conf, beerocks::logging &logger_);
    virtual ~slave_thread();

    virtual bool init() override;
    virtual bool work() override;

protected:
    virtual bool handle_cmdu(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx) override;
    virtual void on_thread_stop() override;
    virtual bool socket_disconnected(Socket *sd) override;
    virtual std::string print_cmdu_types(const beerocks::message::sUdsHeader *cmdu_header) override;

private:
    bool handle_cmdu_control_message(Socket *sd,
                                     std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_backhaul_manager_message(
        Socket *sd, std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_platform_manager_message(
        Socket *sd, std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_ap_manager_message(Socket *sd,
                                        std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_monitor_message(Socket *sd,
                                     std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_control_ieee1905_1_message(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_ap_manager_ieee1905_1_message(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_monitor_ieee1905_1_message(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);

    bool slave_fsm(bool &call_slave_select);
    void slave_reset();
    void stop_slave_thread();
    void backhaul_manager_stop();
    void platform_manager_stop();
    void hostap_services_off();
    bool hostap_services_on();
    void fronthaul_start();
    void fronthaul_stop();
    void log_son_config();
    void platform_notify_error(beerocks::bpl::eErrorCode code, const std::string &error_data);
    bool monitor_heartbeat_check();
    bool ap_manager_heartbeat_check();
    bool send_cmdu_to_controller(ieee1905_1::CmduMessageTx &cmdu_tx);

private:
    const int SELECT_TIMEOUT_MSEC                                     = 200;
    const int SLAVE_INIT_DELAY_SEC                                    = 4;
    const int WAIT_FOR_JOINED_RESPONSE_TIMEOUT_SEC                    = 5;
    const int WAIT_BEFORE_SEND_SLAVE_JOINED_NOTIFICATION_SEC          = 1;
    const int WAIT_BEFORE_SEND_BH_ENABLE_NOTIFICATION_SEC             = 1;
    const int WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE_TIMEOUT_SEC = 600;
    const int MONITOR_HEARTBEAT_TIMEOUT_SEC                           = 10;
    const int MONITOR_HEARTBEAT_RETRIES                               = 10;
    const int AP_MANAGER_HEARTBEAT_TIMEOUT_SEC                        = 10;
    const int AP_MANAGER_HEARTBEAT_RETRIES                            = 10;
    const int CONNECT_PLATFORM_RETRY_SLEEP                            = 1000;
    const int CONNECT_PLATFORM_RETRY_COUNT_MAX                        = 5;

    int connect_platform_retry_counter = 0;

    std::string slave_uds;
    std::string backhaul_manager_uds;
    std::string platform_manager_uds;
    sSlaveConfig config;
    beerocks_message::sSonConfig son_config;
    beerocks::logging &logger;
    std::string master_version;
    int stop_on_failure_attempts;
    bool stopped                   = false;
    bool is_backhaul_disconnected  = false;
    bool is_slave_reset            = false;
    bool is_backhual_reconf        = false;
    bool detach_on_conf_change     = false;
    bool configuration_in_progress = false;
    bool m_logger_configured       = false;

    bool is_backhaul_manager = false;

    //slave FSM //
    eSlaveState slave_state;
    std::chrono::steady_clock::time_point slave_state_timer;
    int slave_resets_counter = 0;

    sSlaveBackhaulParams backhaul_params;
    std::vector<wireless_utils::sChannelPreference> channel_preferences;
    std::vector<beerocks::message::sWifiChannel> supported_channels;

    SocketClient *platform_manager_socket = nullptr;
    SocketClient *backhaul_manager_socket = nullptr;
    SocketClient *master_socket           = nullptr;

    Socket *monitor_socket    = nullptr;
    Socket *ap_manager_socket = nullptr;
    std::string m_fronthaul_iface;

    std::chrono::steady_clock::time_point monitor_last_seen;
    std::chrono::steady_clock::time_point ap_manager_last_seen;
    int monitor_retries_counter    = 0;
    int ap_manager_retries_counter = 0;

    int last_reported_backhaul_rssi = beerocks::RSSI_INVALID;

    // Encryption support - move to common library
    bool autoconfig_wsc_calculate_keys(WSC::m2 &m2, uint8_t authkey[32], uint8_t keywrapkey[16]);
    bool autoconfig_wsc_parse_m2_encrypted_settings(WSC::m2 &m2, uint8_t authkey[32],
                                                    uint8_t keywrapkey[16],
                                                    WSC::configData::config &config);
    bool autoconfig_wsc_authenticate(WSC::m2 &m2, uint8_t authkey[32]);

    std::unique_ptr<mapf::encryption::diffie_hellman> dh = nullptr;
    //copy of M1 message used for authentication
    uint8_t *m1_auth_buf   = nullptr;
    size_t m1_auth_buf_len = 0;

    /**
     * @brief check if there was an error in the constructor
     *
     * @return false if no errors occured in the constructor, true otherwise
     */
    bool m_constructor_failed = false;

    bool parse_intel_join_response(Socket *sd, beerocks::beerocks_header &beerocks_header);
    bool parse_non_intel_join_response(Socket *sd);
    bool handle_autoconfiguration_wsc(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_autoconfiguration_renew(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool autoconfig_wsc_add_m1();
    bool send_operating_channel_report();
    bool handle_ap_metrics_query(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_monitor_ap_metrics_response(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_channel_preference_query(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_channel_selection_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool channel_selection_get_channel_preference(ieee1905_1::CmduMessageRx &cmdu_rx);
    bool channel_selection_get_transmit_power_limit(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                    int &power_limit);
    bool channel_selection_current_channel_restricted();
    beerocks::message::sWifiChannel channel_selection_select_channel();
    bool handle_multi_ap_policy_config_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_client_association_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_1905_higher_layer_data_message(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_client_steering_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_beacon_metrics_query(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_ack_message(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief save channel switch parameters in the agent DB
     *
     * Save majority of sApChannelSwitch parameters in the agent DB.
     * Discard `switch_reason` and `is_dfs_channel` because they are not used in unified agent.
     */
    void save_channel_params_to_db(beerocks_message::sApChannelSwitch params);
};

} // namespace son

#endif
