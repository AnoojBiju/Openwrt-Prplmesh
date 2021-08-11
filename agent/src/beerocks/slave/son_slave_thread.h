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

#include <beerocks/tlvf/beerocks_header.h>

#include <mapf/common/encryption.h>
#include <tlvf/WSC/configData.h>
#include <tlvf/WSC/m1.h>
#include <tlvf/WSC/m2.h>
#include <tlvf/ieee_1905_1/tlvWsc.h>
#include <tlvf/wfa_map/tlvChannelPreference.h>
#include <tlvf/wfa_map/tlvProfile2ErrorCode.h>

// Forward decleration
namespace beerocks_message {
class cChannelList;
}

namespace beerocks {
namespace bpl {
enum class eErrorCode;
}
} // namespace beerocks

namespace son {
class slave_thread : public beerocks::socket_thread {

public:
    struct sAgentConfig {
        // Common configuration from Agent configuration file.
        std::string temp_path;
        std::string vendor;
        std::string model;
        uint16_t ucc_listener_port;
        std::string bridge_iface;
        int stop_on_failure_attempts;
        std::string backhaul_preferred_bssid;

        // Radio configuration
        struct sRadioConfig {
            std::string backhaul_wireless_iface;
            int hostap_ant_gain;
            bool enable_repeater_mode;
            beerocks::eIfaceType hostap_iface_type;

            // This parameter does not exist on the configuration file.
            // Need to check if it still needded. Meanwhile keep it. PPM-1550.
            bool backhaul_wireless_iface_filter_low;
        };

        // key: fronthaul interface name
        std::unordered_map<std::string, sRadioConfig> radios;
    };

    typedef struct {
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
        // General
        STATE_WAIT_BEFORE_INIT = 0,
        STATE_INIT,
        STATE_LOAD_PLATFORM_CONFIGURATION,
        STATE_CONNECT_TO_PLATFORM_MANAGER,
        STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE,
        STATE_STOPPED,

        // This state is the last common state. It means the from now each radio will have a state
        // of its own, specified under "Radio Specific" down below.
        STATE_RADIO_SPECIFIC_FSM,

        // Radio Specific
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
        STATE_PRE_OPERATIONAL,
        STATE_OPERATIONAL,
        STATE_VERSION_MISMATCH,
        STATE_SSID_MISMATCH,
    };

    slave_thread(sAgentConfig conf, beerocks::logging &logger_);
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
        const std::string &fronthaul_iface, Socket *sd,
        std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_platform_manager_message(
        Socket *sd, std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_ap_manager_message(const std::string &fronthaul_iface, Socket *sd,
                                        std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_monitor_message(const std::string &fronthaul_iface, Socket *sd,
                                     std::shared_ptr<beerocks::beerocks_header> beerocks_header);
    bool handle_cmdu_control_ieee1905_1_message(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_ap_manager_ieee1905_1_message(const std::string &fronthaul_iface, Socket &sd,
                                                   ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_cmdu_monitor_ieee1905_1_message(const std::string &fronthaul_iface, Socket &sd,
                                                ieee1905_1::CmduMessageRx &cmdu_rx);

    bool slave_fsm(const std::string &fronthaul_iface);
    bool agent_fsm();
    void slave_reset(const std::string &fronthaul_iface);
    void stop_slave_thread();
    void backhaul_manager_stop(const std::string &fronthaul_iface);
    void platform_manager_stop();
    void hostap_services_off();
    bool hostap_services_on();
    void fronthaul_start(const std::string &fronthaul_iface);
    void fronthaul_stop(const std::string &fronthaul_iface);
    void log_son_config(const std::string &fronthaul_iface);
    void platform_notify_error(beerocks::bpl::eErrorCode code, const std::string &error_data);
    bool monitor_heartbeat_check(const std::string &fronthaul_iface);
    bool ap_manager_heartbeat_check(const std::string &fronthaul_iface);
    bool send_cmdu_to_controller(const std::string &fronthaul_iface,
                                 ieee1905_1::CmduMessageTx &cmdu_tx);

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

    std::string backhaul_manager_uds;
    std::string platform_manager_uds;

    SocketClient *m_platform_manager_socket = nullptr;

    // Global FSM members:
    eSlaveState m_agent_state;
    std::chrono::steady_clock::time_point m_agent_state_timer_sec =
        std::chrono::steady_clock::time_point::min();

    struct sManagedRadio {
        beerocks_message::sSonConfig son_config;
        int stop_on_failure_attempts;
        int connect_platform_retry_counter = 0;
        bool stopped                       = false;
        bool is_backhaul_disconnected      = false;
        bool is_slave_reset                = false;
        bool is_backhaul_reconf            = false;
        bool detach_on_conf_change         = false;
        bool configuration_in_progress     = false;
        bool is_backhaul_manager           = false;
        bool autoconfiguration_completed;
        //slave FSM //
        eSlaveState slave_state;
        std::chrono::steady_clock::time_point slave_state_timer;
        int slave_resets_counter = 0;

        sSlaveBackhaulParams backhaul_params;
        SocketClient *backhaul_manager_socket = nullptr;
        SocketClient *master_socket           = nullptr;

        Socket *monitor_socket    = nullptr;
        Socket *ap_manager_socket = nullptr;
        std::chrono::steady_clock::time_point monitor_last_seen;
        std::chrono::steady_clock::time_point ap_manager_last_seen;
        int monitor_retries_counter    = 0;
        int ap_manager_retries_counter = 0;

        int last_reported_backhaul_rssi = beerocks::RSSI_INVALID;

        std::unique_ptr<mapf::encryption::diffie_hellman> dh = nullptr;
        //copy of M1 message used for authentication
        uint8_t *m1_auth_buf   = nullptr;
        size_t m1_auth_buf_len = 0;
    };

    class cRadioManagers {
        // Regular interfaces list.
        // Key: fronthaul iface name
        std::map<std::string, sManagedRadio> m_radio_managers;
        std::unique_ptr<std::pair<std::string, sManagedRadio>> m_zwdfs_radio_manager;

        sManagedRadio &get_radio_context(const std::string &fronthaul_iface)
        {
            return m_zwdfs_radio_manager && m_zwdfs_radio_manager->first == fronthaul_iface
                       ? m_zwdfs_radio_manager->second
                       : m_radio_managers[fronthaul_iface];
        }

    public:
        sManagedRadio &operator[](const std::string &fronthaul_iface)
        {
            return get_radio_context(fronthaul_iface);
        }

        std::map<std::string, sManagedRadio> &get() { return m_radio_managers; }
        std::unique_ptr<std::pair<std::string, sManagedRadio>> &get_zwdfs()
        {
            return m_zwdfs_radio_manager;
        }

        void set_zwdfs(std::map<std::string, sManagedRadio>::iterator &it)
        {
            m_zwdfs_radio_manager  = std::make_unique<std::pair<std::string, sManagedRadio>>();
            *m_zwdfs_radio_manager = std::move(*it);
            m_radio_managers.erase(it);
        }

        const std::string &get_controller_socket_iface()
        {
            for (auto &radio : get()) {
                if (radio.second.master_socket) {
                    return radio.first;
                }
            }
            return m_radio_managers.begin()->first;
        }

        /**
         * @brief Preform an operation in context of each radio.
         *
         * @param operation An operation function that receives as input arguments the radio
         * manager context and its fronthaul interface name.
         * @return true if the operation succeeds in all radios, otherwise false.
         */
        bool do_on_each_radio_manager(
            std::function<bool(sManagedRadio &radio_manager, const std::string &fronthaul_iface)>
                operation)
        {
            auto success = true;
            for (auto &radio : get()) {
                success &= operation(radio.second, radio.first);
            }
            auto &zwdfs_radio = get_zwdfs();
            if (!zwdfs_radio) {
                return success;
            }
            success &= operation(zwdfs_radio->second, zwdfs_radio->first);
            return success;
        };
    } m_radio_managers;

    /**
     * @brief check if there was an error in the constructor
     *
     * @return false if no errors occurred in the constructor, true otherwise
     */
    bool m_constructor_failed = false;

    sAgentConfig config;

    beerocks::logging &logger;
    std::string master_version;
    bool m_logger_configured = false;

    // Encryption support - move to common library
    bool autoconfig_wsc_calculate_keys(const std::string &fronthaul_iface, WSC::m2 &m2,
                                       uint8_t authkey[32], uint8_t keywrapkey[16]);
    bool autoconfig_wsc_parse_m2_encrypted_settings(WSC::m2 &m2, uint8_t authkey[32],
                                                    uint8_t keywrapkey[16],
                                                    WSC::configData::config &config);
    bool autoconfig_wsc_authenticate(const std::string &fronthaul_iface, WSC::m2 &m2,
                                     uint8_t authkey[32]);

    bool parse_intel_join_response(const std::string &fronthaul_iface, Socket *sd,
                                   beerocks::beerocks_header &beerocks_header);
    bool parse_non_intel_join_response(const std::string &fronthaul_iface, Socket *sd);
    bool handle_autoconfiguration_wsc(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_autoconfiguration_renew(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool autoconfig_wsc_add_m1(const std::string &fronthaul_iface);
    bool send_operating_channel_report(const std::string &fronthaul_iface);
    bool handle_ap_metrics_query(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_monitor_ap_metrics_response(const std::string &fronthaul_iface, Socket &sd,
                                            ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_channel_preference_query(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_channel_selection_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool get_controller_channel_preference(const std::string &fronthaul_iface,
                                           ieee1905_1::CmduMessageRx &cmdu_rx);
    bool channel_selection_get_transmit_power_limit(const std::string &fronthaul_iface,
                                                    ieee1905_1::CmduMessageRx &cmdu_rx,
                                                    int &power_limit);
    bool channel_selection_current_channel_restricted(const std::string &fronthaul_iface);
    beerocks::message::sWifiChannel
    channel_selection_select_channel(const std::string &fronthaul_iface);
    bool handle_multi_ap_policy_config_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_client_association_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_1905_higher_layer_data_message(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_client_steering_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_beacon_metrics_query(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_ack_message(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_profile2_default_802dotq_settings_tlv(ieee1905_1::CmduMessageRx &cmdu_rx);
    bool handle_profile2_traffic_separation_policy_tlv(
        ieee1905_1::CmduMessageRx &cmdu_rx, std::unordered_set<std::string> &misconfigured_ssids);

    bool send_error_response(
        const std::deque<std::pair<wfa_map::tlvProfile2ErrorCode::eReasonCode, sMacAddr>>
            &bss_errors);

    /**
     * @brief Save channel list into AgentDB from beerocks_message::cChannelList class.
     *
     * @param channel_list_class A shared pointer to channel_list_class.
     */
    void fill_channel_list_to_agent_db(
        const std::string &fronthaul_iface,
        const std::shared_ptr<beerocks_message::cChannelList> &channel_list_class);

    /**
     * @brief save channel switch parameters in the agent DB
     *
     * Save majority of sApChannelSwitch parameters in the agent DB.
     * Discard `switch_reason` and `is_dfs_channel` because they are not used in unified agent.
     */
    void save_channel_params_to_db(const std::string &fronthaul_iface,
                                   beerocks_message::sApChannelSwitch params);

    /**
     * @brief save cac capabilities in the agent DB
     */
    void save_cac_capabilities_params_to_db(const std::string &fronthaul_iface);

    struct sChannelPreference {
        sChannelPreference(uint8_t oper_class,
                           wfa_map::cPreferenceOperatingClasses::ePreference preference,
                           wfa_map::cPreferenceOperatingClasses::eReasonCode reason_code)
            : operating_class(oper_class)
        {
            flags.reason_code = reason_code;
            flags.preference  = preference;
        }
        sChannelPreference(uint8_t _operating_class,
                           wfa_map::cPreferenceOperatingClasses::sFlags _flags)
            : operating_class(_operating_class), flags(_flags)
        {
        }

        uint8_t operating_class;
        wfa_map::cPreferenceOperatingClasses::sFlags flags;

        bool operator==(const sChannelPreference &rhs) const
        {
            return operating_class == rhs.operating_class &&
                   flags.preference == rhs.flags.preference &&
                   flags.reason_code == rhs.flags.reason_code;
        }

        bool operator<(const sChannelPreference &rhs) const
        {
            if (operating_class != rhs.operating_class) {
                return operating_class < rhs.operating_class;
            }
            if (flags.preference != rhs.flags.preference) {
                return flags.preference < rhs.flags.preference;
            }
            if (flags.reason_code != rhs.flags.reason_code) {
                return flags.reason_code < rhs.flags.reason_code;
            }
            return false;
        }
    };
    std::map<sChannelPreference, std::set<uint8_t>> m_controller_channel_preferences;

    /**
     * @brief Get a std::map of channels preferences organized in a way it will be easy to fill
     * WFA Channel Preference Report.
     *
     * @return std::map of channels preferences.
     */
    std::map<sChannelPreference, std::set<uint8_t>>
    get_channel_preferences_from_channels_list(const std::string &fronthaul_iface);

    /**
     * @brief Get the channel preference.
     *
     * @pre The channel operating class and the preference operating class have to match.
     * @param channel A channel to check.
     * @param preference The preference of the channel.
     * @param preference_channels_list The preference channels list given by the Controller.
     * @return NON_OPERABLE if channel is restricted, channel preference otherwise.
     */
    wfa_map::cPreferenceOperatingClasses::ePreference
    get_channel_preference(beerocks::message::sWifiChannel channel,
                           const sChannelPreference &preference,
                           const std::set<uint8_t> &preference_channels_list);
};

} // namespace son

#endif
