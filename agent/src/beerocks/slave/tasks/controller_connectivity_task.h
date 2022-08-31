/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CONTROLLER_CONNECTIVITY_TASK_H_
#define _CONTROLLER_CONNECTIVITY_TASK_H_

#include "task.h"

namespace beerocks {

// Forward declaration for Agent context saving
class slave_thread;

/**
 * @brief ControllerConnectivityTask is responsible to maintain and observe connectivity to the controller.
 *
 * Main objectives are like;
 *  - Check timeout of Backhaul Connection Notification
 *  - Check timeout of Controller Communication
 *  - Provide mechanism to switch backhaul connection
 *
 * Configuration parameters:
 *  - check_connectivity_to_controller: disable/enable of this task functionality
 *  - check_indirect_connectivity_to_controller: disable/enable of checking connectivity of indirectly connected agents
 *  - backhaul_connection_timeout_sec: backhaul connection timeout.
 *  It is expected to finish controller discovery within this timeout period.
 *
 * - controller_message_timeout_sec: controller message timeout.
 *  If any message from controller is not received within this timeout period, it starts sending heartbeat.
 *
 * - controller_heartbeat_state_timeout_seconds: heartbeat state timeout.
 *  If any message from controller is not received within this timeout period after message timeout,
 *  it is counted as controller disconnection.
 *
 */
class ControllerConnectivityTask : public Task {
public:
    ControllerConnectivityTask(slave_thread &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~ControllerConnectivityTask() {}

    enum eEvent : uint8_t {
        INIT_TASK,
        BACKHAUL_MANAGER_CONNECTED,
        BACKHAUL_DISCONNECTED_NOTIFICATION,
        CONTROLLER_DISCOVERED,
    };

    void work() override;
    void handle_event(uint8_t event_enum_value, const void *event_obj) override;
    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    /**
     * @brief ControllerConnectivity Task states.
     *
     * INIT State
     * The 'INIT' state refers waiting for inital configuration and connection message
     * The 'WAIT_FOR_CONTROLLER_DISCOVERY' state refers after backhaul link is connected and
     * waiting controller gets discovered.
     *
     * The 'BACKHAUL_LINK_DISCONNECTED' state refers backhaul link is disconnected
     * The 'CONTROLLER_MONITORING' state refers after backhaul link is active and controller is found to monitor
     * The 'WAIT_RESPONSE_FROM_CONTROLLER' state refers last controller message timestamp expires message timeout time
     * In this state, heartbeats are send to verify disconnection and task waits to get response from Controller
     *
     * The 'CONNECTION_TIMEOUT' state refers last controller message timestamp expires connection timeout time
     * The 'DISCONNECT_COMMAND_SEND' state refers after deciding on connection command is send
     * and wait disconnection notification
     *
     */
    enum class eState : uint8_t {
        INIT,
        WAIT_FOR_CONTROLLER_DISCOVERY,
        CONTROLLER_MONITORING,
        WAIT_RESPONSE_FROM_CONTROLLER,
        CONNECTION_TIMEOUT,
        BACKHAUL_LINK_DISCONNECTED,
    };

    struct sConfigurationParams {
    };

    bool m_task_is_active = false;
    eState m_task_state   = eState::INIT;

    slave_thread &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    /**
     * @brief Direct link to controller as boolean.
     *
     * After successful onboarding, each agent/controller sends Topology Discovery to their neighbors.
     * With processing source of these messages, direct or indirect link is detected.
     *
     * If agent has direct link to controller, it is assured that it gets periodical (60 sec) messages
     * from controller. It is important to know that to apply correct amount of timeout time for backhaul connection.
     *
     * Each time backhaul link is established, it is set to false. Then, direct link is verified and changed.
     */
    bool m_direct_link_to_controller = false;

    /**
     * @brief Time point of backhaul connection.
     */
    std::chrono::steady_clock::time_point m_backhaul_connected_time;

    /**
     * @brief Last time point when any controller's message is arrived
     */
    std::chrono::steady_clock::time_point m_last_controller_contact_time;

    /**
     * @brief Amount of heartbeat message is being send to controller
     */
    uint8_t m_count_heartbeat_message = 0;

    /**
     * @brief Last time point when heartbeat message is being send to controller
     */
    std::chrono::steady_clock::time_point m_last_heartbeat_send_time;

    /**
     * @brief Convert enum of task state to string.
     *
     * @param status Enum of task state.
     * @return state as string.
     */
    static const std::string fsm_state_to_string(eState status);

    /**
     * @brief Checks controller last contact time after controller is discovered.
     *
     * Message Timeout:
     * If contact time exceeds over message timeout, heartbeat procedure starts.
     * Timeout period is defined with configuration of controller_message_timeout_sec.
     *
     * If agent does not receive message from controller for message timeout, enter heartbeat sending state.
     * In this state, clearing only once of heartbeat counters is must.
     *
     * Connection Timeout:
     * If contact time exceeds over connection timeout, forcing disconnection is triggered.
     * Timeout period is defined with configurations of controller_message_timeout_sec plus
     * controller_heartbeat_state_timeout_seconds.
     *
     * Incase of indirect connection check, timeouts are multiplied with INDIRECT_TIMEOUT_MULTIPLIER.
     * This is designed to prevent sending frequent heartbeat messages.
     *
     * Agents which indirectly connected to controller does not get DISCOVERY messages from controller
     * every 60 seconds. They only update last contact time with Topology Notification/Query, Metric Collections
     * or VS extensions. So, it is normal them to see less package from controller comparing to direct link.
     *
     * @return None
     */
    void check_controller_last_contact_time();

    /**
     * @brief Checks backhaul link connection time after link is established.
     *
     * If backhaul link connection time exceeds over timeout, forcing disconnection is triggered.
     * This scenario could occur after wired or wireless connection established,
     * but controller could not be discovered in timeout period.
     *
     * Timeout period is defined with configuration of backhaul_connection_timeout_sec.
     *
     * @return None
     */
    void check_backhaul_connection_time();

    /**
     * @brief Checks last heartbeat message sending time to send the message periodically.
     *
     * This method is called in MESSAGE_TIMEOUT state periodically.
     *
     * It send max amount of heartbeat as MAX_HEARTBEAT_COUNT and
     * within HEARTBEAT_SENDING_PERIOD_SEC period.
     *
     * To make it proper usage of this method, clear_heartbeat_counters() needs to be
     * called after entering MESSAGE_TIMEOUT state.
     *
     * @return None
     */
    void check_last_heartbeat_time();

    /**
     * @brief Clears the heartbeat counters.
     *
     * This method needs to be called only once in MESSAGE_TIMEOUT state.
     * @return None
     */
    void clear_heartbeat_counters();

    /**
     * @brief Sends Higher Layer Data CMDU to controller
     *
     * Controller should respond this message with ACK in one second.
     * This is used to check connectivity to the controller.
     *
     * @return true on success and false otherwise.
     */
    bool send_hle_to_controller();

    /**
     * @brief Sends BACKHAUL_DISCONNECT_COMMAND to Backhaul Manager
     *
     * This could be triggered for unsuccessful backhaul link or loosed controller connection.
     *
     * @return true on success and false otherwise.
     */
    bool send_disconnect_to_backhaul_manager();

    /**
     * @brief Reads agent configuration to enable/disable the task.
     *
     * It is filled with INIT_TASK event.
     * This event should be send after read_platform_configuration() method.
     *
     * @return None
     */
    void init_task_configuration();
};

} // namespace beerocks

#endif // _CONTROLLER_CONNECTIVITY_TASK_H_
