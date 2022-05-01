/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _PRE_ASSOCIATION_STEERING_H_
#define _PRE_ASSOCIATION_STEERING_H_

#include "../../db/db.h"
#include "../task.h"
#include "../task_pool.h"
#include "pre_association_steering_task_db.h"

#include <beerocks/tlvf/beerocks_message_common.h>

namespace son {
class pre_association_steering_task : public task {
public:
    static const int event_timeout = 5;
    struct sListenerGeneralRegisterUnregisterEvent {
        int sd;
    };

    struct sSteeringSetGroupRequestEvent {
        int sd;
        uint32_t steeringGroupIndex;
        std::vector<beerocks_message::sSteeringApConfig> ap_cfgs;
        uint8_t remove;
    };

    struct sSteeringSetGroupResponseEvent {
        int32_t ret_code;
    };

    struct sSteeringClientSetRequestEvent {
        int sd;
        uint32_t steeringGroupIndex;
        std::string bssid;
        sMacAddr client_mac;
        beerocks_message::sSteeringClientConfig config;
        uint8_t remove;
    };

    struct sSteeringClientSetResponseEvent {
        int32_t ret_code;
    };

    struct sSteeringRssiMeasurementRequestEvent {
        int sd;
        std::string bssid;
        beerocks_message::sNodeRssiMeasurementRequest params;
    };

    struct sSteeringRssiMeasurementResponseEvent {
        int32_t ret_code;
    };

    struct sSteeringClientDisconnectRequestEvent {
        int sd;
        uint32_t steeringGroupIndex;
        std::string bssid;
        sMacAddr client_mac;
        beerocks_message::eDisconnectType type;
        uint32_t reason;
    };

    struct sSteeringClientDisconnectResponseEvent {
        int32_t ret_code;
    };

    struct sSteeringSlaveJoinEvent {
        std::string radio_mac;
    };

    enum eEvents {
        STEERING_EVENT_PROBE_REQ_NOTIFICATION,
        STEERING_EVENT_CLIENT_CONNECT_NOTIFICATION,
        STEERING_EVENT_CLIENT_DISCONNECT_NOTIFICATION,
        STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION,
        STEERING_EVENT_SNR_XING_NOTIFICATION,
        STEERING_EVENT_SNR_NOTIFICATION,
        STEERING_EVENT_AUTH_FAIL_NOTIFICATION,
        STEERING_EVENT_REGISTER,
        STEERING_EVENT_UNREGISTER,
        STEERING_SET_GROUP_REQUEST,
        STEERING_SET_GROUP_RESPONSE,
        STEERING_CLIENT_SET_REQUEST,
        STEERING_CLIENT_SET_RESPONSE,
        STEERING_CLIENT_DISCONNECT_REQUEST,
        STEERING_CLIENT_DISCONNECT_RESPONSE,
        STEERING_RSSI_MEASUREMENT_REQUEST,
        STEERING_RSSI_MEASUREMENT_RESPONSE,
        STEERING_REMOVE_SOCKET,
        STEERING_SLAVE_JOIN,
    };

public:
    pre_association_steering_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                  task_pool &tasks_);
    virtual ~pre_association_steering_task() {}

protected:
    virtual void work() override;
    virtual void handle_event(int event_type, void *obj) override;

private:
    typedef struct {
        int sd;
        bool events_updates;
    } sBmlPreAssociationSteeringListener;

    typedef struct {
        int bml_sd;
        std::chrono::steady_clock::time_point current_time;
        uint32_t num_of_expected_responses;
        uint32_t num_of_received_responses;
    } sPendingEvent;

    bool is_bml_pre_association_steering_listener_socket(int sd);
    int get_bml_pre_association_steering_socket_at(uint32_t idx);
    bool get_bml_pre_association_steering_events_update_enable(int sd);
    bool set_bml_pre_association_steering_events_update_enable(int sd, bool update_enable);
    void add_bml_pre_association_steering_socket(int sd);
    void remove_bml_pre_association_steering_socket(int sd);
    void send_bml_event_to_listeners(ieee1905_1::CmduMessageTx &cmdu_tx,
                                     const std::vector<int> &bml_listeners);
    bool send_steering_conf_to_agent(const std::string &radio_mac);
    int32_t
    steering_group_fill_ap_configuration(sSteeringSetGroupRequestEvent *event_obj,
                                         std::vector<beerocks_message::sSteeringApConfig> &ap_cfgs);

    void send_bml_response(eEvents event, int sd, int32_t ret = 0);
    void add_pending_request_event(eEvents event, int bml_sd,
                                   uint32_t num_of_expected_responses = 1);
    void remove_pending_request_event(eEvents event);
    bool is_pending_request_event_exist(eEvents event);
    bool is_pending_request_event_responses_match(eEvents event);
    int pending_request_event_get_bml_sd(eEvents event);
    void pending_request_event_increase_received_response(eEvents event);

    void pending_request_events_check_timeout();

    bool check_ap_cfgs_are_valid(std::vector<beerocks_message::sSteeringApConfig> &ap_cfgs);

    db &m_database;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    task_pool &m_tasks;

    pre_association_steering_task_db m_pre_association_steering_db;
    int m_sd;
    std::vector<sBmlPreAssociationSteeringListener>
        m_bml_pre_association_steering_listeners_sockets;
    /**
     * @brief Map of pending request events
     * 
     * Each request event has a corresponding response event.
     * When a request is sent to the slave, it expects a response to be
     * received from the slave. For a single interaction, several requests can be sent,
     * and, therefore several responses are expected - this is determined in sPendingEvent struct.
     * Assuming the number of sent requests matches the number of received responses, the transaction
     * is considered a success.
     * The goal of this map is to make sure the number of request events is matched to received response events.
     */
    std::unordered_map<eEvents, sPendingEvent> m_pending_request_events;
};

} // namespace son

#endif
