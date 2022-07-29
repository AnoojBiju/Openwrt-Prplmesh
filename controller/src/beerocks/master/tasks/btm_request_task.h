/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BTM_REQUEST_TASK_H_
#define _BTM_REQUEST_TASK_H_

#include "../db/db.h"
#include "task.h"
#include "task_pool.h"
#include <tlvf/wfa_map/tlvSteeringBTMReport.h>

namespace son {
class btm_request_task : public task {
public:
    enum events {
        STA_CONNECTED,
        STA_DISCONNECTED,
        BTM_REPORT_RECEIVED,
        BTM_REQUEST_REJECTED,
    };

public:
    btm_request_task(db &database, ieee1905_1::CmduMessageTx &cmdu_tx, task_pool &tasks,
                     const std::string &sta_mac, const std::string &target_bssid,
                     const std::string &triggered_by, bool disassoc_imminent,
                     int validity_interval_ms, int steering_timer_ms,
                     int disassoc_timer_ms        = beerocks::BSS_STEER_DISASSOC_TIMER_MS,
                     const std::string &task_name = std::string("btm_request_task"));
    virtual ~btm_request_task() {}
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

protected:
    virtual void work() override;
    virtual void handle_event(int event_type, void *obj) override;
    virtual void handle_task_end() override;

private:
    void steer_sta();
    void print_steering_info();

    /**
     * @brief Set values for parameters of NBAPI SteerEvent object.
     *
     * @param event_path Path to NBAPI SteerEvent object.
     * @return True on success, false otherwise.
     */
    bool dm_set_steer_event_params(const std::string &event_path);

    /**
     * @brief Save data about client steer event to persistent db.
     *
     * @param steer_origin Steer origin.
     * @param steer_type Steering type.
     */
    void add_steer_history_to_persistent_db(const std::string &steer_origin,
                                            const std::string &steer_type);

    /**
     * @brief Adds steering event in station event map of database.
     * @return True on success, false otherwise.
     */
    bool add_sta_steer_event_to_db();

    /**
     * @brief Update STA's steering statistics
     * for BTM and CAC steering attempts, save last steering timestamp.
     *
     * @param station Station object.
     */
    void update_sta_steer_attempt_stats(Station &station);

    db &m_database;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    task_pool &m_tasks;
    const std::string m_sta_mac;
    const std::string m_target_bssid;
    const std::string m_triggered_by;
    std::string m_steering_type;
    std::string m_ssid_name;
    std::string m_original_bssid;
    wfa_map::tlvSteeringBTMReport::eBTMStatusCode m_status_code =
        wfa_map::tlvSteeringBTMReport::REJECT_UNSPECIFIED;
    bool m_steering_success  = false;
    bool m_disassoc_imminent = true;
    const int m_disassoc_timer_ms;
    const int m_steering_timer_ms;
    bool m_btm_report_received = false;

    /**
     * @brief The timestamp of steering event in data model of steering events.
     */
    std::string m_dm_timestamp;

    /**
     * @brief The timestamp when the steering started.
     */
    std::chrono::steady_clock::time_point m_steering_start = {};

    /**
     * @brief The duration between STA disassociation and association event.
     * If timestamp for disassociation event (m_disassoc_ts) was not set
     * m_duration is set to zero.
     */
    std::chrono::milliseconds m_duration = {};

    static constexpr int STEERING_WAIT_TIME_MS = 25000;

    enum states {
        SEND_BTM_REQUEST = 0,
        FINALIZE,
    };

    int m_state = 0;
};
} // namespace son

#endif //_BTM_REQUEST_TASK_H_
