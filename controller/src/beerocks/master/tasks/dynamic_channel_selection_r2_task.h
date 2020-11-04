/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

// This task will eventually replace the existing DCS task, but
// in order not to break existing functionality, it is introduced
// as a new separate task.

#ifndef _DYNAMIC_CHANNEL_SELECTION_R2_TASK_H_
#define _DYNAMIC_CHANNEL_SELECTION_R2_TASK_H_

#include "../db/db.h"
#include "task.h"
#include "task_pool.h"

#include <beerocks/tlvf/beerocks_message.h>

#include <chrono>

namespace son {

class dynamic_channel_selection_r2_task : public task, public std::enable_shared_from_this<task> {
public:
    dynamic_channel_selection_r2_task(db &database, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                      task_pool &tasks_);

    struct sScanRequestEvent {
        sMacAddr radio_mac;
    };

    struct sScanReportEvent {
        sMacAddr agent_mac;
        uint16_t mid;
    };

    enum eEvent : uint8_t {};

    enum class eRadioScanStatus : uint8_t { PENDING, TRIGGERED_WAIT_FOR_ACK, SCAN_IN_PROGRESS };
    enum class eAgentStatus : uint8_t { IDLE, BUSY };

    // Struct of the status of an agent and it's scan requests
    struct sAgentScanStatus {

        // Struct of a radio scan request
        struct sRadioScanRequest {
            uint16_t mid            = INVALID_MID_ID;
            eRadioScanStatus status = eRadioScanStatus::PENDING;
        };

        eAgentStatus status;
        /**
         * @brief Map of radio scans
         * 
         * Key:     radio mac.
         * Value:   radio scan request as sRadioScanRequest struct.
         */
        std::unordered_map<sMacAddr, sRadioScanRequest> radio_scans;
    };

    /**
     * @brief Map of agent's status.
     * 
     * Key:     agent mac.
     * Value:   agent status as sAgentScanStatus struct.
     */
    std::unordered_map<sMacAddr, sAgentScanStatus> m_agents_status_map;

    /**
     * @brief Map of outgoing mids to agents.
     * 
     * Key:     mid (message id) value.
     * Value:   agent mac.
     */
    std::unordered_map<uint16_t, sMacAddr> mid_to_agent_map;

protected:
    virtual void work() override;
    virtual void handle_event(int event_enum_value, void *event_obj) override;

private:
    enum eState : uint8_t { IDLE, TRIGGER_SCAN };

    // clang-format off
    const std::unordered_map<eState, std::string, std::hash<int>> m_states_string = {
      { eState::IDLE,                "IDLE"              },
      { eState::TRIGGER_SCAN,        "TRIGGER_SCAN"      },
    };
    // clang-format on

    eState m_state = eState::IDLE;

    // Class constants
    static constexpr uint16_t INVALID_MID_ID = UINT16_MAX;

    db &database;
    ieee1905_1::CmduMessageTx &cmdu_tx;
    task_pool &tasks;
};

} //namespace son
#endif
