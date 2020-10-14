/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _DYNAMIC_CHANNEL_SELECTION_TASK_H_
#define _DYNAMIC_CHANNEL_SELECTION_TASK_H_

#include "task.h"

#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanRequest.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class DynamicChannelSelectionTask : public Task {
public:
    DynamicChannelSelectionTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~DynamicChannelSelectionTask() {}

    void work() override;

    enum eEvent : uint8_t { TEMP_EVENT_TEST };

    void handle_event(uint8_t event_enum_value, const void *event_obj) override;

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    /* Class members */

    /**
     * @brief dynamic channel selection Task states.
     * 
     */
    enum class eState : uint8_t { INIT, IDLE };

    struct sStateStatus {
        eState state = eState::INIT;
    };

    /**
     * @brief State of dynamic channel selection task mapped by front radio interface name.
     * 
     * Key:     Front radio interface name.
     * Value:   dynamic channel selection task state struct of the mapped Front radio interface name.
     */
    std::unordered_map<std::string, sStateStatus> m_state;

    /**
     * @brief Convert enum of task state to string.
     * 
     * @param status Enum of task state. 
     * @return state as string.
     */
    static const std::string fsm_state_to_string(eState status);

    backhaul_manager &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
};

} // namespace beerocks

#endif // _DYNAMIC_CHANNEL_SELECTION_TASK_H_
