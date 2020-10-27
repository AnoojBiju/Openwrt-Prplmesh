/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CHANNEL_SCAN_TASK_H_
#define _CHANNEL_SCAN_TASK_H_

#include "task.h"

#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanRequest.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class ChannelScanTask : public Task {
public:
    ChannelScanTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~ChannelScanTask() {}

    void work() override;

    enum eEvent : uint8_t {};

    void handle_event(uint8_t event_enum_value, const void *event_obj) override;

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac, Socket *sd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

    void start_scan();

private:
    /* Class members */

    /**
     * @brief channel scan Task states.
     * 
     */
    enum eState : uint8_t { UNCONFIGURED, INIT, IDLE };

    // clang-format off
    const std::unordered_map<eState, std::string, std::hash<int>> m_states_string = {
      { eState::UNCONFIGURED,          "UNCONFIGURED"      },
      { eState::INIT,                  "INIT"              },
      { eState::IDLE,                  "IDLE"              },
    };
    // clang-format on

    /**
     * @brief State of channel scan task mapped by front radio interface name.
     * 
     * Key:     Front radio interface name.
     * Value:   channel scan task state of the mapped Front radio interface name.
     */
    std::unordered_map<std::string, eState> m_state;

    backhaul_manager &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    /* 1905.1 message handlers: */

    /**
    * @brief Handles 1905 channel scan request message.
    * 
    * @param[in] cmdu_rx Received CMDU.
    * @param[in] src_mac MAC address of the message sender.
    * @return True on success, otherwise false.
    */
    bool handle_channel_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);

    /* 1905.1 message responses: */

    /**
    * @brief Sends 1905 CHANNEL_SCAN_REPORT message back to the sender.
    * 
    * @param[in] cmdu_rx Received CMDU.
    * @param[in] src_mac MAC address of the message sender.
    * @return True on success, otherwise false.
    */
    bool send_channel_scan_report(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);
};

} // namespace beerocks

#endif // _CHANNEL_SCAN_TASK_H_
