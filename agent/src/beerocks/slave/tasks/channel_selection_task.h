/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CHANNEL_SELECTION_TASK_H_
#define _CHANNEL_SELECTION_TASK_H_

#include "task.h"

#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvChannelSelectionResponse.h>

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class ChannelSelectionTask : public Task {
public:
    ChannelSelectionTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    void handle_channel_selection_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                          const sMacAddr &src_mac);
    void handle_slave_channel_selection_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                 const sMacAddr &src_mac);

    /**
     * @brief Handles Vendor Specific messages. 
     * 
     * @param[in] cmdu_rx Received CMDU.
     * @param[in] src_mac MAC address of the message sender.
     * @param[in] beerocks_header Shared pointer to beerocks header.
     * @return true, if the message has been handled, otherwise false.
     */
    bool handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                std::shared_ptr<beerocks_header> beerocks_header);

    /* Vendor specific message handlers: */

    void handle_vs_csa_notification(ieee1905_1::CmduMessageRx &cmdu_rx,
                                    std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_csa_error_notification(ieee1905_1::CmduMessageRx &cmdu_rx,
                                          std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_cac_started_notification(ieee1905_1::CmduMessageRx &cmdu_rx,
                                            std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_dfs_cac_completed_notification(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_channels_list_notification(ieee1905_1::CmduMessageRx &cmdu_rx,
                                              std::shared_ptr<beerocks_header> beerocks_header);

    void
    handle_vs_zwdfs_ant_channel_switch_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                std::shared_ptr<beerocks_header> beerocks_header);

    struct sChannelSelectionResponse {
        sMacAddr radio_mac;
        wfa_map::tlvChannelSelectionResponse::eResponseCode response_code;
    };

    struct sExpectedChannelSelection {
        uint16_t mid;
        std::vector<sMacAddr> requests;
        std::vector<sChannelSelectionResponse> responses;
    };

    sExpectedChannelSelection m_expected_channel_selection;

    backhaul_manager &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
};

} // namespace beerocks

#endif // _CHANNEL_SELECTION_TASK_H_
