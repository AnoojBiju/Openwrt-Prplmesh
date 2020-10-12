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

#include <beerocks/tlvf/enums/eDfsState.h>

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class ChannelSelectionTask : public Task {
public:
    ChannelSelectionTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac, Socket *sd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    /**
     * @brief Contain the current channel selection which has chosen by the task.
     *
     * From the channel and the bandwidth, a center channel can be evaluated by a look-up on
     * 'son::wireless_utils::channels_table_5g'
     *
     * @param channel Chosen beacon channel.
     * @param secondary_channel Chosen secondary beacon channel. Relevant only if the bandwidth is
     *  80+80.
     * @param bw Bandwidth of the channel.
     * @param dfs_state DFS state for knowing if the channel is DFS channel or not.
     */
    struct sSelectedChannel {
        uint8_t channel;
        uint8_t secondary_channel;
        eWiFiBandwidth bw;
        beerocks_message::eDfsState dfs_state;
    } m_selected_channel;

    void handle_channel_selection_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                          const sMacAddr &src_mac);
    void handle_slave_channel_selection_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                 const sMacAddr &src_mac);

    /**
     * @brief Handles Vendor Specific messages.
     *
     * @param[in] cmdu_rx Received CMDU.
     * @param[in] src_mac MAC address of the message sender.
     * @param[in] sd Socket of the thread which has sent the message.
     * @param[in] beerocks_header Shared pointer to beerocks header.
     * @return true, if the message has been handled, otherwise false.
     */
    bool handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                Socket *sd, std::shared_ptr<beerocks_header> beerocks_header);

    /* Vendor specific message handlers: */

    void handle_vs_csa_notification(ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
                                    std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_csa_error_notification(ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
                                          std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_cac_started_notification(ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
                                            std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_dfs_cac_completed_notification(ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
                                                  std::shared_ptr<beerocks_header> beerocks_header);

    void handle_vs_channels_list_notification(ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
                                              std::shared_ptr<beerocks_header> beerocks_header);

    void
    handle_vs_zwdfs_ant_channel_switch_response(ieee1905_1::CmduMessageRx &cmdu_rx, Socket *sd,
                                                std::shared_ptr<beerocks_header> beerocks_header);

    /* Helper functions */
    const std::string socket_to_front_iface_name(const Socket *sd);
    Socket *front_iface_name_to_socket(const std::string &iface_name);

    /* Class members */

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
