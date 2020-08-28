/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _LINK_METRICS_COLLECTION_TASK_H_
#define _LINK_METRICS_COLLECTION_TASK_H_

#include "task.h"

#include <tlvf/CmduMessageTx.h>

#include "bcl/network/socket.h"

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class LinkMetricsCollectionTask : public Task {
public:
    LinkMetricsCollectionTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~LinkMetricsCollectionTask() {}

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

    void work() override;

private:
    backhaul_manager &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    void handle_link_metric_query(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);
    void handle_combined_infrastructure_metrics(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                const sMacAddr &src_mac);
    void handle_beacon_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);
    void handle_associated_sta_link_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                  const sMacAddr &src_mac);
    void handle_ap_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);
    void handle_multi_ap_policy_config_request(ieee1905_1::CmduMessageRx &cmdu_rx,
                                               const sMacAddr &src_mac);
    void handle_ap_metrics_response(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);

    /**
     * @brief Sends an AP Metrics Query message for each bssid on 'bssid_list' to the Fronthaul.
     * If the 'bssid_list' is empty, sends a query on each bssid that exists on the Agent.
     *
     * @param mid MID of the message to be sent.
     * @param bssid_list List of bssids to send a query on.
     * @return true on success, otherwise false.
     */
    bool send_ap_metric_query_message(
        uint16_t mid,
        const std::unordered_set<sMacAddr> &bssid_list = std::unordered_set<sMacAddr>());

    /**
     * AP Metrics Reporting configuration and status information type.
     */
    struct sApMetricsReportingInfo {
        /**
         * AP Metrics Reporting Interval in seconds (0: Do not report AP Metrics periodically).
         * This value is set by the controller through a Multi-AP Policy Config Request message,
         * inside the Metric Reporting Policy TLV.
         */
        uint8_t reporting_interval_s = 0;

        /**
         * Time point at which AP metrics were reported for the last time.
         */
        std::chrono::steady_clock::time_point last_reporting_time_point;
    };

    /**
     * AP Metrics Reporting configuration and status information.
     */
    sApMetricsReportingInfo m_ap_metrics_reporting_info;

    struct sApMetricsQuery {
        Socket *soc;
        sMacAddr bssid;
    };

    std::vector<sApMetricsQuery> m_ap_metric_query;
};

} // namespace beerocks

#endif // _LINK_METRICS_COLLECTION_TASK_H_
