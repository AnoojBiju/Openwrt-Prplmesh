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
#include <tlvf/wfa_map/tlvApMetrics.h>
#include <tlvf/wfa_map/tlvAssociatedStaLinkMetrics.h>

#include "../backhaul_manager/backhaul_manager_thread.h"

#include "bcl/network/socket.h"

namespace beerocks {

// Forward decleration for backhaul_manager context saving
class backhaul_manager;

class LinkMetricsCollectionTask : public Task {
public:
    LinkMetricsCollectionTask(backhaul_manager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);

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
     * @brief Adds link metric TLVs to response message.
     *
     * Creates a Transmitter Link Metric TLV or a Receiver Link Metric TLV or both and adds them to
     * the Link Metric Response message.
     *
     * @param[in] reporter_al_mac 1905.1 AL MAC address of the device that transmits the response message.
     * @param[in] link_interface Connecting interface in this device.
     * @param[in] link_neighbor Neighbor connected to interface.
     * @param[in] link_metrics Metrics information associated to the link between the local interface and the neighbor's interface.
     * @param[in] link_metrics_type The link metrics type requested: TX, RX or both.
     *
     * @return True on success and false otherwise.
     */
    bool add_link_metrics(const sMacAddr &reporter_al_mac,
                          const backhaul_manager::sLinkInterface &link_interface,
                          const backhaul_manager::sLinkNeighbor &link_neighbor,
                          const sLinkMetrics &link_metrics,
                          ieee1905_1::eLinkMetricsType link_metrics_type);

    /**
     * @brief Creates a new link metrics collector for given media type.
     *
     * Creates a new link metrics collector suitable for the underlying network technology of the
     * connecting interface.
     * Collector choice depends on bits 15 to 8 of media type, that is, the media type group.
     *
     * @param[in] iface_mac MAC address of the connecting interface.
     * @param[in] media_type The underlying network technology of the connecting interface.
     *
     * @return Link metrics collector on success and nullptr otherwise.
     */
    std::unique_ptr<link_metrics_collector>
    create_link_metrics_collector(const backhaul_manager::sLinkInterface &link_interface) const;

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

    struct sStaTrafficStats {
        sMacAddr sta_mac;
        uint32_t byte_sent;
        uint32_t byte_recived;
        uint32_t packets_sent;
        uint32_t packets_recived;
        uint32_t tx_packets_error;
        uint32_t rx_packets_error;
        uint32_t retransmission_count;
    };

    struct sStaLinkMetrics {
        sMacAddr sta_mac;
        wfa_map::tlvAssociatedStaLinkMetrics::sBssidInfo bssid_info;
    };

    struct sApMetrics {
        sMacAddr bssid;
        uint8_t channel_utilization;
        uint16_t number_of_stas_currently_associated;
        wfa_map::tlvApMetrics::sEstimatedService estimated_service_parameters;
        std::vector<uint8_t> estimated_service_info_field;
    };

    struct sApMetricsResponse {
        sApMetrics metric;
        std::vector<sStaTrafficStats> sta_traffic_stats;
        std::vector<sStaLinkMetrics> sta_link_metrics;
    };

    std::vector<sApMetricsResponse> m_ap_metric_response;
};

} // namespace beerocks

#endif // _LINK_METRICS_COLLECTION_TASK_H_
