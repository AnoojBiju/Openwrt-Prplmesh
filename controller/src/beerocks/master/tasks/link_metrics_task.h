/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _LINK_METRICS_TASK_H_
#define _LINK_METRICS_TASK_H_

#include "../db/db.h"
#include "task.h"
#include "task_pool.h"

namespace son {
class LinkMetricsTask : public task {
public:
    LinkMetricsTask(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                    ieee1905_1::CmduMessageTx &cert_cmdu_tx_, task_pool &tasks_);
    virtual ~LinkMetricsTask() {}

    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

    /**
     * @brief Handles CMDU of 1905 Link Metric Response
     *
     * This handler is written to handle Link Metric Response is given for
     * all neighbors and TX/RX together. Metric Msg. FLAGS are needs to be set in this manner!
     * If only RX or TX is received, link_metric_data_map will hold only what it is given.
     * But interface stats work just as fine.
     *
     * @param src_mac Source MAC address.
     * @param cmdu_rx Received CMDU to be handled.
     * @return true on success and false otherwise.
     */
    bool handle_cmdu_1905_link_metric_response(const sMacAddr &src_mac,
                                               ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles CMDU of 1905 Unassoc Sta Link Metrics Response
     *
     * This handler is written to handle Unassoc Link Metrics Response for the unassociated
     * stations. It will update the map.
     *
     * @param src_mac Source MAC address.
     * @param cmdu_rx Received CMDU to be handled.
     * @return true on success and false otherwise.
     */
    bool
    handle_cmdu_1905_unassociated_station_link_metric_response(const sMacAddr &src_mac,
                                                               ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Method is used only for certification so update the certification cmdu
     *
     * @return true on success and false otherwise.
     */
    bool construct_combined_infra_metric();

    /**
     * @brief Method is used for handling event like sending unassoc sta link metrics to supported agent(s)
     * who announced support in capability info.
     *
     * @return none
     */
    void handle_event(int event_enum_value, void *event_obj) override;

    struct sUnAssociatedLinkMetricsQueryEvent {
        uint8_t opClass;
        uint8_t channel;
        sMacAddr unassoc_sta_mac;
    };

    enum eEvent : uint8_t { UNASSOC_STA_LINK_METRICS_QUERY };

protected:
    virtual void work() override;

private:
    db &database;
    ieee1905_1::CmduMessageTx &cmdu_tx;
    ieee1905_1::CmduMessageTx &cert_cmdu_tx;
    task_pool &tasks;
    std::chrono::steady_clock::time_point last_query_request{};

    /**
     * @brief Prints all link metric and its sub parameters according to supplied map.
     *
     * @param link_metric_data Link Metrics Map as Agent->Neighbor->Metrics.
     * @return None.
     */
    static void print_link_metric_map(
        std::unordered_map<sMacAddr, std::unordered_map<sMacAddr, son::db::link_metrics_data>> const
            &link_metric_data);
};

} // namespace son

#endif
