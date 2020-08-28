/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "link_metrics_collection_task.h"

#include "../agent_db.h"
#include "../backhaul_manager/backhaul_manager_thread.h"
#include "../helpers/media_type.h"
#include "../link_metrics/ieee802_11_link_metrics_collector.h"
#include "../link_metrics/ieee802_3_link_metrics_collector.h"

#include <beerocks/tlvf/beerocks_message_backhaul.h>

#include <tlvf/ieee_1905_1/tlvLinkMetricQuery.h>
#include <tlvf/ieee_1905_1/tlvLinkMetricResultCode.h>
#include <tlvf/ieee_1905_1/tlvReceiverLinkMetric.h>
#include <tlvf/ieee_1905_1/tlvTransmitterLinkMetric.h>
#include <tlvf/wfa_map/tlvApMetricQuery.h>
#include <tlvf/wfa_map/tlvAssociatedStaTrafficStats.h>
#include <tlvf/wfa_map/tlvBeaconMetricsQuery.h>
#include <tlvf/wfa_map/tlvMetricReportingPolicy.h>
#include <tlvf/wfa_map/tlvStaMacAddressType.h>
#include <tlvf/wfa_map/tlvSteeringPolicy.h>

namespace beerocks {

LinkMetricsCollectionTask::LinkMetricsCollectionTask(backhaul_manager &btl_ctx,
                                                     ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::LINK_METRICS_COLLECTION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
}

bool LinkMetricsCollectionTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                            const sMacAddr &src_mac,
                                            std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::LINK_METRIC_QUERY_MESSAGE: {
        handle_link_metric_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::COMBINED_INFRASTRUCTURE_METRICS_MESSAGE: {
        handle_combined_infrastructure_metrics(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::BEACON_METRICS_QUERY_MESSAGE: {
        handle_beacon_metrics_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE: {
        handle_associated_sta_link_metrics_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::AP_METRICS_QUERY_MESSAGE: {
        handle_ap_metrics_query(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE: {
        handle_multi_ap_policy_config_request(cmdu_rx, src_mac);
        break;
    }
    case ieee1905_1::eMessageType::AP_METRICS_RESPONSE_MESSAGE: {
        handle_slave_ap_metrics_response(cmdu_rx, src_mac);
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

void LinkMetricsCollectionTask::work()
{
    auto db = AgentDB::get();

    if (db->statuses.ap_autoconfiguration_completed) {
        /**
         * Get current time. It is later used to compute elapsed time since some start time and
         * check if a timeout has expired to perform periodic actions.
         */
        auto now = std::chrono::steady_clock::now();

        /**
         * If periodic AP metrics reporting is enabled, check if time interval has elapsed and if
         * so, then report AP metrics.
         */
        if (0 != ap_metrics_reporting_info.reporting_interval_s) {
            int elapsed_time_s = std::chrono::duration_cast<std::chrono::seconds>(
                                     now - ap_metrics_reporting_info.last_reporting_time_point)
                                     .count();

            if (elapsed_time_s >= ap_metrics_reporting_info.reporting_interval_s) {
                ap_metrics_reporting_info.last_reporting_time_point = now;

                // We must generate a new MID for the periodic AP Metrics Response messages that
                // do not correspond to an AP Metrics Query message.
                // We cannot set MID to 0 here because we must also differentiate periodic
                // AP Metrics Response messages and messages received from monitor thread
                // due to channel utilization crossed configured threshold value.
                // As a temporary solution, set MID to UINT16_MAX here.
                // TODO: to be fixed as part of #1328

                // Send ap_metrics query on all bssids exists on the Agent.
                send_ap_metric_query_message(UINT16_MAX);
            }
        }
    }
}

void LinkMetricsCollectionTask::handle_link_metric_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                         const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received LINK_METRIC_QUERY_MESSAGE, mid=" << std::hex << mid;

    /**
     * The IEEE 1905.1 standard says about the Link Metric Query TLV and the neighbor type octet
     * that "If the value is 0, then the EUI48 field is not present; if the value is 1, then the
     * EUI-48 field shall be present."
     *
     * However, optional fields are not currently supported by TLVF.
     *
     * As a workaround, instead of defining a tlvLinkMetricQuery TLV with an optional field, we
     * have defined two different TLVs: tlvLinkMetricQuery with the optional field and
     * tlvLinkMetricQueryAllNeighbors without it. Application must check which of both TLVs has
     * been received inside the message.
     */
    std::shared_ptr<ieee1905_1::tlvLinkMetricQueryAllNeighbors> tlvLinkMetricQueryAllNeighbors;
    std::shared_ptr<ieee1905_1::tlvLinkMetricQuery> tlvLinkMetricQuery;

    tlvLinkMetricQueryAllNeighbors = cmdu_rx.getClass<ieee1905_1::tlvLinkMetricQueryAllNeighbors>();
    if (!tlvLinkMetricQueryAllNeighbors) {
        tlvLinkMetricQuery = cmdu_rx.getClass<ieee1905_1::tlvLinkMetricQuery>();
        if (!tlvLinkMetricQuery) {
            LOG(ERROR) << "getClass ieee1905_1::tlvLinkMetricQueryAllNeighbors and "
                          "ieee1905_1::tlvLinkMetricQuery failed";
            return;
        }
    }

    auto db = AgentDB::get();

    /**
     * 1905.1 AL MAC address of the device that transmits the response message.
     */
    sMacAddr reporter_al_mac = db->bridge.mac;

    /**
     * 1905.1 AL MAC address of a neighbor of the receiving device.
     * Query can specify a particular neighbor device or all neighbor devices.
     */
    sMacAddr neighbor_al_mac = net::network_utils::ZERO_MAC;

    /**
     * Obtain link metrics for either all neighbors or a specific neighbor
     */
    ieee1905_1::eLinkMetricNeighborType neighbor_type;

    /**
     * The link metrics type requested: TX, RX or both
     */
    ieee1905_1::eLinkMetricsType link_metrics_type;

    if (tlvLinkMetricQuery) {
        /**
         * If tlvLinkMetricQuery has been included in message, we will be permissive enough to
         * allow it specify ALL_NEIGHBORS and if so, then we will just ignore the field
         * containing the MAC address of neighbor.
         */
        neighbor_type     = tlvLinkMetricQuery->neighbor_type();
        neighbor_al_mac   = tlvLinkMetricQuery->mac_al_1905_device();
        link_metrics_type = tlvLinkMetricQuery->link_metrics_type();
    } else {
        neighbor_type = tlvLinkMetricQueryAllNeighbors->neighbor_type();
        if (ieee1905_1::eLinkMetricNeighborType::ALL_NEIGHBORS != neighbor_type) {
            LOG(ERROR) << "Unexpected neighbor type: " << std::hex << int(neighbor_type);
            return;
        }
        link_metrics_type = tlvLinkMetricQueryAllNeighbors->link_metrics_type();
    }

    /**
     * Set alias flag to true if link metrics for a specific neighbor have been requested
     */
    bool specific_neighbor =
        ieee1905_1::eLinkMetricNeighborType::SPECIFIC_NEIGHBOR == neighbor_type;

    /**
     * Create response message
     */
    auto cmdu_tx_header =
        m_cmdu_tx.create(mid, ieee1905_1::eMessageType::LINK_METRIC_RESPONSE_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "Failed creating LINK_METRIC_RESPONSE_MESSAGE header! mid=" << std::hex
                   << mid;
        return;
    }

    /**
     * Get the list of neighbor links from the topology database.
     * Neighbors are grouped by the interface that connects to them.
     */
    std::map<backhaul_manager::sLinkInterface, std::vector<backhaul_manager::sLinkNeighbor>>
        neighbor_links_map;
    if (!get_neighbor_links(neighbor_al_mac, neighbor_links_map)) {
        LOG(ERROR) << "Failed to get the list of neighbor links";
        return;
    }

    /**
     * If the specified neighbor 1905.1 AL ID does not identify a neighbor of the receiving 1905.1
     * AL, then a link metric ResultCode TLV (see Table 6-21) with a value set to “invalid
     * neighbor” shall be included in this message.
     */
    bool invalid_neighbor = specific_neighbor && neighbor_links_map.empty();
    if (invalid_neighbor) {
        auto tlvLinkMetricResultCode = m_cmdu_tx.addClass<ieee1905_1::tlvLinkMetricResultCode>();
        if (!tlvLinkMetricResultCode) {
            LOG(ERROR) << "addClass ieee1905_1::tlvLinkMetricResultCode failed, mid=" << std::hex
                       << mid;
            return;
        }

        LOG(INFO) << "Invalid neighbor 1905.1 AL ID specified: " << neighbor_al_mac;

        tlvLinkMetricResultCode->value() = ieee1905_1::tlvLinkMetricResultCode::INVALID_NEIGHBOR;

        LOG(DEBUG) << "Sending LINK_METRIC_RESPONSE_MESSAGE (invalid neighbour), mid: " << std::hex
                   << mid;
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                      tlvf::mac_to_string(db->bridge.mac));
        return;
    }

    /**
     * Report link metrics for the link with specific neighbor or for all neighbors, as
     * obtained from topology database
     */
    for (const auto &entry : neighbor_links_map) {
        auto interface        = entry.first;
        const auto &neighbors = entry.second;

        std::unique_ptr<link_metrics_collector> collector =
            create_link_metrics_collector(interface);
        if (!collector) {
            continue;
        }

        for (const auto &neighbor : neighbors) {

            LOG(TRACE) << "Getting link metrics for interface " << interface.iface_name
                       << " (MediaType = " << std::hex << (int)interface.media_type
                       << ") and neighbor " << neighbor.iface_mac;

            sLinkMetrics link_metrics;
            if (!collector->get_link_metrics(interface.iface_name, neighbor.iface_mac,
                                             link_metrics)) {
                LOG(ERROR) << "Unable to get link metrics for interface " << interface.iface_name
                           << " and neighbor " << neighbor.iface_mac;
                return;
            }

            if (!add_link_metrics(reporter_al_mac, interface, neighbor, link_metrics,
                                  link_metrics_type)) {
                return;
            }
        }
    }

    LOG(DEBUG) << "Sending LINK_METRIC_RESPONSE_MESSAGE, mid: " << std::hex << mid;
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_combined_infrastructure_metrics(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received COMBINED_INFRASTRUCTURE_METRICS message, mid=" << std::hex << mid;

    if (cmdu_rx.getClass<ieee1905_1::tlvReceiverLinkMetric>())
        LOG(DEBUG) << "Received TLV_RECEIVER_LINK_METRIC";
    if (cmdu_rx.getClass<ieee1905_1::tlvTransmitterLinkMetric>())
        LOG(DEBUG) << "Received TLV_TRANSMITTER_LINK_METRIC";

    // build ACK message CMDU
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return;
    }
    LOG(DEBUG) << "sending ACK message to the originator, mid=" << std::hex << mid;
    auto db = AgentDB::get();
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_beacon_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                            const sMacAddr &src_mac)
{
    LOG(DEBUG) << "now going to handle BEACON METRICS QUERY";

    // extract the desired STA mac
    auto tlvBeaconMetricsQuery = cmdu_rx.getClass<wfa_map::tlvBeaconMetricsQuery>();
    if (!tlvBeaconMetricsQuery) {
        LOG(ERROR) << "handle_1905_beacon_metrics_query should handle only tlvBeaconMetrics, but "
                      "got something else: 0x"
                   << std::hex << (uint16_t)cmdu_rx.getMessageType();
        return;
    }

    const sMacAddr &requested_sta_mac = tlvBeaconMetricsQuery->associated_sta_mac();
    LOG(DEBUG) << "the requested STA mac is: " << requested_sta_mac;

    // build ACK message CMDU
    const auto mid      = cmdu_rx.getMessageId();
    auto cmdu_tx_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return;
    }

    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(requested_sta_mac, AgentDB::eMacType::CLIENT);
    if (!radio) {
        LOG(DEBUG) << "STA with MAC [" << requested_sta_mac
                   << "] is not associated with any BSS operated by the agent";

        // add an Error Code TLV
        auto error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvErrorCode>();
        if (!error_code_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvErrorCode has failed";
            return;
        }

        error_code_tlv->reason_code() =
            wfa_map::tlvErrorCode::STA_NOT_ASSOCIATED_WITH_ANY_BSS_OPERATED_BY_THE_AGENT;

        error_code_tlv->sta_mac() = requested_sta_mac;

        // report the error
        std::stringstream errorSS;
        auto error_tlv = m_cmdu_tx.getClass<wfa_map::tlvErrorCode>();
        if (error_tlv) {
            errorSS << "0x" << error_tlv->reason_code();
        } else {
            errorSS << "note: error constructing the error itself";
        }

        LOG(DEBUG) << "sending ACK message to the originator with an error, mid: " << std::hex
                   << mid << " tlv error code: " << errorSS.str();

        // send the error
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                      tlvf::mac_to_string(db->bridge.mac));
        return;
    }

    auto radio_info = m_btl_ctx.get_radio(radio->front.iface_mac);
    if (!radio_info) {
        LOG(ERROR) << "Failed to get radio info for " << radio->front.iface_mac;
        return;
    }

    LOG(DEBUG) << "Found the radio that has the sation. radio: " << radio->front.iface_mac
               << "; station: " << requested_sta_mac;

    LOG(DEBUG) << "BEACON METRICS QUERY: sending ACK message to the originator mid: " << std::hex
               << mid; // USED IN TESTS

    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_associated_sta_link_metrics_query(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE , mid=" << std::dec
               << int(mid);

    if (!m_cmdu_tx.create(mid,
                          ieee1905_1::eMessageType::ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE)) {
        LOG(ERROR)
            << "cmdu creation of type ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE, has failed";
        return;
    }

    auto mac = cmdu_rx.getClass<wfa_map::tlvStaMacAddressType>();
    if (!mac) {
        LOG(ERROR) << "Failed to get mac address";
        return;
    }

    auto assoc_link_metrics = m_cmdu_tx.addClass<wfa_map::tlvAssociatedStaLinkMetrics>();
    if (!assoc_link_metrics) {
        LOG(ERROR) << "Failed to create tlvAssociatedStaLinkMetrics tlv";
        return;
    }

    auto db = AgentDB::get();

    // Check if it is an error scenario - if the STA specified in the STA link Query message is not associated
    // with any of the BSS operated by the Multi-AP Agent
    auto radio = db->get_radio_by_mac(mac->sta_mac(), AgentDB::eMacType::CLIENT);
    if (!radio) {
        LOG(ERROR) << "client with mac address " << mac->sta_mac() << " not found";
        //Add an Error Code TLV
        auto error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvErrorCode>();
        if (!error_code_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvErrorCode has failed";
            return;
        }
        error_code_tlv->reason_code() =
            wfa_map::tlvErrorCode::STA_NOT_ASSOCIATED_WITH_ANY_BSS_OPERATED_BY_THE_AGENT;
        error_code_tlv->sta_mac() = mac->sta_mac();

        LOG(DEBUG) << "Send a ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE back to controller";
        m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                      tlvf::mac_to_string(db->bridge.mac));
        return;
    }
    auto client_it = radio->associated_clients.find(mac->sta_mac());
    if (client_it == radio->associated_clients.end()) {
        LOG(ERROR) << "Cannot find sta sta " << mac->sta_mac();
        return;
    }
    if (client_it->second.bssid == net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "Cannot find sta bssid";
        return;
    }
    LOG(DEBUG) << "Client with mac address " << mac->sta_mac() << " connected to "
               << client_it->second.bssid;

    auto request_out = message_com::create_vs_message<
        beerocks_message::cACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST>(m_cmdu_tx, mid);

    if (!request_out) {
        LOG(ERROR) << "Failed to build ACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST";
        return;
    }

    request_out->sync()    = true;
    request_out->sta_mac() = mac->sta_mac();

    auto radio_info = m_btl_ctx.get_radio(radio->front.iface_mac);
    if (!radio_info) {
        LOG(ERROR) << "Failed to get radio info for " << radio->front.iface_mac;
        return;
    }
    message_com::send_cmdu(radio_info->slave, m_cmdu_tx);
}

void LinkMetricsCollectionTask::handle_ap_metrics_query(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                        const sMacAddr &src_mac)
{
    const auto mid           = cmdu_rx.getMessageId();
    auto ap_metric_query_tlv = cmdu_rx.getClass<wfa_map::tlvApMetricQuery>();
    if (!ap_metric_query_tlv) {
        LOG(ERROR) << "AP Metrics Query CMDU mid=" << std::hex << mid
                   << " does not have AP Metric Query TLV";
        return;
    }

    std::unordered_set<sMacAddr> bssids;
    for (size_t bssid_idx = 0; bssid_idx < ap_metric_query_tlv->bssid_list_length(); bssid_idx++) {
        auto bssid_tuple = ap_metric_query_tlv->bssid_list(bssid_idx);
        if (!std::get<0>(bssid_tuple)) {
            LOG(ERROR) << "Failed to get bssid " << bssid_idx << " from AP_METRICS_QUERY";
            return;
        }
        bssids.insert(std::get<1>(bssid_tuple));
        LOG(DEBUG) << "Received AP_METRICS_QUERY_MESSAGE, mid=" << std::hex << mid << "  bssid "
                   << std::get<1>(bssid_tuple);
    }

    if (!send_ap_metric_query_message(mid, bssids)) {
        LOG(ERROR) << "Failed to forward AP_METRICS_RESPONSE to the son_slave_thread";
        return;
    }
}

bool LinkMetricsCollectionTask::send_ap_metric_query_message(
    uint16_t mid, const std::unordered_set<sMacAddr> &bssid_list)
{
    auto db = AgentDB::get();

    for (const auto &radio : db->get_radios_list()) {
        if (!radio) {
            continue;
        }
        for (const auto &bssid : radio->front.bssids) {
            if (!bssid_list.empty() && bssid_list.find(bssid.mac) == bssid_list.end()) {
                continue;
            }
            LOG(DEBUG) << "Forwarding AP_METRICS_QUERY_MESSAGE message to son_slave, bssid: "
                       << bssid.mac;

            if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::AP_METRICS_QUERY_MESSAGE)) {
                LOG(ERROR) << "Failed to create AP_METRICS_QUERY_MESSAGE";
                return false;
            }

            auto query = m_cmdu_tx.addClass<wfa_map::tlvApMetricQuery>();
            if (!query) {
                LOG(ERROR) << "Failed addClass<wfa_map::tlvApMetricQuery>";
                return false;
            }

            if (!query->alloc_bssid_list(1)) {
                LOG(ERROR) << "Failed to allocate memory for bssid_list";
                return false;
            }

            auto list = query->bssid_list(0);
            if (!std::get<0>(list)) {
                LOG(ERROR) << "Failed to get element of bssid_list";
            }
            std::get<1>(list) = bssid.mac;

            auto radio_info = m_btl_ctx.get_radio(radio->front.iface_mac);
            if (!radio_info) {
                LOG(ERROR) << "Failed to get radio info for " << radio->front.iface_mac;
                return false;
            }

            if (!message_com::send_cmdu(radio_info->slave, m_cmdu_tx)) {
                LOG(ERROR) << "Failed forwarding AP_METRICS_QUERY_MESSAGE message to son_slave";
            }

            m_ap_metric_query.push_back({radio_info->slave, bssid.mac});
        }
    }
    return true;
}

void LinkMetricsCollectionTask::handle_multi_ap_policy_config_request(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE, mid=" << std::hex << mid;

    auto steering_policy_tlv = cmdu_rx.getClass<wfa_map::tlvSteeringPolicy>();
    if (steering_policy_tlv) {
        // For the time being, agent doesn't do steering so steering policy is ignored.
    }

    auto db = AgentDB::get();

    auto metric_reporting_policy_tlv = cmdu_rx.getClass<wfa_map::tlvMetricReportingPolicy>();
    if (metric_reporting_policy_tlv) {
        /**
         * The Multi-AP Policy Config Request message containing a Metric Reporting Policy TLV is
         * sent by the controller and received by the backhaul manager.
         * The backhaul manager forwards the request message "as is" to all the slaves managing the
         * radios which Radio Unique Identifier has been specified.
         */
        for (size_t i = 0; i < metric_reporting_policy_tlv->metrics_reporting_conf_list_length();
             i++) {
            auto tuple = metric_reporting_policy_tlv->metrics_reporting_conf_list(i);
            if (!std::get<0>(tuple)) {
                LOG(ERROR) << "Failed to get metrics_reporting_conf[" << i
                           << "] from TLV_METRIC_REPORTING_POLICY";
                return;
            }

            auto metrics_reporting_conf = std::get<1>(tuple);

            std::shared_ptr<backhaul_manager::sRadioInfo> radio =
                m_btl_ctx.get_radio(metrics_reporting_conf.radio_uid);
            if (radio) {
                uint16_t length = message_com::get_uds_header(cmdu_rx)->length;
                cmdu_rx.swap(); // swap back before forwarding
                if (!message_com::forward_cmdu_to_uds(radio->slave, cmdu_rx, length)) {
                    LOG(ERROR) << "Failed to forward message to slave " << radio->radio_mac;
                }
                cmdu_rx.swap(); // swap back to normal after forwarding, for next iteration
            } else {
                LOG(INFO) << "Radio Unique Identifier " << metrics_reporting_conf.radio_uid
                          << " not found";
            }
        }

        /**
         * The AP Metrics Reporting Interval field indicates if periodic AP metrics reporting is
         * to be enabled, and if so the cadence.
         *
         * Store configured interval value and restart the timer.
         *
         * Reporting interval value works just for enabling/disabling auto sending AP Metrics Response,
         * which will be send every 500 ms.
         */
        ap_metrics_reporting_info.reporting_interval_s =
            metric_reporting_policy_tlv->metrics_reporting_interval_sec();
        ap_metrics_reporting_info.last_reporting_time_point = std::chrono::steady_clock::now();
    }

    // send ACK_MESSAGE back to the controller
    if (!m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return;
    }

    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(src_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

void LinkMetricsCollectionTask::handle_slave_ap_metrics_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                                 const sMacAddr &src_mac)
{
    auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received AP_METRICS_RESPONSE_MESSAGE, mid=" << std::hex << int(mid);

    auto db = AgentDB::get();

    if (db->controller_info.bridge_mac == net::network_utils::ZERO_MAC) {
        LOG(ERROR) << "controller_info.bridge_mac == ZERO_MAC. Skip AP_METRICS_RESPONSE_MESSAGE";
        return;
    }

    /**
     * If AP Metrics Response message does not correspond to a previously received and forwarded
     * AP Metrics Query message (which we know because message id is not set), then forward message
     * to controller.
     * This might happen when channel utilization value has crossed configured threshold or when
     * periodic metrics reporting interval has elapsed.
     */
    if (0 == mid) {
        uint16_t length = message_com::get_uds_header(cmdu_rx)->length;
        cmdu_rx.swap(); //swap back before forwarding
        m_btl_ctx.send_cmdu_to_broker(cmdu_rx, tlvf::mac_to_string(db->controller_info.bridge_mac),
                                      tlvf::mac_to_string(db->bridge.mac), length);
        return;
    }

    /**
     * When periodic metrics reporting interval has elapsed, we emulate that we have received an
     * AP Metrics Query message from controller. To differentiate real queries from emulated ones,
     * we use a "special" mid value.
     * Note that this design is flaw as a real query might also have this special mid value. This
     * is just a quick and dirty fix to pass 4.7.5 and 4.7.6 for M1
     * TODO: to be fixed as part of #1328
     */
    if (UINT16_MAX == mid) {
        mid = 0;
    }

    auto ap_metrics_tlv = cmdu_rx.getClass<wfa_map::tlvApMetrics>();
    if (!ap_metrics_tlv) {
        LOG(ERROR) << "Failed cmdu_rx.getClass<wfa_map::tlvApMetrics>(), mid=" << std::hex << mid;
        return;
    }

    auto bssid_tlv = ap_metrics_tlv->bssid();
    auto mac       = std::find_if(
        m_ap_metric_query.begin(), m_ap_metric_query.end(),
        [&bssid_tlv](sApMetricsQuery const &query) { return query.bssid == bssid_tlv; });

    if (mac == m_ap_metric_query.end()) {
        LOG(ERROR) << "Failed search in ap_metric_query for bssid: " << bssid_tlv
                   << " from mid=" << std::hex << mid;
        return;
    }

    sApMetrics metric;
    // Copy data to the response vector
    metric.bssid               = ap_metrics_tlv->bssid();
    metric.channel_utilization = ap_metrics_tlv->channel_utilization();
    metric.number_of_stas_currently_associated =
        ap_metrics_tlv->number_of_stas_currently_associated();
    metric.estimated_service_parameters = ap_metrics_tlv->estimated_service_parameters();
    auto info                           = ap_metrics_tlv->estimated_service_info_field();
    for (size_t i = 0; i < ap_metrics_tlv->estimated_service_info_field_length(); i++) {
        metric.estimated_service_info_field.push_back(info[i]);
    }
    std::vector<sStaTrafficStats> traffic_stats_response;

    for (auto &sta_traffic : cmdu_rx.getClassList<wfa_map::tlvAssociatedStaTrafficStats>()) {
        if (!sta_traffic) {
            LOG(ERROR) << "Failed to get class list for tlvAssociatedStaTrafficStats";
            continue;
        }

        traffic_stats_response.push_back(
            {sta_traffic->sta_mac(), sta_traffic->byte_sent(), sta_traffic->byte_recived(),
             sta_traffic->packets_sent(), sta_traffic->packets_recived(),
             sta_traffic->tx_packets_error(), sta_traffic->rx_packets_error(),
             sta_traffic->retransmission_count()});
    }

    std::vector<sStaLinkMetrics> link_metrics_response;
    for (auto &sta_link_metric : cmdu_rx.getClassList<wfa_map::tlvAssociatedStaLinkMetrics>()) {
        if (!sta_link_metric) {
            LOG(ERROR) << "Failed getClassList<wfa_map::tlvAssociatedStaLinkMetrics>";
            continue;
        }
        if (sta_link_metric->bssid_info_list_length() != 1) {
            LOG(ERROR) << "sta_link_metric->bssid_info_list_length() should be equal to 1";
            continue;
        }
        auto response_list = sta_link_metric->bssid_info_list(0);
        link_metrics_response.push_back({sta_link_metric->sta_mac(), std::get<1>(response_list)});
    }

    // Fill a response vector
    m_ap_metric_response.push_back({metric, traffic_stats_response, link_metrics_response});

    // Remove an entry from the processed query
    m_ap_metric_query.erase(
        std::remove_if(m_ap_metric_query.begin(), m_ap_metric_query.end(),
                       [&](sApMetricsQuery const &query) { return mac->bssid == query.bssid; }),
        m_ap_metric_query.end());

    if (!m_ap_metric_query.empty()) {
        return;
    }

    // We received all responses - prepare and send response message to the controller
    auto cmdu_header = m_cmdu_tx.create(mid, ieee1905_1::eMessageType::AP_METRICS_RESPONSE_MESSAGE);

    if (!cmdu_header) {
        LOG(ERROR) << "Failed building IEEE1905 AP_METRICS_RESPONSE_MESSAGE";
        return;
    }

    // Prepare tlvApMetrics for each processed query
    for (const auto &response : m_ap_metric_response) {
        auto ap_metrics_response_tlv = m_cmdu_tx.addClass<wfa_map::tlvApMetrics>();
        if (!ap_metrics_response_tlv) {
            LOG(ERROR) << "Failed addClass<wfa_map::tlvApMetrics>";
            return;
        }

        ap_metrics_response_tlv->bssid()               = response.metric.bssid;
        ap_metrics_response_tlv->channel_utilization() = response.metric.channel_utilization;
        ap_metrics_response_tlv->number_of_stas_currently_associated() =
            response.metric.number_of_stas_currently_associated;
        ap_metrics_response_tlv->estimated_service_parameters() =
            response.metric.estimated_service_parameters;
        if (!ap_metrics_response_tlv->alloc_estimated_service_info_field(
                response.metric.estimated_service_info_field.size())) {
            LOG(ERROR) << "Couldn't allocate "
                          "ap_metrics_response_tlv->alloc_estimated_service_info_field";
            return;
        }
        std::copy_n(response.metric.estimated_service_info_field.begin(),
                    response.metric.estimated_service_info_field.size(),
                    ap_metrics_response_tlv->estimated_service_info_field());

        for (auto &stat : response.sta_traffic_stats) {
            auto sta_traffic_response_tlv =
                m_cmdu_tx.addClass<wfa_map::tlvAssociatedStaTrafficStats>();

            if (!sta_traffic_response_tlv) {
                LOG(ERROR) << "Failed addClass<wfa_map::tlvAssociatedStaTrafficStats>";
                continue;
            }

            sta_traffic_response_tlv->sta_mac()              = stat.sta_mac;
            sta_traffic_response_tlv->byte_sent()            = stat.byte_sent;
            sta_traffic_response_tlv->byte_recived()         = stat.byte_recived;
            sta_traffic_response_tlv->packets_sent()         = stat.packets_sent;
            sta_traffic_response_tlv->packets_recived()      = stat.packets_recived;
            sta_traffic_response_tlv->tx_packets_error()     = stat.tx_packets_error;
            sta_traffic_response_tlv->rx_packets_error()     = stat.rx_packets_error;
            sta_traffic_response_tlv->retransmission_count() = stat.retransmission_count;
        }

        for (auto &link_metric : response.sta_link_metrics) {
            auto sta_link_metric_response_tlv =
                m_cmdu_tx.addClass<wfa_map::tlvAssociatedStaLinkMetrics>();

            if (!sta_link_metric_response_tlv) {
                LOG(ERROR) << "Failed addClass<wfa_map::tlvAssociatedStaLinkMetrics>";
                continue;
            }

            sta_link_metric_response_tlv->sta_mac() = link_metric.sta_mac;
            if (!sta_link_metric_response_tlv->alloc_bssid_info_list(1)) {
                LOG(ERROR) << "Failed alloc_bssid_info_list";
                continue;
            }
            auto &sta_link_metric_response =
                std::get<1>(sta_link_metric_response_tlv->bssid_info_list(0));
            sta_link_metric_response = link_metric.bssid_info;
        }
    }

    // Clear the m_ap_metric_response vector after preparing response to the controller
    m_ap_metric_response.clear();

    LOG(DEBUG) << "Sending AP_METRICS_RESPONSE_MESSAGE, mid=" << std::hex << mid;
    m_btl_ctx.send_cmdu_to_broker(m_cmdu_tx, tlvf::mac_to_string(db->controller_info.bridge_mac),
                                  tlvf::mac_to_string(db->bridge.mac));
}

bool LinkMetricsCollectionTask::add_link_metrics(
    const sMacAddr &reporter_al_mac, const backhaul_manager::sLinkInterface &link_interface,
    const backhaul_manager::sLinkNeighbor &link_neighbor, const sLinkMetrics &link_metrics,
    ieee1905_1::eLinkMetricsType link_metrics_type)
{
    /**
     * Add Transmitter Link Metric TLV if specifically requested or both requested
     */
    if ((ieee1905_1::eLinkMetricsType::TX_LINK_METRICS_ONLY == link_metrics_type) ||
        (ieee1905_1::eLinkMetricsType::BOTH_TX_AND_RX_LINK_METRICS == link_metrics_type)) {
        auto tlvTransmitterLinkMetric = m_cmdu_tx.addClass<ieee1905_1::tlvTransmitterLinkMetric>();
        if (!tlvTransmitterLinkMetric) {
            LOG(ERROR) << "addClass ieee1905_1::tlvTransmitterLinkMetric failed";
            return false;
        }

        tlvTransmitterLinkMetric->reporter_al_mac() = reporter_al_mac;
        tlvTransmitterLinkMetric->neighbor_al_mac() = link_neighbor.al_mac;

        if (!tlvTransmitterLinkMetric->alloc_interface_pair_info()) {
            LOG(ERROR) << "alloc_interface_pair_info failed";
            return false;
        }
        auto interface_pair_info = tlvTransmitterLinkMetric->interface_pair_info(0);
        if (!std::get<0>(interface_pair_info)) {
            LOG(ERROR) << "Failed accessing interface_pair_info";
            return false;
        }
        auto interfacePairInfo                      = std::get<1>(interface_pair_info);
        interfacePairInfo.rc_interface_mac          = link_interface.iface_mac;
        interfacePairInfo.neighbor_interface_mac    = link_neighbor.iface_mac;
        interfacePairInfo.link_metric_info.intfType = link_interface.media_type;
        // TODO
        //Indicates whether or not the 1905.1 link includes one or more IEEE 802.1 bridges
        interfacePairInfo.link_metric_info.IEEE802_1BridgeFlag =
            ieee1905_1::tlvTransmitterLinkMetric::LINK_DOES_NOT_INCLUDE_BRIDGE;
        interfacePairInfo.link_metric_info.packet_errors = link_metrics.transmitter.packet_errors;
        interfacePairInfo.link_metric_info.transmitted_packets =
            link_metrics.transmitter.transmitted_packets;
        interfacePairInfo.link_metric_info.mac_throughput_capacity =
            std::min(link_metrics.transmitter.mac_throughput_capacity_mbps,
                     static_cast<uint32_t>(UINT16_MAX));
        interfacePairInfo.link_metric_info.link_availability =
            link_metrics.transmitter.link_availability;
        interfacePairInfo.link_metric_info.phy_rate =
            std::min(link_metrics.transmitter.phy_rate_mbps, static_cast<uint32_t>(UINT16_MAX));
    }

    /**
     * Add Receiver Link Metric TLV if specifically requested or both requested
     */
    if ((ieee1905_1::eLinkMetricsType::RX_LINK_METRICS_ONLY == link_metrics_type) ||
        (ieee1905_1::eLinkMetricsType::BOTH_TX_AND_RX_LINK_METRICS == link_metrics_type)) {
        auto tlvReceiverLinkMetric = m_cmdu_tx.addClass<ieee1905_1::tlvReceiverLinkMetric>();
        if (!tlvReceiverLinkMetric) {
            LOG(ERROR) << "addClass ieee1905_1::tlvReceiverLinkMetric failed";
            return false;
        }

        tlvReceiverLinkMetric->reporter_al_mac() = reporter_al_mac;
        tlvReceiverLinkMetric->neighbor_al_mac() = link_neighbor.al_mac;

        if (!tlvReceiverLinkMetric->alloc_interface_pair_info()) {
            LOG(ERROR) << "alloc_interface_pair_info failed";
            return false;
        }
        auto interface_pair_info = tlvReceiverLinkMetric->interface_pair_info(0);
        if (!std::get<0>(interface_pair_info)) {
            LOG(ERROR) << "Failed accessing interface_pair_info";
            return false;
        }
        auto interfacePairInfo                           = std::get<1>(interface_pair_info);
        interfacePairInfo.rc_interface_mac               = link_interface.iface_mac;
        interfacePairInfo.neighbor_interface_mac         = link_neighbor.iface_mac;
        interfacePairInfo.link_metric_info.intfType      = link_interface.media_type;
        interfacePairInfo.link_metric_info.packet_errors = link_metrics.receiver.packet_errors;
        interfacePairInfo.link_metric_info.packets_received =
            link_metrics.receiver.packets_received;
        interfacePairInfo.link_metric_info.rssi_db = link_metrics.receiver.rssi;
    }

    return true;
}

std::unique_ptr<link_metrics_collector> LinkMetricsCollectionTask::create_link_metrics_collector(
    const backhaul_manager::sLinkInterface &link_interface) const
{
    ieee1905_1::eMediaType media_type = link_interface.media_type;
    ieee1905_1::eMediaTypeGroup media_type_group =
        static_cast<ieee1905_1::eMediaTypeGroup>(media_type >> 8);

    if (ieee1905_1::eMediaTypeGroup::IEEE_802_3 == media_type_group) {
        return std::make_unique<ieee802_3_link_metrics_collector>();
    }

    if (ieee1905_1::eMediaTypeGroup::IEEE_802_11 == media_type_group) {
        return std::make_unique<ieee802_11_link_metrics_collector>();
    }

    LOG(ERROR) << "Unable to create link metrics collector for interface '"
               << link_interface.iface_name << "' (unsupported media type " << std::hex
               << (int)media_type << ")";

    return nullptr;
}

/**
 * @brief Gets the name of the interface with given MAC address.
 *
 * @param[in] iface_mac MAC address of the network interface.
 * @param[out] iface_name Name of the network interface on success and empty string on error.
 *
 * @return True on success and false otherwise.
 */
static bool get_iface_name(const sMacAddr &iface_mac, std::string &iface_name)
{
    if (net::network_utils::linux_iface_get_name(iface_mac, iface_name)) {
        return true;
    }

    LOG(ERROR) << "Failed getting interface name for MAC address: " << iface_mac;
    iface_name.clear();

    return false;
}

bool LinkMetricsCollectionTask::get_neighbor_links(
    const sMacAddr &neighbor_mac_filter,
    std::map<backhaul_manager::sLinkInterface, std::vector<backhaul_manager::sLinkNeighbor>>
        &neighbor_links_map)
{
    // TODO: Topology Database is required to implement this method.

    // TODO: this is not accurate as we have made the assumption that there is a single interface.
    // Note that when processing Topology Discovery message we must store the IEEE 1905.1 AL MAC
    // address of the transmitting device together with the interface that such message is
    // received through.
    backhaul_manager::sLinkInterface wired_interface;
    auto db = AgentDB::get();

    wired_interface.iface_name = db->ethernet.iface_name;
    wired_interface.iface_mac  = db->ethernet.mac;

    if (!MediaType::get_media_type(wired_interface.iface_name,
                                   ieee1905_1::eMediaTypeGroup::IEEE_802_3,
                                   wired_interface.media_type)) {
        LOG(ERROR) << "Unable to compute media type for interface " << wired_interface.iface_name;
        return false;
    }

    for (const auto &neighbors_on_local_iface : db->neighbor_devices) {
        auto &neighbors = neighbors_on_local_iface.second;
        for (const auto &neighbor_entry : neighbors) {
            backhaul_manager::sLinkNeighbor neighbor;
            neighbor.al_mac    = neighbor_entry.first;
            neighbor.iface_mac = neighbor_entry.second.transmitting_iface_mac;
            if ((neighbor_mac_filter == net::network_utils::ZERO_MAC) ||
                (neighbor_mac_filter == neighbor.al_mac)) {
                neighbor_links_map[wired_interface].push_back(neighbor);
            }
        }
    }

    // Also include a link for each associated client
    for (const auto radio : db->get_radios_list()) {
        if (!radio) {
            continue;
        }

        for (const auto &associated_client : radio->associated_clients) {
            auto &bssid = associated_client.second.bssid;

            backhaul_manager::sLinkInterface interface;
            if (!get_iface_name(bssid, interface.iface_name)) {
                LOG(ERROR) << "Unable to get interface name for BSSID " << bssid;
                return false;
            }

            interface.iface_mac  = bssid;
            interface.media_type = MediaType::get_802_11_media_type(radio->freq_type,
                                                                    radio->max_supported_bw);

            if (ieee1905_1::eMediaType::UNKNOWN_MEDIA == interface.media_type) {
                LOG(ERROR) << "Unknown media type for interface " << interface.iface_name;
                return false;
            }

            LOG(TRACE) << "Getting neighbors connected to interface " << interface.iface_name
                       << " with BSSID " << bssid;

            // TODO: This is not correct... We actually have to get this from the topology
            // discovery message, which will give us the neighbor interface and AL MAC addresses.
            backhaul_manager::sLinkNeighbor neighbor;
            neighbor.iface_mac = associated_client.first;
            neighbor.al_mac    = neighbor.iface_mac;

            if ((neighbor_mac_filter == net::network_utils::ZERO_MAC) ||
                (neighbor_mac_filter == neighbor.al_mac)) {
                neighbor_links_map[interface].push_back(neighbor);
            }
        }
    }

    return true;
}

} // namespace beerocks
