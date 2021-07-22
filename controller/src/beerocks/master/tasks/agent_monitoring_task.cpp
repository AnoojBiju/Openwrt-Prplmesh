/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "agent_monitoring_task.h"
#include "../db/db_algo.h"
#include "../son_actions.h"

#include <bpl/bpl_cfg.h>
#include <easylogging++.h>
#include <tlvf/ieee_1905_1/tlvDeviceInformation.h>
#include <tlvf/wfa_map/tlvApOperationalBSS.h>
#include <tlvf/wfa_map/tlvMetricReportingPolicy.h>
#include <tlvf/wfa_map/tlvProfile2Default802dotQSettings.h>
#include <tlvf/wfa_map/tlvProfile2TrafficSeparationPolicy.h>

using namespace beerocks;
using namespace net;
using namespace son;

agent_monitoring_task::agent_monitoring_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_,
                                             task_pool &tasks_, const std::string &task_name_)
    : task(task_name_), database(database_), cmdu_tx(cmdu_tx_), tasks(tasks_)
{
}

void agent_monitoring_task::work()
{
    if (!m_ap_autoconfig_renew_sent) {
        /**
         * Usually, the ap-configuration sequence is started when the agent sends the ap-config
         * search request message, to which the controller responds with the ap-config response
         * message.
         * But with the scenario presented in PPM-1390, the controller process is restarted and
         * loads without ever receiving an ap-config search request message.
         * To resolve this, we can initialize the ap-config "handshake" by sending a ap-config
         * renew message, informing the agent of a newly restarted controller process.
         * To make sure all the tasks in the controller are running correctly, we need to send
         * the ap-config renew message after the controller finished its startup function,
         * during the event loop handling.
         * Doing this will give all the controller tasks enough time to finish their
         * initialization.
         * Since the agent_monitoring_task is responsible for handling the AGENT_JOIN as well as
         * the WSC autoconfiguration, it was suggested as the best place to send the ap-config
         * renew message from.
         **/
        son_actions::send_ap_config_renew_msg(cmdu_tx, database);
        m_ap_autoconfig_renew_sent = true;
    }
}

bool agent_monitoring_task::handle_ieee1905_1_msg(const sMacAddr &src_mac,
                                                  ieee1905_1::CmduMessageRx &cmdu_rx)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_WSC_MESSAGE: {
        auto tlvWsc = cmdu_rx.getClass<ieee1905_1::tlvWsc>();
        if (!tlvWsc) {
            LOG(ERROR) << "getClass<ieee1905_1::tlvWsc> failed";
            return false;
        }

        auto m1 = WSC::m1::parse(*tlvWsc);
        if (!m1) {
            LOG(INFO) << "Not a valid M1 - Ignoring WSC CMDU";
            return false;
        }
        return start_task(tlvf::mac_to_string(src_mac), m1, cmdu_rx);
    }
    case ieee1905_1::eMessageType::TOPOLOGY_RESPONSE_MESSAGE: {
        start_agent_monitoring(src_mac, cmdu_rx);
        break;
    }
    default: {
        return false;
    }
    }
    return true;
}

bool agent_monitoring_task::start_agent_monitoring(const sMacAddr &src_mac,
                                                   ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto tlvDeviceInformation = cmdu_rx.getClass<ieee1905_1::tlvDeviceInformation>();
    if (!tlvDeviceInformation) {
        LOG(ERROR) << "ieee1905_1::tlvDeviceInformation not found";
        return false;
    }

    const auto &al_mac    = tlvDeviceInformation->mac();
    auto tlvApInformation = cmdu_rx.getClass<wfa_map::tlvApOperationalBSS>();
    if (!tlvApInformation) {
        LOG(ERROR) << "ieee1905_1::tlvApOperationalBSS not found";
        return false;
    }

    for (uint8_t i = 0; i < tlvApInformation->radio_list_length(); i++) {
        auto radio_entry   = std::get<1>(tlvApInformation->radio_list(i));
        auto ruid          = radio_entry.radio_uid();
        auto bsses_from_m2 = m_bss_configured[ruid];

        for (uint8_t j = 0; j < radio_entry.radio_bss_list_length(); j++) {
            auto bss_entry = std::get<1>(radio_entry.radio_bss_list(j));
            bool found     = false;

            for (const auto &bss_from_m2 : bsses_from_m2) {
                if (bss_from_m2.ssid == bss_entry.ssid_str()) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                LOG(WARNING) << "Configured BSS [" << bss_entry.ssid_str()
                             << "] for radio: " << ruid << " of device " << al_mac
                             << "came from nowhere (wasn't specified in M2)";
                return false;
            }
        }
        for (const auto &bss_from_m2 : bsses_from_m2) {
            bool found = false;

            for (uint8_t j = 0; j < radio_entry.radio_bss_list_length(); j++) {
                auto bss_entry = std::get<1>(radio_entry.radio_bss_list(j));
                if (bss_from_m2.ssid == bss_entry.ssid_str()) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                LOG(WARNING) << "BSS [" << bss_from_m2.ssid
                             << "] reported in M2 was not configured for : " << ruid
                             << " of device " << al_mac;
                return false;
            }
        }
    }
    return true;
}

bool agent_monitoring_task::start_task(const std::string &src_mac, std::shared_ptr<WSC::m1> m1,
                                       ieee1905_1::CmduMessageRx &cmdu_rx)
{
    if (!send_tlv_metric_reporting_policy(src_mac, m1, cmdu_rx, cmdu_tx)) {
        LOG(ERROR) << "Failed to send Metric Reporting Policy to radio agent=" << src_mac;
    }
    if (!send_tlv_empty_channel_selection_request(src_mac, cmdu_tx)) {
        LOG(ERROR) << "Failed to send Channel Selection Request to radio agent=" << src_mac;
    }
    if (!database.setting_certification_mode()) {
        // trigger Topology query
        LOG(TRACE) << "Sending Topology Query to " << src_mac;
        son_actions::send_topology_query_msg(src_mac, cmdu_tx, database);

        // trigger channel selection
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CHANNEL_PREFERENCE_QUERY_MESSAGE)) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        son_actions::send_cmdu_to_agent(src_mac, cmdu_tx, database);
    }
    if (!database.setting_certification_mode()) {
        // trigger AP capability query
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::AP_CAPABILITY_QUERY_MESSAGE)) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        son_actions::send_cmdu_to_agent(src_mac, cmdu_tx, database);
    }
    return true;
}

bool agent_monitoring_task::send_tlv_metric_reporting_policy(const std::string &dst_mac,
                                                             std::shared_ptr<WSC::m1> m1,
                                                             ieee1905_1::CmduMessageRx &cmdu_rx,
                                                             ieee1905_1::CmduMessageTx &cmdu_tx)
{
    auto radio_basic_caps = cmdu_rx.getClass<wfa_map::tlvApRadioBasicCapabilities>();
    if (!radio_basic_caps) {
        LOG(ERROR) << "getClass<wfa_map::tlvApRadioBasicCapabilities> failed";
        return false;
    }

    auto ruid                  = radio_basic_caps->radio_uid();
    auto al_mac                = tlvf::mac_to_string(m1->mac_addr());
    const auto &bss_info_confs = database.get_bss_info_configuration(m1->mac_addr());
    uint8_t num_bsss           = 0;

    for (const auto &bss_info_conf : bss_info_confs) {
        // Check if the radio supports it
        if (!son_actions::has_matching_operating_class(*radio_basic_caps, bss_info_conf)) {
            continue;
        }
        if (num_bsss >= radio_basic_caps->maximum_number_of_bsss_supported()) {
            LOG(INFO) << "Configured BSSes exceed maximum for " << al_mac << " radio " << ruid;
            break;
        }
        m_bss_configured[ruid].push_back(bss_info_conf);
        num_bsss++;
    }

    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE)) {
        LOG(ERROR) << "Failed building MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE ! ";
        return false;
    }

    if (num_bsss) {
        add_traffic_policy_tlv(database, cmdu_tx, m1);
        add_profile_2default_802q_settings_tlv(database, cmdu_tx, m1);
    }

    auto metric_reporting_policy_tlv = cmdu_tx.addClass<wfa_map::tlvMetricReportingPolicy>();
    if (!metric_reporting_policy_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvMetricReportingPolicy has failed";
        return false;
    }

    // TODO Settings needs to be changable (PPM-1140)
    metric_reporting_policy_tlv->metrics_reporting_interval_sec() =
        beerocks::bpl::DEFAULT_LINK_METRICS_REQUEST_INTERVAL_VALUE_SEC.count();

    // Add one radio configuration to list
    // TODO Multiple radio can be implemented within one message (PPM-1139)
    if (!metric_reporting_policy_tlv->alloc_metrics_reporting_conf_list()) {
        LOG(ERROR) << "Failed to add metrics_reporting_conf to tlvMetricReportingPolicy";
        return false;
    }

    auto tuple = metric_reporting_policy_tlv->metrics_reporting_conf_list(0);
    if (!std::get<0>(tuple)) {
        LOG(ERROR) << "Failed to get metrics_reporting_conf[0"
                   << "] from TLV_METRIC_REPORTING_POLICY";
        return false;
    }

    auto &reporting_conf     = std::get<1>(tuple);
    reporting_conf.radio_uid = ruid;
    reporting_conf.policy.include_associated_sta_link_metrics_tlv_in_ap_metrics_response  = 1;
    reporting_conf.policy.include_associated_sta_traffic_stats_tlv_in_ap_metrics_response = 1;

    reporting_conf.sta_metrics_reporting_rcpi_threshold                  = 0;
    reporting_conf.sta_metrics_reporting_rcpi_hysteresis_margin_override = 0;
    reporting_conf.ap_channel_utilization_reporting_threshold            = 0;

    return son_actions::send_cmdu_to_agent(dst_mac, cmdu_tx, database);
}

bool agent_monitoring_task::send_tlv_empty_channel_selection_request(
    const std::string &dst_mac, ieee1905_1::CmduMessageTx &cmdu_tx)
{
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CHANNEL_SELECTION_REQUEST_MESSAGE)) {
        LOG(ERROR) << "Failed building CHANNEL_SELECTION_REQUEST_MESSAGE ! ";
        return false;
    }
    return son_actions::send_cmdu_to_agent(dst_mac, cmdu_tx, database);
}

bool agent_monitoring_task::add_profile_2default_802q_settings_tlv(
    db &database, ieee1905_1::CmduMessageTx &cmdu_tx, std::shared_ptr<WSC::m1> m1)
{
    auto default_8021q_config = database.get_default_8021q_setting(m1->mac_addr());
    if (default_8021q_config.primary_vlan_id > 0) {
        auto tlv_default_8021q_settings =
            cmdu_tx.addClass<wfa_map::tlvProfile2Default802dotQSettings>();
        if (!tlv_default_8021q_settings) {
            LOG(ERROR) << "Failed adding tlvProfile2Default802dotQSettings";
            return false;
        }
        tlv_default_8021q_settings->primary_vlan_id() = default_8021q_config.primary_vlan_id;
        tlv_default_8021q_settings->default_pcp()     = default_8021q_config.default_pcp;
    }
    return true;
}

bool agent_monitoring_task::add_traffic_policy_tlv(db &database, ieee1905_1::CmduMessageTx &cmdu_tx,
                                                   std::shared_ptr<WSC::m1> m1)
{
    auto traffic_separation_configs =
        database.get_traffic_separataion_configuration(m1->mac_addr());
    if (!traffic_separation_configs.empty()) {
        auto tlv_traffic_policy = cmdu_tx.addClass<wfa_map::tlvProfile2TrafficSeparationPolicy>();
        if (!tlv_traffic_policy) {
            LOG(ERROR) << "Failed adding tlvProfile2TrafficSeparationPolicy";
            return false;
        }
        for (auto &config : traffic_separation_configs) {
            auto ssid_vlan_id_entry = tlv_traffic_policy->create_ssids_vlan_id_list();
            if (!ssid_vlan_id_entry) {
                LOG(ERROR) << "Failed creating ssid_vlan_id entry";
                return false;
            }
            if (!ssid_vlan_id_entry->set_ssid_name(config.ssid)) {
                LOG(ERROR) << "Failed setting ssid";
                return false;
            }
            ssid_vlan_id_entry->vlan_id() = config.vlan_id;
            if (!tlv_traffic_policy->add_ssids_vlan_id_list(ssid_vlan_id_entry)) {
                LOG(ERROR) << "Failed adding ssid_vlan_entry";
                return false;
            }
        }
    }
    return true;
}
