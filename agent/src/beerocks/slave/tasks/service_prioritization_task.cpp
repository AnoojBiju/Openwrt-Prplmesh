/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "service_prioritization_task.h"
#include "../agent_db.h"
#include "../son_slave_thread.h"
#include <beerocks/tlvf/beerocks_message_apmanager.h>

#include <bpl/bpl_service_prio_utils.h>
#include <tlvf/wfa_map/tlvDscpMappingTable.h>
#include <tlvf/wfa_map/tlvProfile2ErrorCode.h>

namespace beerocks {

ServicePrioritizationTask::ServicePrioritizationTask(slave_thread &btl_ctx,
                                                     ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::SERVICE_PRIORITIZATION), m_btl_ctx(btl_ctx), m_cmdu_tx(cmdu_tx)
{
    LOG(DEBUG) << "called " << __func__;
    service_prio_utils = bpl::register_service_prio_utils();
    if (ServicePrioritizationTask::service_prio_utils) {
        LOG(DEBUG) << __func__ << "called allocated";
    } else {
        LOG(DEBUG) << __func__ << "called  not allocated";
    }
}

bool ServicePrioritizationTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx,
                                            uint32_t iface_index, const sMacAddr &dst_mac,
                                            const sMacAddr &src_mac, int fd,
                                            std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::SERVICE_PRIORITIZATION_REQUEST_MESSAGE: {
        handle_service_prioritization_request(cmdu_rx, src_mac);
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

bool service_prio_utils_init() { return true; }

void ServicePrioritizationTask::handle_service_prioritization_request(
    ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac)
{
    const auto mid = cmdu_rx.getMessageId();

    LOG(DEBUG) << "Received SERVICE_PRIORITIZATION_REQUEST_MESSAGE, mid=" << std::hex << mid;

    m_cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);

    LOG(DEBUG) << "sending ACK message back to controller";
    m_btl_ctx.send_cmdu_to_controller({}, m_cmdu_tx);

    auto service_prioritization_rules =
        cmdu_rx.getClassList<wfa_map::tlvServicePrioritizationRule>();

    // Split rules to lists of rules to remove and rules to add.
    // If rule is being added, but it already exist only overwite it.
    std::vector<std::shared_ptr<wfa_map::tlvServicePrioritizationRule>> rules_to_remove;
    std::vector<std::shared_ptr<wfa_map::tlvServicePrioritizationRule>> rules_to_add;
    auto db = AgentDB::get();
    for (auto &rule : service_prioritization_rules) {
        LOG(DEBUG) << "Service Prioritization Rule TLV Dump"
                   << "\nRule id=" << rule->rule_params().id
                   << "\nadd_remove=" << rule->rule_params().bits_field1.add_remove
                   << "\nprecedence=" << rule->rule_params().precedence
                   << "\noutput=" << rule->rule_params().output
                   << "\nalways_match=" << rule->rule_params().bits_field2.always_match;
        // Remove
        if (!rule->rule_params().bits_field1.add_remove) {
            rules_to_remove.push_back(rule);
            continue;
        }

        auto rule_found_it = db->service_prioritization.rules.find(rule->rule_params().id);

        // Overwrite existing rule
        if (rule_found_it != db->service_prioritization.rules.end()) {
            rule_found_it->second = rule->rule_params();
            continue;
        }

        // Rule to Add
        rules_to_add.push_back(rule);
    }

    // Prepare error response message, in case we will need to fill it.
    if (!m_cmdu_tx.create(0, ieee1905_1::eMessageType::ERROR_RESPONSE_MESSAGE)) {
        LOG(ERROR) << "CMDU creation has failed";
        return;
    }

    for (const auto &rule_to_remove : rules_to_remove) {
        auto rule_found_it =
            db->service_prioritization.rules.find(rule_to_remove->rule_params().id);
        if (rule_found_it != db->service_prioritization.rules.end()) {
            db->service_prioritization.rules.erase(rule_found_it);
            continue;
        }
        // If we were asked to remove a rule we don't have, add Profile-2 Error Code TLV.
        auto profile2_error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2ErrorCode>();
        if (!profile2_error_code_tlv) {
            LOG(ERROR) << "addClass has failed";
            return;
        }
        profile2_error_code_tlv->reason_code() =
            wfa_map::tlvProfile2ErrorCode::eReasonCode::SERVICE_PRIORITIZATION_RULE_NOT_FOUND;
        profile2_error_code_tlv->set_service_prioritization_rule_id(
            rule_to_remove->rule_params().id);
    }

    for (const auto &rule_to_add : rules_to_add) {
        // '1' is the current maximum allowed ruled specified in the
        // tlvProfile2ApCapability::max_prioritization_rules
        if (db->service_prioritization.rules.size() >= db->device_conf.max_prioritization_rules) {
            auto profile2_error_code_tlv = m_cmdu_tx.addClass<wfa_map::tlvProfile2ErrorCode>();
            if (!profile2_error_code_tlv) {
                LOG(ERROR) << "addClass has failed";
                return;
            }
            profile2_error_code_tlv->reason_code() = wfa_map::tlvProfile2ErrorCode::
                NUMBER_OF_SERVICE_PRIORITIZATION_RULES_EXCEEDED_THE_MAXIMUM_SUPPORTED;
            profile2_error_code_tlv->set_service_prioritization_rule_id(
                rule_to_add->rule_params().id);
            break;
        }

        db->service_prioritization.rules[rule_to_add->rule_params().id] =
            rule_to_add->rule_params();
    }

    // If added Profile2ErrorCode TLVs, send the ERROR_RESPONSE_MESSAGE.
    if (m_cmdu_tx.getClass<wfa_map::tlvProfile2ErrorCode>()) {
        m_btl_ctx.send_cmdu_to_controller({}, m_cmdu_tx);
    }

    auto dscp_mapping_table_tlv = cmdu_rx.getClass<wfa_map::tlvDscpMappingTable>();
    if (dscp_mapping_table_tlv) {
        auto dscp_mapping_table = dscp_mapping_table_tlv->dscp_pcp_mapping(0);
        std::copy(dscp_mapping_table, dscp_mapping_table + 64,
                  db->service_prioritization.dscp_mapping_table.begin());
    }
    auto m_dscp_mapping_table = db->service_prioritization.dscp_mapping_table;
    int i                     = 0;
    for (const auto &dscp : m_dscp_mapping_table) {
        LOG(DEBUG) << "dscp[" << i << "]=" << dscp;
        i++;
    }

    const auto &rules = db->service_prioritization.rules;
    auto it           = rules.cbegin();
    i                 = 0;
    LOG(DEBUG) << "All Service Prioritization Rules Dump max_rules="
               << db->device_conf.max_prioritization_rules;
    while (it != rules.cend()) {
        LOG(DEBUG) << "Service Prioritization Rule TLV i=" << i << "\nRule id=" << it->second.id
                   << "\nadd_remove=" << it->second.bits_field1.add_remove
                   << "\nprecedence=" << it->second.precedence << "\noutput=" << it->second.output
                   << "\nalways_match=" << it->second.bits_field2.always_match;
        ++it;
        i++;
    }

    if (db->service_prioritization.rules.empty()) {
        LOG(ERROR) << "No active rules, disabling service prio in hostap";
    } else {
        if (!qos_apply_active_rule()) {
            LOG(ERROR) << "Failed setting up QoS active rule";
        }
    }
}

bool ServicePrioritizationTask::qos_apply_active_rule()
{
    const auto &rules = AgentDB::get()->service_prioritization.rules;
    auto it           = rules.cbegin();
    auto active       = rules.cend();
    while (it != rules.cend()) {
        if (it->second.bits_field2.always_match) {
            if ((active == rules.cend()) || (active->second.precedence < it->second.precedence)) {
                active = it;
            }
        }
        ++it;
    }
    LOG(ERROR) << "inside %s" << __func__;
    if (active != rules.cend()) {
        auto db                                      = AgentDB::get();
        std::string iface                            = "wlan0";
        const auto &radio                            = db->radio(iface);
        const auto &radio_mac                        = radio->front.iface_mac;
        beerocks_message::sServicePrioConfig request = {0};
        request.mode                                 = active->second.output;
        std::copy(db->service_prioritization.dscp_mapping_table.begin(),
                  db->service_prioritization.dscp_mapping_table.end(), request.data);
        LOG(DEBUG) << "Before sending";
        if (radio_mac != beerocks::net::network_utils::ZERO_MAC) {
            beerocks::ServicePrioritizationTask::send_service_prio_config(radio_mac, request);
            LOG(DEBUG) << "After sending";
        }
        switch (active->second.output) {
        case QOS_USE_DSCP_MAP:
            LOG(ERROR) << "inside QOS_USE_DSCP_MAP" << __func__;
            return qos_setup_dscp_map();
        case QOS_USE_UP:
            LOG(ERROR) << "inside QOS_USE_UP" << __func__;
            return qos_setup_up_map();
        default:
            LOG(ERROR) << "inside single_value" << __func__;
            return qos_setup_single_value_map(active->second.output);
        }
    }

    return true;
}

bool ServicePrioritizationTask::qos_flush_setup()
{
    LOG(ERROR) << "inside %s" << __func__;
    if (!service_prio_utils) {
        return false;
    }
    //TODO: PPM-2389, drive ebtables or external software
    service_prio_utils->flush_rules();
    return true;
}

bool ServicePrioritizationTask::qos_setup_single_value_map(uint8_t pcp)
{
    if (pcp >= QOS_USE_DSCP_MAP) {
        LOG(ERROR) << "invalid output value for QoS single rule (" << static_cast<uint16_t>(pcp)
                   << ')';
        return false;
    }

    qos_flush_setup();

    LOG(DEBUG) << "ServicePrioritizationTask::qos_create_single_value_map - NOT IMPLEMENTED YET";
    service_prio_utils->apply_single_value_map(pcp);

    //TODO: PPM-2389, drive ebtables or external software
    return true;
}

bool ServicePrioritizationTask::qos_setup_dscp_map()
{
    LOG(ERROR) << "inside %s" << __func__;
    LOG(DEBUG) << "ServicePrioritizationTask::qos_setup_dscp_map - DSCP custom map used for PCP";

    qos_flush_setup();

    LOG(DEBUG) << "ServicePrioritizationTask::qos_setup_dscp_map - NOT IMPLEMENTED YET";
    service_prio_utils->apply_dscp_map();

    //TODO: PPM-2389, drive ebtables or external software
    return true;
}

bool ServicePrioritizationTask::qos_setup_up_map()
{
    LOG(DEBUG) << "ServicePrioritizationTask::qos_setup_up_map - UP used for PCP";

    qos_flush_setup();

    LOG(DEBUG) << "ServicePrioritizationTask::qos_setup_up_map - NOT IMPLEMENTED YET";
    service_prio_utils->apply_up_map();

    //TODO: PPM-2389, drive ebtables or external software
    return true;
}

bool ServicePrioritizationTask::send_service_prio_config(
    const sMacAddr &radio_mac, const beerocks_message::sServicePrioConfig &request)
{
    m_btl_ctx.m_radio_managers.do_on_each_radio_manager(
        [&](slave_thread::sManagedRadio &radio_manager,
            const std::string &fronthaul_iface) -> bool {
            auto request_msg = message_com::create_vs_message<
                beerocks_message::cACTION_APMANAGER_HOSTAP_SERVICE_PRIO_CONFIG>(m_cmdu_tx);

            if (!request_msg) {
                LOG(ERROR)
                    << "Failed to build cACTION_APMANAGER_HOSTAP_SERVICE_PRIO_CONFIG message";
                return false;
            }

            request_msg->cs_params().mode = request.mode;
            std::copy(request.data, request.data + 64, request_msg->cs_params().data);
            LOG(DEBUG) << "Sending service priority config to radio " << radio_mac
                       << " mode: " << request.mode;

            m_btl_ctx.send_cmdu(radio_manager.ap_manager_fd, m_cmdu_tx);
            return true;
        });
    return true;
}

} // namespace beerocks
