/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _AGENT_MONITORING_TASK_H_
#define _AGENT_MONITORING_TASK_H_

#include "../db/db.h"
#include "task.h"
#include "task_pool.h"

#include <tlvf/WSC/m1.h>

namespace son {
class agent_monitoring_task : public task {

public:
    agent_monitoring_task(db &database_, ieee1905_1::CmduMessageTx &cmdu_tx_, task_pool &tasks_,
                          const std::string &task_name_ = std::string("agent_monitoring"));
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

    static bool add_profile_2default_802q_settings_tlv(db &database,
                                                       ieee1905_1::CmduMessageTx &cmdu_tx,
                                                       std::shared_ptr<WSC::m1> m1);
    static bool add_traffic_policy_tlv(db &database, ieee1905_1::CmduMessageTx &cmdu_tx,
                                       std::shared_ptr<WSC::m1> m1);

protected:
    void work() override;

private:
    db &database;
    ieee1905_1::CmduMessageTx &cmdu_tx;
    task_pool &tasks;

    bool m_ap_autoconfig_renew_sent = false;

    /**
     * @brief Map with key=ruid and value BSSes that were configured
     * for radio with ruid (key) in M2.
     */
    std::unordered_map<sMacAddr, std::list<wireless_utils::sBssInfoConf>> m_bss_configured;

    /**
     * @brief Recive Topology Response message, checks that Agent configured BSSes
     * reported in M2 message. If it's so agent monitoring should start.
     * @param src_mac MAC address of agent.
     * @param cmdu_rx is a Topology Response message.
     */
    bool start_agent_monitoring(const std::string &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
    * @brief Sends topology query, policy configuration,
    * AP capability query, start dynamic channel selection task.
    * 
    * @param mac MAC address of agent.
    * @param m1 M1 message.
    * @param cmdu_rx AP Autoconfiguration WSC message.
    */
    bool start_task(const std::string &src_mac, std::shared_ptr<WSC::m1> m1,
                    ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Sends 'CHANNEL_SELECTION_REQUEST_MESSAGE' without any TLVs included,
     * to get Operating Channel Report back from agents.
     *
     * If a Channel Selection Request message contains zero Channel Preference TLVs,
     * it is indicating the highest preference for all channels and operating classes supported
     * by all of the Multi-AP Agent’s radios.
     *
     * Operating Channel Report should be sent back from the Agent after this empty message.
     * That way operating classes are registered to data model.
     *
     * @param dst_mac Destination MAC address.
     * @param cmdu_tx CMDU to be transmitted.
     * @return True on success, false otherwise.
    */
    bool send_tlv_empty_channel_selection_request(const std::string &dst_mac,
                                                  ieee1905_1::CmduMessageTx &cmdu_tx);

    /**
     * @brief Sends Tlv metric resporting policy within 'MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE'
     *
     * @param dst_mac Destination MAC address.
     * @param m1 M1.
     * @param cmdu_rx AP AUTOCONFIGURATION WSC MESSAGE.
     * @param cmdu_tx CMDU to be transmitted.
     * @return True on success, false otherwise.
    */
    bool send_tlv_metric_reporting_policy(const std::string &dst_mac, std::shared_ptr<WSC::m1> m1,
                                          ieee1905_1::CmduMessageRx &cmdu_rx,
                                          ieee1905_1::CmduMessageTx &cmdu_tx);
};

} // namespace son

#endif
