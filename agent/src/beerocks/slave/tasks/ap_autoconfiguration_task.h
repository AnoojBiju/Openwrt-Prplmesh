/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _AP_AUTOCONFIGURATION_TASK_H_
#define _AP_AUTOCONFIGURATION_TASK_H_

#include "task.h"

#include <tlvf/CmduMessageTx.h>

namespace beerocks {

// Forward declaration for BackhaulManager context saving
class BackhaulManager;

class ApAutoConfigurationTask : public Task {
public:
    ApAutoConfigurationTask(BackhaulManager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~ApAutoConfigurationTask() {}

    void work() override;

    enum eEvent : uint8_t {
        INIT_TASK,
        START_AP_AUTOCONFIGURATION,
    };

    void handle_event(uint8_t event_enum_value, const void *event_obj) override;

    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

private:
    /* Class members */

    /**
     * @brief AP-Autoconfiguration Task states.
     * 
     * The AP-Autoconfiguration task states represent the AP-Autoconfiguration phases described on
     * IEEE 1905.1-2013 standard, section 10.1.
     * The 'CONTROLLER_DISCOVERY' state refers to the 'Registrar Discovery' phase.
     * The 'AP_CONFIGURATION' state refers to the 'Parameter configuration' phase.
     */
    enum class eState : uint8_t {
        UNCONFIGURED,
        CONTROLLER_DISCOVERY,
        WAIT_FOR_CONTROLLER_DISCOVERY_COMPLETE,
        SEND_AP_AUTOCONFIGURATION_WSC_M1,
        WAIT_AP_AUTOCONFIGURATION_WSC_M2,
        SEND_MONITOR_SON_CONFIG,
        CONFIGIRED
    };

    struct sConfigurationParams {
        eState state = eState::UNCONFIGURED;
        std::chrono::steady_clock::time_point timeout;
        std::unique_ptr<mapf::encryption::diffie_hellman> dh = nullptr;
        //copy of M1 message used for authentication
        uint8_t *m1_auth_buf   = nullptr;
        size_t m1_auth_buf_len = 0;
    };

    /**
     * @brief State of AP-Autoconfiguration task on mapped by front radio interface name.
     * 
     * Key:     Front radio interface name.
     * Value:   AP-Autoconfiguration task state struct of the mapped Front radio interface name.
     * 
     * According to IEEE 1905.1-2013, the AP-Autoconfiguration routine shall occur separately
     * for every 1905.1 device supported band. Multi-AP standard extend the definition and add that
     * the 'AP_CONFIGURATION' phase shall occur for each radio of the Multi-AP device (instead of
     * a band).
     */
    std::unordered_map<std::string, sConfigurationParams> m_radios_conf_params;

    /**
     * @brief Convert enum of task state to string.
     * 
     * @param status Enum of task state. 
     * @return state as string.
     */
    static const std::string fsm_state_to_string(eState status);

    /**
     * @brief A map that contains the discovery status on each of the Agent supported bands.
     * 
     * Since the discovery states are attached to each bands instead of each radio, need to hold,
     * helper container to manage it.
     * 
     * Key: Band type.
     * Value: Struct that contain flags on the discovery phase of mapped band.
     */
    struct sDiscoveryStatus {
        bool completed = false;
        bool msg_sent  = false;
    };
    // Decalaring unordered_map with key which is an enum, does not compiles on older gcc version.
    // It was considered a defect in the standard, and was fixed in C++14, and also fixed in the
    // version of libstdc++ shipping with gcc as of 6.1.
    // To make unordered_map work with an enum as key, std::hash<int> function was added as third
    // template argument.
    std::unordered_map<eFreqType, sDiscoveryStatus, std::hash<int>> m_discovery_status;

    bool m_task_is_active = false;

    slave_thread &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    /* Message handlers: */

    /**
    * @brief Handles 1905 AP Autoconfiguration message.
    * 
    * @param[in] cmdu_rx Received CMDU.
    * @param[in] src_mac MAC address of the message sender.
    */
    void handle_ap_autoconfiguration_response(ieee1905_1::CmduMessageRx &cmdu_rx,
                                              const sMacAddr &src_mac);

    /* Helper functions */
    bool send_ap_autoconfiguration_search_message(const std::string &radio_iface);
};

} // namespace beerocks

#endif // _AP_AUTOCONFIGURATION_TASK_H_
