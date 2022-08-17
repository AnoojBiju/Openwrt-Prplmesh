/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef VBSS_TASK_H
#define VBSS_TASK_H

#include "../src/beerocks/master/db/db.h"
#include "../src/beerocks/master/tasks/task.h"
#include "vbss_actions.h"

namespace vbss {
struct sAPRadioVBSSCapabilities {
    uint8_t max_vbss;
    bool vbsses_subtract;
    bool apply_vbssid_restrict;
    bool apply_vbssid_match_mask_restrict;
    bool apply_fixed_bits_restrict;
    sMacAddr fixed_bits_mask;
    sMacAddr fixed_bits_value;

    sAPRadioVBSSCapabilities(sMacAddr ruid, sAPRadioVBSSCapabilities &caps)
        : sAPRadioVBSSCapabilities(caps)
    {
    }
    sAPRadioVBSSCapabilities() {}
};

} // end namespace vbss

class vbss_task : public son::task {

public:
    vbss_task(son::db &database, task_pool &tasks,
              const std::string &task_name_ = std::string("vbss_task"));
    virtual ~vbss_task() {}
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

    enum eEventType { MOVE };

    // TODO: Might be able to be moved to private. Revisit later
    // Keeping public for now in case people want to check later
    enum eMoveProcessState {
        INIT,
        CLIENT_SEC_CTX,
        VBSS_MOVE_PREP,
        VBSS_CREATION,
        VBSS_MOVE_CANCEL,
        TRIGGER_CHANNEL_SWITCH,
        VBSS_DESTRUCTION
    };

    struct sMoveEvent {
        vbss::sClientVBSS client_vbss;
        sMacAddr dest_ruid;
        std::string ssid;
        std::string password;
        eMoveProcessState state = INIT;
        std::shared_ptr<vbss::sClientSecCtxInfo> sec_ctx_info;

        sMoveEvent(sMacAddr vbssid, const vbss::sClientVBSS &client_vbss_, sMacAddr dest_ruid_,
                   const std::string &ssid_, const std::string &password_)
            : client_vbss(client_vbss_), dest_ruid(dest_ruid_), ssid(ssid_), password(password_)
        {
        }

        sMoveEvent(){};
    };

protected:
    virtual void work() override;
    virtual void handle_event(int event_enum_value, void *event_obj) override;

private:
    son::db &m_database;
    son::task_pool &m_tasks;

    /**
     * @brief A map between VBSSIDs and active (in the process of executing) move events
     */
    beerocks::mac_map<sMoveEvent> active_moves;

    /**
     * @brief Get the active move event which corresponds to the given VBSSID and is in the given state
     * 
     * @param vbssid The VBSSID to find the active move event for
     * @param state The state to verify
     * @return If an active move event exists for the given VBSSID in the given state, the move event's pointer. Otherwise nullptr
     */
    std::shared_ptr<sMoveEvent> get_matching_active_move(sMacAddr vbssid, eMoveProcessState state);

    /**
     * @brief Determines whether a channel switch should occur during the move between two radios
     * 
     * @param src_ruid The currently connected radio
     * @param dest_ruid The destination radio for the move
     * @param out_chan If channels and op classes do not match, the new channel to be switched to
     * @param out_opclass If channels and op classes do not match, the new op class to be switched to
     * @return If the channels and op classes do not match, true, otherwise false
     */
    bool should_trigger_channel_switch(sMacAddr src_ruid, sMacAddr dest_ruid, uint8_t &out_chan,
                                       uint8_t &out_opclass);

    /**
     * @brief Begin process of moving client from one agent to another after recieving a move event
     * 
     * @param move_event The event struct recieved in handle_event containing the necsessary info
     * @return True if the first request executed successfully, false otherwise.
     */
    bool handle_move_client_event(const sMoveEvent &move_event);

    /**
     * @brief Generic method to handle the three responses that send AP Radio VBSS Capabilities TLVs in the response
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Whether the response was handled successfully or not
     */
    bool handle_ap_radio_vbss_caps_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles either a Move Preperation or a Move Cancel response since they both return a single Client Info TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @param did_cancel "Move Preperation" response if false, "Move Cancel" if true
     * @return Whether the response was handled successfully or not
     */
    bool handle_move_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx,
                                  bool did_cancel);

    /**
     * @brief Handles the "Trigger Channel Switch Announcement Response" which includes a Client Info TLV and a Trigger Channel Switch Announcement TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Whether the response was handled successfully or not
     */
    bool handle_trigger_chan_switch_announce_resp(const sMacAddr &src_mac,
                                                  ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles the VBSS Response which contains a single Virtual BSS Event TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Whether the response was handled successfully or not
     */
    bool handle_vbss_event_response(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles the 1905.1 Topology Response Message which (if the source agent supports VBSS) will include a VBSS Configuration Report TLV 
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Whether the response was handled successfully or not
     */
    bool handle_top_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles a Client Security Context Response which returns a Client Info TLV and a Client Security Context TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Whether the response was handled successfully or not
     */
    bool handle_client_security_ctx_resp(const sMacAddr &src_mac,
                                         ieee1905_1::CmduMessageRx &cmdu_rx);
};

#endif // VBSS_TASK_H
