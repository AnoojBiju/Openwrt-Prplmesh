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
              std::shared_ptr<beerocks::TimerManager> timer_manager,
              const std::string &task_name_ = std::string("vbss_task"));
    virtual ~vbss_task();
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

    enum eEventType { MOVE, CREATE, DESTROY };

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

        sMoveEvent(const sMacAddr &vbssid, const vbss::sClientVBSS &client_vbss_,
                   sMacAddr dest_ruid_, const std::string &ssid_, const std::string &password_)
            : client_vbss(client_vbss_), dest_ruid(dest_ruid_), ssid(ssid_), password(password_)
        {
        }

        sMoveEvent(const sMacAddr &vbssid, const vbss::sClientVBSS &client_vbss_,
                   sMacAddr dest_ruid_, const std::string &ssid_, const std::string &password_,
                   const eMoveProcessState &state_)
            : client_vbss(client_vbss_), dest_ruid(dest_ruid_), ssid(ssid_), password(password_),
              state(state_)
        {
        }

        sMoveEvent(){};
    };

    struct sCreationEvent {
        vbss::sClientVBSS client_vbss;
        sMacAddr dest_ruid;
        std::string ssid;
        std::string password;
        std::shared_ptr<vbss::sClientSecCtxInfo> sec_ctx_info;

        sCreationEvent(const sMacAddr &vbssid, const vbss::sClientVBSS &client_vbss_,
                       sMacAddr dest_ruid_, const std::string &ssid_, const std::string &password_)
            : client_vbss(client_vbss_), dest_ruid(dest_ruid_), ssid(ssid_), password(password_)
        {
        }

        sCreationEvent() {}
    };

    struct sDestructionEvent {
        vbss::sClientVBSS client_vbss;
        bool should_disassociate;

        sDestructionEvent(const sMacAddr &vbssid, const vbss::sClientVBSS &client_vbss_,
                          bool should_disassociate_)
            : client_vbss(client_vbss_), should_disassociate(should_disassociate_)
        {
        }

        sDestructionEvent() {}
    };

protected:
    virtual void work() override;
    virtual void handle_event(int event_enum_value, void *event_obj) override;

private:
    son::db &m_database;
    son::task_pool &m_tasks;
    std::shared_ptr<beerocks::TimerManager> m_timer_manager;

    std::unordered_map<sMacAddr, int> m_active_event_to_timer_fd;

    /**
     * @brief A map between VBSSIDs and active (in the process of executing) move events
     */
    beerocks::mac_map<sMoveEvent> active_moves;

    /**
     * @brief A map between VBSSIDs and active (in the process of executing) VBSS creation events 
     * 
     */
    beerocks::mac_map<sCreationEvent> active_creation_events;

    /**
     * @brief A map between VBSSIDs and active (in the process of executing) VBSS destruction events 
     * 
     */
    beerocks::mac_map<sDestructionEvent> active_destruction_events;

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
     * @param move_event The event struct received in handle_event containing the necessary info
     * @return True if the first request executed successfully, false otherwise.
     */
    bool handle_move_client_event(const sMoveEvent &move_event);

    /**
     * @brief Begin process of creating a VBSS after recieving a create event, starting with fetching the Client Security Context
     * 
     * @param create_event The event struct received in handle_event containing the necessary info
     * @return True if the first request executed successfully, false otherwise.
     */
    bool handle_vbss_creation_event(const sCreationEvent &create_event);

    /**
     * @brief Send a VBSS Request with the VBSS Destruction TLV to the given agent
     * 
     * @param destroy_event The event struct received in handle_event containing the necessary info
     * @return True if the destroy VBSS request executed successfully, false otherwise.
     */
    bool handle_vbss_destruction_event(const sDestructionEvent &destroy_event);

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
     * @return Whether the response was handled successfully or not
     */
    bool handle_move_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

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

    /**
     * @brief Amount to increase a TXPN by when moving a VBSS.
     */
    static constexpr size_t TX_PN_INCREASE_AMOUNT{100000};

    /**
     * @brief Increments the value of a transmission packet number (TX PN) by a given amount.
     * @param[in,out] tx_pn Reference to a vector of bytes representing the current TX PN.
     * @param[in] tx_pn_len The length of the TX PN.
     * @param[in] amount The amount by which to increment the current TX PN.
     * @return True if the function successfully incremented the TX PN and updated the provided vector, false otherwise.
    */
    bool increment_tx_pn(std::vector<uint8_t> &tx_pn, size_t tx_pn_len, size_t amount);

    /**
     * @brief Handles a timeout situation where a Multi-AP Agent has not replied to a VBSS message
     * within some timeout threshold.
     * 
     * @param dest_ruid The destination radio UID of interest for a given VBSS message
     * @param client_vbss The client VBSS of interest.
     */
    void handle_timeout(const vbss::sClientVBSS &client_vbss);

    /**
     * @brief Begins a timer for a timed VBSS event.
     * 
     * @param vbssid The VBSSID of the (move|creation) event.
     * @param timer_period_ms The period the timer will elapse on. Also the initial delay.
     */
    void begin_timer_for_timed_event(const vbss::sClientVBSS &vbssid,
                                     std::chrono::milliseconds timer_period_ms);

    /**
     * @brief Removes a timer for a timed VBSS event.
     * 
     * @param vbssid The VBSSID of the event to remove the timer for.
     */
    void remove_timer_for_timed_event(const sMacAddr &vbssid);

    /**
     * @brief Handles a Move Cancel Response message
     * 
     * @param src_mac The Agent the message came from.
     * @param cmdu_rx The CMDU to process. 
     * @return true on success, otherwise false.
     */
    bool handle_move_cancel_response(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);
};

#endif // VBSS_TASK_H
