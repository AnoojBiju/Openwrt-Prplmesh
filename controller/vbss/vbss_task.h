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

class vbss_task : public son::task {

public:
    vbss_task(son::db &database, task_pool &tasks,
              const std::string &task_name_ = std::string("vbss_task"));
    virtual ~vbss_task() {}
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

    enum eEventType {
        MOVE,
        CREATE,
        DESTROY,
        STATION_CONNECTED,
        STATION_DISCONNECT,
        UNASSOCIATED_STATS
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
    beerocks::mac_map<vbss::sMoveEvent> active_moves;

    /**
     * @brief A map between VBSSIDs and active (in the process of executing) VBSS creation events 
     * 
     */
    beerocks::mac_map<vbss::sCreationEvent> active_creation_events;

    /**
     * @brief A map between VBSSIDs and active (in the process of executing) VBSS destruction events 
     * 
     */
    beerocks::mac_map<vbss::sDestructionEvent> active_destruction_events;

    /**
     * @brief Get the active move event which corresponds to the given VBSSID and is in the given state
     * 
     * @param vbssid The VBSSID to find the active move event for
     * @param state The state to verify
     * @return If an active move event exists for the given VBSSID in the given state, the move event's pointer. Otherwise nullptr
     */
    std::shared_ptr<vbss::sMoveEvent> get_matching_active_move(sMacAddr vbssid,
                                                               vbss::eMoveProcessState state);

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
    bool handle_move_client_event(const vbss::sMoveEvent &move_event);

    /**
     * @brief Begin process of creating a VBSS after recieving a create event, starting with fetching the Client Security Context
     * 
     * @param create_event The event struct received in handle_event containing the necessary info
     * @return True if the first request executed successfully, false otherwise.
     */
    bool handle_vbss_creation_event(const vbss::sCreationEvent &create_event);

    /**
     * @brief Send a VBSS Request with the VBSS Destruction TLV to the given agent
     * 
     * @param destroy_event The event struct received in handle_event containing the necessary info
     * @return True if the destroy VBSS request executed successfully, false otherwise.
     */
    bool handle_vbss_destruction_event(const vbss::sDestructionEvent &destroy_event);

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

    /**
     * @brief When a station connects lets analyze to see if it's a VSTA
     * 
     * @param stationConnected 
     * @return true If no errors occurred. a true does not mean it's a VSTA
     * @return false If an error occurred processing this event
     */
    bool handle_station_connected_event(const vbss::sStationConnectedEvent &stationConnected);

    /**
     * @brief When a station disconnect lets pass that info to the manager to get everything cleaned up
     * 
     * @param stationDisconnect 
     * @return true 
     * @return false 
     */
    bool handle_station_disconnect_event(const vbss::sStationDisconEvent &stationDisconnect);

    bool
    handle_unassociated_vsta_stats(const vbss::sUnassociatedStatsEvent &unassociated_stat_event);

    /**
     * @brief Amount to increase a TXPN by when moving a VBSS.
     */
    static constexpr size_t TX_PN_INCREASE_AMOUNT{1000};

    /**
     * @brief Increments the value of a transmission packet number (TX PN) by a given amount.
     * @param[in,out] tx_pn Reference to a vector of bytes representing the current TX PN.
     * @param[in] tx_pn_len The length of the TX PN.
     * @param[in] amount The amount by which to increment the current TX PN.
     * @return True if the function successfully incremented the TX PN and updated the provided vector, false otherwise.
    */
    bool increment_tx_pn(std::vector<uint8_t> &tx_pn, size_t tx_pn_len, size_t amount);
};

#endif // VBSS_TASK_H
