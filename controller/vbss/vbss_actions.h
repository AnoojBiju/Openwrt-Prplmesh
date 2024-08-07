
#include "../src/beerocks/master/db/agent.h"
#include "../src/beerocks/master/db/db.h"
#include "../src/beerocks/master/son_actions.h"
#include <tlvf/common/sMacAddr.h>

#ifndef VBSS_ACTIONS_H
#define VBSS_ACTIONS_H

namespace vbss {

struct sClientVBSS {
    sMacAddr vbssid;
    sMacAddr client_mac;
    bool client_is_associated;
    sMacAddr current_connected_ruid;
};

struct sClientSecCtxInfo {
    const bool client_is_connected;
    const uint16_t key_length;
    uint8_t *ptk = nullptr;
    std::vector<uint8_t> tx_packet_num;
    const uint16_t group_key_length;
    uint8_t *gtk = nullptr;
    std::vector<uint8_t> group_tx_packet_num;

    sClientSecCtxInfo(bool is_connected, uint16_t ptk_len, const std::vector<uint8_t> &tx_pkt_num,
                      uint16_t gtk_len, const std::vector<uint8_t> &group_tx_pkt_num)
        : client_is_connected(is_connected), key_length(ptk_len), tx_packet_num(tx_pkt_num),
          group_key_length(gtk_len), group_tx_packet_num(group_tx_pkt_num)
    {
    }

    ~sClientSecCtxInfo()
    {
        if (ptk != nullptr) {
            delete[] ptk;
        }
        if (gtk != nullptr) {
            delete[] gtk;
        }
    }
};

class vbss_actions {

public:
    /**
     * @brief Send a request to create a virtual VBSS
     * 
     * @param client_vbss The VBSS to create for the client, filled with the VBSSID and the client's MAC address
     * @param dest_ruid The UID of the radio that this VBSS will be created on
     * @param ssid The SSID to set for the new VBSS
     * @param password The password to set for the new password
     * @param client_sec_ctx The client security context. If client is not associated, should equal nullptr
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool create_vbss(const sClientVBSS &client_vbss, const sMacAddr &dest_ruid,
                            const std::string &ssid, const std::string &password,
                            const sClientSecCtxInfo *client_sec_ctx, son::db &database);

    /**
     * @brief Sends a request to destroy the current virtual BSS
     * 
     * @param should_disassociate Wether the client should be disassociated or not
     * @param client_vbss The sClientVBSS object containing the vbssid, client_mac, and current_ruid
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool destroy_vbss(const sClientVBSS &client_vbss, const bool should_disassociate,
                             son::db &database);

    /**
     * @brief Requests the AP Radio VBSS Capabilities via a Virtual BSS Capabilities Request 
     * 
     * @param agent_mac The MAC address of the agent to send the request to
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool request_ap_radio_vbss_caps(const sMacAddr &agent_mac, son::db &database);

    /**
     * @brief Sends a move preparation request
     * 
     * @param agent_mac The MAC address of the agent to send the request to
     * @param client_vbss The sClientVBSS object containing the vbssid and client_mac
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool send_move_prep_request(const sMacAddr &agent_mac, const sClientVBSS &client_vbss,
                                       son::db &database);

    /**
     * @brief Sends a move cancel request
     * 
     * @param agent_mac The MAC address of the agent to send the request to
     * @param client_vbss The sClientVBSS object containing the vbssid and client_mac
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool send_move_cancel_request(const sMacAddr &agent_mac, const sClientVBSS &client_vbss,
                                         son::db &database);

    /**
     * @brief Sends a request for the client security context
     * 
     * @param agent_mac The MAC address of the agent to send the request to
     * @param client_vbss The sClientVBSS object containing the vbssid and client_mac
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool send_client_security_ctx_request(const sMacAddr &agent_mac,
                                                 const sClientVBSS &client_vbss, son::db &database);

    /**
     * @brief Sends a trigger channel switch announcement request
     * 
     * @param agent_mac The MAC address of the agent to send the request to. May not be needed since this may only be to the currently connected agent.
     * @param csa_channel Channel of destination Multi-AP radio
     * @param op_class Operating Class of destination Multi-AP Agent radio
     * @param client_vbss The sClientVBSS object containing the vbssid and client_mac
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool send_trigger_channel_switch_announcement(const sMacAddr &agent_mac,
                                                         const uint8_t csa_channel,
                                                         const uint8_t op_class,
                                                         const sClientVBSS &client_vbss,
                                                         son::db &database);

private:
    /**
     * @brief Sends a CmduMessage with the given message type and a single Client Info TLV
     * 
     * @param msg_type The type to set the CmduMessageTx as
     * @param dest_agent_mac The destination agent for this request
     * @param client_vbss The sClientVBSS object containing the vbssid and client_mac
     * @param database Database to fetch controller, agent, and radio contexts
     * @return Wether the message was sent successfully or not
     */
    static bool send_client_info_tlv_msg(const ieee1905_1::eMessageType msg_type,
                                         const sMacAddr dest_agent_mac,
                                         const sClientVBSS &client_vbss, son::db &database);
};

} // namespace vbss

#endif //VBSS_ACTIONS_H
