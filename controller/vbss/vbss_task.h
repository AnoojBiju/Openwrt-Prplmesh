#include "../db/db.h"
#include "../src/beerocks/master/tasks/task.h"

namespace vbss {
struct sAPRadioVBSSCapabilities {
    uint8_t max_vbss;
    bool vbsses_subtract;
    bool apply_vbssid_restrict;
    bool apply_vbssid_match_mask_restrict;
    bool apply_fixed_bits_restrict;
    sMacAddr fixed_bits_mask;
    sMacAddr fixed_bits_value;
};

} // end namespace vbss

class vbss_task : public son::task {

public:
    vbss_task(son::db &database_);
    virtual ~vbss_task() {}
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

private:
    son::db &database;

    /**
     * @brief Generic method to handle the three responses that send AP Radio VBSS Capabilities TLVs in the response
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Wether the response was handled successfully or not
     */
    bool handle_ap_radio_vbss_caps_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles either a Move Preperation or a Move Cancel response since they both return a single Client Info TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @param did_cancel "Move Preperation" response if false, "Move Cancel" if true
     * @return Wether the response was handled successfully or not
     */
    bool handle_move_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx,
                                  bool did_cancel);

    /**
     * @brief Handles the "Trigger Channel Switch Announcement Response" which includes a Client Info TLV and a Trigger Channel Switch Announcement TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Wether the response was handled successfully or not
     */
    bool handle_trigger_chan_switch_announce_resp(const sMacAddr &src_mac,
                                                  ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles the VBSS Response which contains a single Virtual BSS Event TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Wether the response was handled successfully or not
     */
    bool handle_vbss_event_response(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles the 1905.1 Topology Response Message which (if the source agent supports VBSS) will include a VBSS Configuration Report TLV 
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Wether the response was handled successfully or not
     */
    bool handle_top_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    /**
     * @brief Handles a Client Security Context Response which returns a Client Info TLV and a Client Security Context TLV
     * 
     * @param src_mac The MAC address of the agent who sent the response
     * @param cmdu_rx The response message
     * @return Wether the response was handled successfully or not
     */
    bool handle_client_security_ctx_resp(const sMacAddr &src_mac,
                                         ieee1905_1::CmduMessageRx &cmdu_rx);
};
