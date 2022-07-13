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

    bool handle_ap_radio_vbss_caps_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    bool handle_move_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx,
                                  bool did_cancel);

    bool handle_trigger_chan_switch_announce_resp(const sMacAddr &src_mac,
                                                  ieee1905_1::CmduMessageRx &cmdu_rx);

    bool handle_vbss_event_response(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);

    bool handle_top_response_msg(const sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx);
};
