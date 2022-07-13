// TEMP!!!! JUST TO CREATE SOME CODE!!! WILL BE REPLACED BY RAPHAEL's CODE

#include <cstddef>
#include <memory>
#include <ostream>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <tlvf/CmduMessageTx.h>
#include <tlvf/common/sMacAddr.h>
#include <tlvf/swap.h>
#include <tlvf/wfa_map/eTlvTypeMap.h>

class tlvTriggerChannelSwitchAnnounce : public BaseClass {

public:
    tlvTriggerChannelSwitchAnnounce(uint8_t *buff, size_t buff_len, bool parse = false);
    ~tlvTriggerChannelSwitchAnnounce();

    wfa_map::eTlvTypeMap *m_type = nullptr;
    uint16_t *m_length           = nullptr;
    uint16_t *m_subtype          = nullptr;

    uint8_t *m_csa_channel = nullptr; // Channel of destination Multi-AP radio
    uint8_t *m_op_class    = nullptr; // Operating Class of dest Multi-AP radio

private:
    bool init();
    size_t get_initial_size();
};
