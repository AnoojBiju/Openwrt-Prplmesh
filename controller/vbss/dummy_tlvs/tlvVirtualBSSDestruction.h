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

class tlvVirtualBSSDestruction : public BaseClass {

public:
    tlvVirtualBSSDestruction(uint8_t *buff, size_t buff_len, bool parse = false);
    ~tlvVirtualBSSDestruction();

    wfa_map::eTlvTypeMap *m_type = nullptr;
    uint16_t *m_length           = nullptr;
    uint16_t *m_subtype          = nullptr;

    sMacAddr *m_ruid               = nullptr; // Radio Unique ID of a radio of the Multi-AP Agent
    sMacAddr *m_bssid              = nullptr;
    uint8_t *m_disassociate_client = nullptr; // Should disassociate

private:
    bool init();
    size_t get_initial_size();
};
