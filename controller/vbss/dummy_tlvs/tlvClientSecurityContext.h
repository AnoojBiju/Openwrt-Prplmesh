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

class tlvClientSecurityContext : public BaseClass {

public:
    tlvClientSecurityContext(uint8_t *buff, size_t buff_len, bool parse = false);
    ~tlvClientSecurityContext();

    wfa_map::eTlvTypeMap *m_type = nullptr;
    uint16_t *m_length           = nullptr;
    uint16_t *m_subtype          = nullptr;

    typedef struct sVbssSettings {

        uint8_t client_connected : 1;
        uint8_t reserved : 7;

        void struct_swap() {}
        void struct_init() {}
    } __attribute__((packed)) sVbssSettings;

    uint16_t &key_length();
    std::string ptk_str();
    uint64_t &tx_packet_num();
    uint16_t &group_key_length();
    std::string gtk_str();
    uint64_t &group_tx_packet_num();
    sVbssSettings &vbss_settings();

private:
    bool init();
    size_t get_initial_size();
};
