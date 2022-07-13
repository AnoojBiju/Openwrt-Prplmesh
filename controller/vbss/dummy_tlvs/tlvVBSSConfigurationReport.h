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

class tlvVBSSConfigurationReport : public BaseClass {

public:
    tlvVBSSConfigurationReport(uint8_t *buff, size_t buff_len, bool parse = false);
    ~tlvVBSSConfigurationReport();

    wfa_map::eTlvTypeMap *m_type = nullptr;
    uint16_t *m_length           = nullptr;
    uint16_t *m_subtype          = nullptr;

    uint8_t &num_radios();
    sMacAddr &ruid();
    uint8_t &num_bss();
    sMacAddr &bssid();
    uint8_t &ssid_len();
    std::string ssid_str();

private:
    bool init();
    size_t get_initial_size();
};
