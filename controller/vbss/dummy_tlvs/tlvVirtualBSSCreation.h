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

class tlvVirtualBSSCreation : public BaseClass {

public:
    tlvVirtualBSSCreation(uint8_t *buff, size_t buff_len, bool parse = false);
    ~tlvVirtualBSSCreation();

    wfa_map::eTlvTypeMap *m_type = nullptr;
    uint16_t *m_length           = nullptr;
    uint16_t *m_subtype          = nullptr;
    sMacAddr *m_ruid             = nullptr; // Radio Unique ID of a radio of the Multi-AP Agent
    sMacAddr *m_bssid            = nullptr;
    sMacAddr *m_client_mac       = nullptr;
    _Bool *m_client_is_assoc  = nullptr; // If m_client_is_assoc == true, below fields are populated
    uint64_t *m_tx_packet_num = nullptr;
    uint64_t *m_group_tx_packet_num = nullptr;

    bool set_ssid(const std::string &str){};          // Just a dummy
    bool set_password(const std::string &str){};      // Just a dummy
    bool set_dpp_connector(const std::string &str){}; // Just a dummy
    bool set_ptk(const std::string &str){};           // Just a dummy
    bool set_gtk(const std::string &str){};           // Just a dummy

private:
    bool init();
    size_t get_initial_size();

    uint16_t *m_ssid_len      = nullptr;
    char *m_ssid              = nullptr;
    uint16_t *m_pass_len      = nullptr;
    char *m_password          = nullptr;
    uint16_t *m_dpp_conn_len  = nullptr; // 0 indicates that DPP Connector is not present
    char *m_dpp_conn          = nullptr;
    uint16_t *m_key_len       = nullptr;
    char *m_ptk               = nullptr;
    uint16_t *m_group_key_len = nullptr;
    char *m_gtk               = nullptr;
};
