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

class tlvAPRadioVBSSCapabilities : public BaseClass {
public:
    tlvAPRadioVBSSCapabilities(uint8_t *buff, size_t buff_len, bool parse = false);
    explicit tlvAPRadioVBSSCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
    ~tlvAPRadioVBSSCapabilities();

    typedef struct sVbssSettings {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        uint8_t reserved : 4;
        uint8_t fixed_bit_restrictions : 1;
        uint8_t vbssid_match_and_mask_restrictions : 1;
        uint8_t vbssid_restrictions : 1;
        uint8_t vbsss_subtract : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        uint8_t vbsss_subtract : 1;
        uint8_t vbssid_restrictions : 1;
        uint8_t vbssid_match_and_mask_restrictions : 1;
        uint8_t fixed_bit_restrictions : 1;
        uint8_t reserved : 4;
#else
#error "Bitfield macros are not defined"
#endif
        void struct_swap() {}
        void struct_init() {}
    } __attribute__((packed)) sVbssSettings;

    const wfa_map::eTlvTypeMap &type();
    const uint16_t &length();
    const uint16_t &subtype();
    sMacAddr &radio_uid();
    uint8_t &max_vbss();
    tlvAPRadioVBSSCapabilities::sVbssSettings &vbss_settings();
    sMacAddr &fixed_bits_mask();
    sMacAddr &fixed_bits_value();
    void class_swap() override;
    bool finalize() override;
    static size_t get_initial_size();

private:
    bool init();
    wfa_map::eTlvTypeMap *m_type                               = nullptr;
    uint16_t *m_length                                         = nullptr;
    uint16_t *m_subtype                                        = nullptr;
    sMacAddr *m_radio_uid                                      = nullptr;
    uint8_t *m_max_vbss                                        = nullptr;
    tlvAPRadioVBSSCapabilities::sVbssSettings *m_vbss_settings = nullptr;
    sMacAddr *m_fixed_bits_mask                                = nullptr;
    sMacAddr *m_fixed_bits_value                               = nullptr;
};
