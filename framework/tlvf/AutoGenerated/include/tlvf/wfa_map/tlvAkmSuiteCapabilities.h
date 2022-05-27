///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_WFA_MAP_TLVAKMSUITECAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVAKMSUITECAPABILITIES_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tuple>
#include <ostream>
#include "tlvf/ieee_1905_1/sVendorOUI.h"
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class tlvAkmSuiteCapabilities : public BaseClass
{
    public:
        tlvAkmSuiteCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAkmSuiteCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAkmSuiteCapabilities();

        typedef struct sBssAkmSuiteSelector {
            //Any OUI value specified in Table 9-133 of "IEEE Std. 802.11-2016" or Table 55 of "Wi-Fi Easy
            //Connect Specification".
            sVendorOUI oui;
            //Any suite type value specified in Table 9-133 of "IEEE Std. 802.11-2016" or Table 55 of
            //"Wi-Fi Easy Connect Specification".
            uint8_t akm_suite_type;
            void struct_swap(){
                oui.struct_swap();
            }
            void struct_init(){
            }
        } __attribute__((packed)) sBssAkmSuiteSelector;
        
        enum eAkmSuiteOUI: uint32_t {
            IEEE80211 = 0xfac,
            WEC = 0x506f9a,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eAkmSuiteOUI_str(eAkmSuiteOUI enum_value) {
            switch (enum_value) {
            case IEEE80211: return "IEEE80211";
            case WEC:       return "WEC";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eAkmSuiteOUI value) { return out << eAkmSuiteOUI_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& number_of_bh_bss_akm_suite_selectors();
        std::tuple<bool, sBssAkmSuiteSelector&> backhaul_bss_akm_suite_selectors(size_t idx);
        bool alloc_backhaul_bss_akm_suite_selectors(size_t count = 1);
        uint8_t& number_of_fh_bss_akm_suite_selectors();
        std::tuple<bool, sBssAkmSuiteSelector&> fronthaul_bss_akm_suite_selectors(size_t idx);
        bool alloc_fronthaul_bss_akm_suite_selectors(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_number_of_bh_bss_akm_suite_selectors = nullptr;
        sBssAkmSuiteSelector* m_backhaul_bss_akm_suite_selectors = nullptr;
        size_t m_backhaul_bss_akm_suite_selectors_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_number_of_fh_bss_akm_suite_selectors = nullptr;
        sBssAkmSuiteSelector* m_fronthaul_bss_akm_suite_selectors = nullptr;
        size_t m_fronthaul_bss_akm_suite_selectors_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAKMSUITECAPABILITIES_H_
