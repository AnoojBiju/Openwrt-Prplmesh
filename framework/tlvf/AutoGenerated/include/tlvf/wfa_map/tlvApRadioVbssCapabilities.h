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

#ifndef _TLVF_WFA_MAP_TLVAPRADIOVBSSCAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVAPRADIOVBSSCAPABILITIES_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <asm/byteorder.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/wfa_map/eVirtualBssSubtype.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class ApRadioVbssCapabilities : public BaseClass
{
    public:
        ApRadioVbssCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit ApRadioVbssCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~ApRadioVbssCapabilities();

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
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sVbssSettings;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        const eVirtualBssSubtype& subtype();
        sMacAddr& radio_uid();
        uint8_t& max_vbss();
        ApRadioVbssCapabilities::sVbssSettings& vbss_settings();
        sMacAddr& fixed_bits_mask();
        sMacAddr& fixed_bits_value();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eVirtualBssSubtype* m_subtype = nullptr;
        sMacAddr* m_radio_uid = nullptr;
        uint8_t* m_max_vbss = nullptr;
        ApRadioVbssCapabilities::sVbssSettings* m_vbss_settings = nullptr;
        sMacAddr* m_fixed_bits_mask = nullptr;
        sMacAddr* m_fixed_bits_value = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAPRADIOVBSSCAPABILITIES_H_
