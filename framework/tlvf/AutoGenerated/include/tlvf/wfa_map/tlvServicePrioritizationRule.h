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

#ifndef _TLVF_WFA_MAP_TLVSERVICEPRIORITIZATIONRULE_H_
#define _TLVF_WFA_MAP_TLVSERVICEPRIORITIZATIONRULE_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <asm/byteorder.h>

namespace wfa_map {


class tlvServicePrioritizationRule : public BaseClass
{
    public:
        tlvServicePrioritizationRule(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvServicePrioritizationRule(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvServicePrioritizationRule();

        typedef struct sRuleBitsField1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t add_remove : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t add_remove : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sRuleBitsField1;
        
        typedef struct sRuleBitsField2 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t always_match : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t always_match : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sRuleBitsField2;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        uint32_t& rule_id();
        sRuleBitsField1& rule_bits_field1();
        //Rule Precedence - higher number means higher priority. Possible values: 0x00 - 0xFE
        uint8_t& precedence();
        //Rule Output. The value of, or method used to select, the 802.1Q C-TAG PCP output value.
        //Possible values: 0x00 - 0x09
        uint8_t& output();
        sRuleBitsField2& rule_bits_field2();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint32_t* m_rule_id = nullptr;
        sRuleBitsField1* m_rule_bits_field1 = nullptr;
        uint8_t* m_precedence = nullptr;
        uint8_t* m_output = nullptr;
        sRuleBitsField2* m_rule_bits_field2 = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVSERVICEPRIORITIZATIONRULE_H_
