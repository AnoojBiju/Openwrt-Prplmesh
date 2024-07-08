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

#ifndef _TLVF_WFA_MAP_TLVTIDTOLINKMAPPINGPOLICY_H_
#define _TLVF_WFA_MAP_TLVTIDTOLINKMAPPINGPOLICY_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"
#include <tuple>
#include <vector>
#include <asm/byteorder.h>

namespace wfa_map {

class cNumTIDtoLinks;

class tlvTIDtoLinkMappingPolicy : public BaseClass
{
    public:
        tlvTIDtoLinkMappingPolicy(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTIDtoLinkMappingPolicy(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTIDtoLinkMappingPolicy();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_2 : 7;
            uint8_t is_bSTA_Config : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t is_bSTA_Config : 1;
            uint8_t reserved_2 : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags1;
        
        typedef struct sFlags2 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_3 : 7;
            uint8_t TIDToLink_Mapping_Negotiation : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t TIDToLink_Mapping_Negotiation : 1;
            uint8_t reserved_3 : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags2;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sFlags2& flags();
        sMacAddr& MLD_MAC_Addr();
        uint8_t* reserved_1(size_t idx = 0);
        bool set_reserved_1(const void* buffer, size_t size);
        uint16_t& num_Mapping();
        std::tuple<bool, cNumTIDtoLinks&> numTIDtoLinkMappings(size_t idx);
        std::shared_ptr<cNumTIDtoLinks> create_numTIDtoLinkMappings();
        bool add_numTIDtoLinkMappings(std::shared_ptr<cNumTIDtoLinks> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sFlags2* m_flags = nullptr;
        sMacAddr* m_MLD_MAC_Addr = nullptr;
        uint8_t* m_reserved_1 = nullptr;
        size_t m_reserved_1_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint16_t* m_num_Mapping = nullptr;
        cNumTIDtoLinks* m_numTIDtoLinkMappings = nullptr;
        size_t m_numTIDtoLinkMappings_idx__ = 0;
        std::vector<std::shared_ptr<cNumTIDtoLinks>> m_numTIDtoLinkMappings_vector;
        bool m_lock_allocation__ = false;
};

class cNumTIDtoLinks : public BaseClass
{
    public:
        cNumTIDtoLinks(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cNumTIDtoLinks(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cNumTIDtoLinks();

        typedef struct sFlags3 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_5 : 7;
            uint8_t addRemove : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t addRemove : 1;
            uint8_t reserved_5 : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags3;
        
        typedef struct sFlags4 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_6 : 2;
            uint8_t link_Mapping_Size : 1;
            uint8_t expected_Duration_Present : 1;
            uint8_t mapping_Switch_Time_Present : 1;
            uint8_t default_Link_Mapping : 1;
            uint8_t direction : 2;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t direction : 2;
            uint8_t default_Link_Mapping : 1;
            uint8_t mapping_Switch_Time_Present : 1;
            uint8_t expected_Duration_Present : 1;
            uint8_t link_Mapping_Size : 1;
            uint8_t reserved_6 : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags4;
        
        sFlags4& flags();
        sMacAddr& STA_MLD_MAC_Addr();
        uint8_t& link_Mapping_Presence_Indicator();
        uint8_t* expected_Duration(size_t idx = 0);
        bool set_expected_Duration(const void* buffer, size_t size);
        uint16_t* TIDtoLinkMappings(size_t idx = 0);
        bool alloc_TIDtoLinkMappings(size_t count = 1);
        uint8_t* reserved_4(size_t idx = 0);
        bool set_reserved_4(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sFlags4* m_flags = nullptr;
        sMacAddr* m_STA_MLD_MAC_Addr = nullptr;
        uint8_t* m_link_Mapping_Presence_Indicator = nullptr;
        uint8_t* m_expected_Duration = nullptr;
        size_t m_expected_Duration_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint16_t* m_TIDtoLinkMappings = nullptr;
        size_t m_TIDtoLinkMappings_idx__ = 0;
        uint8_t* m_reserved_4 = nullptr;
        size_t m_reserved_4_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTIDTOLINKMAPPINGPOLICY_H_
