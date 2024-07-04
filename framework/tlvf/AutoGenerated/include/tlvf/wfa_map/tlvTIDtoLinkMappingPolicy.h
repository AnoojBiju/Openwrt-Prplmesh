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
            uint8_t reserved : 7;
            uint8_t is_bsta_config : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t is_bsta_config : 1;
            uint8_t reserved : 7;
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
            uint8_t reserved : 7;
            uint8_t tid_to_link_mapping_negotiation : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t tid_to_link_mapping_negotiation : 1;
            uint8_t reserved : 7;
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
        sMacAddr& mld_mac_Addr();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint16_t& num_mapping();
        std::tuple<bool, cNumTIDtoLinks&> num_tid_to_link_mappings(size_t idx);
        std::shared_ptr<cNumTIDtoLinks> create_num_tid_to_link_mappings();
        bool add_num_tid_to_link_mappings(std::shared_ptr<cNumTIDtoLinks> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sFlags2* m_flags = nullptr;
        sMacAddr* m_mld_mac_Addr = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint16_t* m_num_mapping = nullptr;
        cNumTIDtoLinks* m_num_tid_to_link_mappings = nullptr;
        size_t m_num_tid_to_link_mappings_idx__ = 0;
        std::vector<std::shared_ptr<cNumTIDtoLinks>> m_num_tid_to_link_mappings_vector;
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
            uint8_t reserved : 7;
            uint8_t addremove : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t addremove : 1;
            uint8_t reserved : 7;
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
            uint8_t reserved : 2;
            uint8_t link_mapping_size : 1;
            uint8_t expected_duration_present : 1;
            uint8_t mapping_switch_time_present : 1;
            uint8_t default_link_mapping : 1;
            uint8_t direction : 2;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t direction : 2;
            uint8_t default_link_mapping : 1;
            uint8_t mapping_switch_time_present : 1;
            uint8_t expected_duration_present : 1;
            uint8_t link_mapping_size : 1;
            uint8_t reserved : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags4;
        
        sFlags4& flags();
        sMacAddr& sta_mld_mac_addr();
        uint8_t& link_mapping_presence_indicator();
        uint8_t* expected_duration(size_t idx = 0);
        bool set_expected_duration(const void* buffer, size_t size);
        uint16_t* tid_to_link_mappings(size_t idx = 0);
        bool alloc_tid_to_link_mappings(size_t count = 1);
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sFlags4* m_flags = nullptr;
        sMacAddr* m_sta_mld_mac_addr = nullptr;
        uint8_t* m_link_mapping_presence_indicator = nullptr;
        uint8_t* m_expected_duration = nullptr;
        size_t m_expected_duration_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint16_t* m_tid_to_link_mappings = nullptr;
        size_t m_tid_to_link_mappings_idx__ = 0;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTIDTOLINKMAPPINGPOLICY_H_
