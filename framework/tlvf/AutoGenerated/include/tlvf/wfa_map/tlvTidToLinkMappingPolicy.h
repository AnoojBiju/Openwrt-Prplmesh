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

class cMapping;
class cTidToLinkControlField;

class tlvTidToLinkMappingPolicy : public BaseClass
{
    public:
        tlvTidToLinkMappingPolicy(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTidToLinkMappingPolicy(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTidToLinkMappingPolicy();

        typedef struct sIsBStaConfig {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t is_bsta_mld : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t is_bsta_mld : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sIsBStaConfig;
        
        typedef struct sTidToLinkMappingNegotiation {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t is_enabled : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t is_enabled : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sTidToLinkMappingNegotiation;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sIsBStaConfig& is_bsta_config();
        sMacAddr& mld_mac_addr();
        sTidToLinkMappingNegotiation& tid_to_link_mapping_negotiation();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint16_t& num_mapping();
        std::tuple<bool, cMapping&> mapping(size_t idx);
        std::shared_ptr<cMapping> create_mapping();
        bool add_mapping(std::shared_ptr<cMapping> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sIsBStaConfig* m_is_bsta_config = nullptr;
        sMacAddr* m_mld_mac_addr = nullptr;
        sTidToLinkMappingNegotiation* m_tid_to_link_mapping_negotiation = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint16_t* m_num_mapping = nullptr;
        cMapping* m_mapping = nullptr;
        size_t m_mapping_idx__ = 0;
        std::vector<std::shared_ptr<cMapping>> m_mapping_vector;
        bool m_lock_allocation__ = false;
};

class cMapping : public BaseClass
{
    public:
        cMapping(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cMapping(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cMapping();

        typedef struct sAddRemove {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t should_be_removed : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t should_be_removed : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sAddRemove;
        
        typedef struct sTidToLinkMapping {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t bit0 : 1;
            uint8_t bit1 : 1;
            uint8_t bit2 : 1;
            uint8_t bit3 : 1;
            uint8_t bit4 : 1;
            uint8_t bit5 : 1;
            uint8_t bit6 : 1;
            uint8_t bit7 : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bit7 : 1;
            uint8_t bit6 : 1;
            uint8_t bit5 : 1;
            uint8_t bit4 : 1;
            uint8_t bit3 : 1;
            uint8_t bit2 : 1;
            uint8_t bit1 : 1;
            uint8_t bit0 : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sTidToLinkMapping;
        
        sAddRemove& add_remove();
        sMacAddr& sta_mld_mac_addr();
        bool isPostInitSucceeded() override;
        std::shared_ptr<cTidToLinkControlField> create_tid_to_link_control_field();
        bool add_tid_to_link_control_field(std::shared_ptr<cTidToLinkControlField> ptr);
        std::shared_ptr<cTidToLinkControlField> tid_to_link_control_field() { return m_tid_to_link_control_field_ptr; }
        sTidToLinkMapping& tid_to_link_mapping();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sAddRemove* m_add_remove = nullptr;
        sMacAddr* m_sta_mld_mac_addr = nullptr;
        cTidToLinkControlField *m_tid_to_link_control_field = nullptr;
        std::shared_ptr<cTidToLinkControlField> m_tid_to_link_control_field_ptr = nullptr;
        bool m_tid_to_link_control_field_init = false;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
        sTidToLinkMapping* m_tid_to_link_mapping = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
};

class cTidToLinkControlField : public BaseClass
{
    public:
        cTidToLinkControlField(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cTidToLinkControlField(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cTidToLinkControlField();

        typedef struct sTidToLinkControl {
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
        } __attribute__((packed)) sTidToLinkControl;
        
        sTidToLinkControl& tid_to_link_control();
        uint8_t& link_mapping_presence_indicator();
        uint8_t* expected_duration(size_t idx = 0);
        bool set_expected_duration(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sTidToLinkControl* m_tid_to_link_control = nullptr;
        uint8_t* m_link_mapping_presence_indicator = nullptr;
        uint8_t* m_expected_duration = nullptr;
        size_t m_expected_duration_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTIDTOLINKMAPPINGPOLICY_H_
