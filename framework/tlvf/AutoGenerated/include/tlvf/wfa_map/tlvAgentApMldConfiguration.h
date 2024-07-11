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

#ifndef _TLVF_WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_
#define _TLVF_WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>
#include <vector>
#include "tlvf/common/sMacAddr.h"
#include <asm/byteorder.h>

namespace wfa_map {

class cApMld;
class cAffiliatedAp;

class tlvAgentApMldConfiguration : public BaseClass
{
    public:
        tlvAgentApMldConfiguration(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAgentApMldConfiguration(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAgentApMldConfiguration();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& num_ap_mld();
        std::tuple<bool, cApMld&> ap_mld(size_t idx);
        std::shared_ptr<cApMld> create_ap_mld();
        bool add_ap_mld(std::shared_ptr<cApMld> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_num_ap_mld = nullptr;
        cApMld* m_ap_mld = nullptr;
        size_t m_ap_mld_idx__ = 0;
        std::vector<std::shared_ptr<cApMld>> m_ap_mld_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cApMld : public BaseClass
{
    public:
        cApMld(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cApMld(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cApMld();

        typedef struct sApMldMacAddrValid {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t is_valid : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t is_valid : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sApMldMacAddrValid;
        
        typedef struct sModes {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 4;
            uint8_t emlmr : 1;
            uint8_t emlsr : 1;
            uint8_t nstr : 1;
            uint8_t str : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t str : 1;
            uint8_t nstr : 1;
            uint8_t emlsr : 1;
            uint8_t emlmr : 1;
            uint8_t reserved : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sModes;
        
        sApMldMacAddrValid& ap_mld_mac_addr_valid();
        uint8_t& ssid_length();
        std::string ssid_str();
        char* ssid(size_t length = 0);
        bool set_ssid(const std::string& str);
        bool set_ssid(const char buffer[], size_t size);
        bool alloc_ssid(size_t count = 1);
        sMacAddr& ap_mld_mac_addr();
        sModes& modes();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint8_t& num_affiliated_ap();
        std::tuple<bool, cAffiliatedAp&> affiliated_ap(size_t idx);
        std::shared_ptr<cAffiliatedAp> create_affiliated_ap();
        bool add_affiliated_ap(std::shared_ptr<cAffiliatedAp> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sApMldMacAddrValid* m_ap_mld_mac_addr_valid = nullptr;
        uint8_t* m_ssid_length = nullptr;
        char* m_ssid = nullptr;
        size_t m_ssid_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sMacAddr* m_ap_mld_mac_addr = nullptr;
        sModes* m_modes = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        uint8_t* m_num_affiliated_ap = nullptr;
        cAffiliatedAp* m_affiliated_ap = nullptr;
        size_t m_affiliated_ap_idx__ = 0;
        std::vector<std::shared_ptr<cAffiliatedAp>> m_affiliated_ap_vector;
        bool m_lock_allocation__ = false;
};

class cAffiliatedAp : public BaseClass
{
    public:
        cAffiliatedAp(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAffiliatedAp(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAffiliatedAp();

        typedef struct sAffiliatedApFieldsValid {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 6;
            uint8_t linkid_valid : 1;
            uint8_t affiliated_ap_mac_addr_valid : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t affiliated_ap_mac_addr_valid : 1;
            uint8_t linkid_valid : 1;
            uint8_t reserved : 6;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sAffiliatedApFieldsValid;
        
        sAffiliatedApFieldsValid& affiliated_ap_fields_valid();
        sMacAddr& ruid();
        sMacAddr& affiliated_ap_mac_addr();
        uint8_t& linkid();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sAffiliatedApFieldsValid* m_affiliated_ap_fields_valid = nullptr;
        sMacAddr* m_ruid = nullptr;
        sMacAddr* m_affiliated_ap_mac_addr = nullptr;
        uint8_t* m_linkid = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_
