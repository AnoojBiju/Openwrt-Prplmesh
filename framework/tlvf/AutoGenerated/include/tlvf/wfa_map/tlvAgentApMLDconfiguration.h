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

class cAPMLDEntry;
class cAffiliatedAPEntry;

class tlvAgentApMLDconfiguration : public BaseClass
{
    public:
        tlvAgentApMLDconfiguration(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAgentApMLDconfiguration(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAgentApMLDconfiguration();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& num_ap_mld();
        std::tuple<bool, cAPMLDEntry&> ap_mld_entries(size_t idx);
        std::shared_ptr<cAPMLDEntry> create_ap_mld_entries();
        bool add_ap_mld_entries(std::shared_ptr<cAPMLDEntry> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_num_ap_mld = nullptr;
        cAPMLDEntry* m_ap_mld_entries = nullptr;
        size_t m_ap_mld_entries_idx__ = 0;
        std::vector<std::shared_ptr<cAPMLDEntry>> m_ap_mld_entries_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cAPMLDEntry : public BaseClass
{
    public:
        cAPMLDEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAPMLDEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAPMLDEntry();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t ap_mld_mac_addr_valid : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t ap_mld_mac_addr_valid : 1;
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
        } __attribute__((packed)) sFlags2;
        
        sFlags2& flags();
        uint8_t& ssid_length();
        std::string ssid_str();
        char* ssid(size_t length = 0);
        bool set_ssid(const std::string& str);
        bool set_ssid(const char buffer[], size_t size);
        bool alloc_ssid(size_t count = 1);
        sMacAddr& ap_mld_mac_addr();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint8_t& num_affiliated_ap();
        std::tuple<bool, cAffiliatedAPEntry&> affiliated_ap_entries(size_t idx);
        std::shared_ptr<cAffiliatedAPEntry> create_affiliated_ap_entries();
        bool add_affiliated_ap_entries(std::shared_ptr<cAffiliatedAPEntry> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sFlags2* m_flags = nullptr;
        uint8_t* m_ssid_length = nullptr;
        char* m_ssid = nullptr;
        size_t m_ssid_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sMacAddr* m_ap_mld_mac_addr = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        uint8_t* m_num_affiliated_ap = nullptr;
        cAffiliatedAPEntry* m_affiliated_ap_entries = nullptr;
        size_t m_affiliated_ap_entries_idx__ = 0;
        std::vector<std::shared_ptr<cAffiliatedAPEntry>> m_affiliated_ap_entries_vector;
        bool m_lock_allocation__ = false;
};

class cAffiliatedAPEntry : public BaseClass
{
    public:
        cAffiliatedAPEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAffiliatedAPEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAffiliatedAPEntry();

        typedef struct sFlags3 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 6;
            uint8_t link_id_valid : 1;
            uint8_t affiliated_ap_mac_addr_valid : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t affiliated_ap_mac_addr_valid : 1;
            uint8_t link_id_valid : 1;
            uint8_t reserved : 6;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags3;
        
        sFlags3& flags();
        sMacAddr& ruid();
        sMacAddr& affiliated_ap_mac_addr();
        //0-15 = Variable, 16-255 = Reserved
        uint8_t& link_id();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sFlags3* m_flags = nullptr;
        sMacAddr* m_ruid = nullptr;
        sMacAddr* m_affiliated_ap_mac_addr = nullptr;
        uint8_t* m_link_id = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_
