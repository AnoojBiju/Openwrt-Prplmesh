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

#ifndef _TLVF_WFA_MAP_TLVASSOCIATEDSTAMLDCONFIGURATIONREPORT_H_
#define _TLVF_WFA_MAP_TLVASSOCIATEDSTAMLDCONFIGURATIONREPORT_H_

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

class cAffiliatedSta;

class tlvAssociatedStaMldConfigurationReport : public BaseClass
{
    public:
        tlvAssociatedStaMldConfigurationReport(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAssociatedStaMldConfigurationReport(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAssociatedStaMldConfigurationReport();

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
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& sta_mld_mac_addr();
        sMacAddr& ap_mld_mac_addr();
        sModes& modes();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint8_t& num_affiliated_sta();
        std::tuple<bool, cAffiliatedSta&> affiliated_sta(size_t idx);
        std::shared_ptr<cAffiliatedSta> create_affiliated_sta();
        bool add_affiliated_sta(std::shared_ptr<cAffiliatedSta> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_sta_mld_mac_addr = nullptr;
        sMacAddr* m_ap_mld_mac_addr = nullptr;
        sModes* m_modes = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_affiliated_sta = nullptr;
        cAffiliatedSta* m_affiliated_sta = nullptr;
        size_t m_affiliated_sta_idx__ = 0;
        std::vector<std::shared_ptr<cAffiliatedSta>> m_affiliated_sta_vector;
        bool m_lock_allocation__ = false;
};

class cAffiliatedSta : public BaseClass
{
    public:
        cAffiliatedSta(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAffiliatedSta(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAffiliatedSta();

        sMacAddr& bssid();
        sMacAddr& affiliated_sta_mac_addr();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bssid = nullptr;
        sMacAddr* m_affiliated_sta_mac_addr = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVASSOCIATEDSTAMLDCONFIGURATIONREPORT_H_
