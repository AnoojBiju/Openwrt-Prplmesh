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

#ifndef _TLVF_WFA_MAP_TLVSPATIALREUSEREQUEST_H_
#define _TLVF_WFA_MAP_TLVSPATIALREUSEREQUEST_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"
#include <asm/byteorder.h>

namespace wfa_map {


class tlvSpatialReuseRequest : public BaseClass
{
    public:
        tlvSpatialReuseRequest(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvSpatialReuseRequest(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvSpatialReuseRequest();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t bss_color : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bss_color : 6;
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
            uint8_t psr_disallowed : 1;
            uint8_t non_srg_offset_valid : 1;
            uint8_t srg_information_valid : 1;
            uint8_t hesiga_spatial_reuse_value15_allowed : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t hesiga_spatial_reuse_value15_allowed : 1;
            uint8_t srg_information_valid : 1;
            uint8_t non_srg_offset_valid : 1;
            uint8_t psr_disallowed : 1;
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
        sMacAddr& radio_uid();
        sFlags1& flags1();
        sFlags2& flags2();
        uint8_t& non_srg_obsspd_max_offset();
        uint8_t& srg_obsspd_min_offset();
        uint8_t& srg_obsspd_max_offset();
        uint64_t& srg_bss_color_bitmap();
        uint64_t& srg_partial_bssid_bitmap();
        uint16_t& reserved();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_radio_uid = nullptr;
        sFlags1* m_flags1 = nullptr;
        sFlags2* m_flags2 = nullptr;
        uint8_t* m_non_srg_obsspd_max_offset = nullptr;
        uint8_t* m_srg_obsspd_min_offset = nullptr;
        uint8_t* m_srg_obsspd_max_offset = nullptr;
        uint64_t* m_srg_bss_color_bitmap = nullptr;
        uint64_t* m_srg_partial_bssid_bitmap = nullptr;
        uint16_t* m_reserved = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVSPATIALREUSEREQUEST_H_
