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

#ifndef _TLVF_WFA_MAP_TLVSPATIALREUSEREPORT_H_
#define _TLVF_WFA_MAP_TLVSPATIALREUSEREPORT_H_

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


class tlvSpatialReuseReport : public BaseClass
{
    public:
        tlvSpatialReuseReport(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvSpatialReuseReport(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvSpatialReuseReport();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 2;
            uint8_t bss_color : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bss_color : 6;
            uint8_t reserved : 2;
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
            uint8_t Psr_Disallowed : 1;
            uint8_t Reserved : 1;
            uint8_t Non_SRG_offset_valid : 1;
            uint8_t SRG_information_valid : 1;
            uint8_t HESIGA_Spatial_reuse_value15_allowed : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t HESIGA_Spatial_reuse_value15_allowed : 1;
            uint8_t SRG_information_valid : 1;
            uint8_t Non_SRG_offset_valid : 1;
            uint8_t Reserved : 1;
            uint8_t Psr_Disallowed : 1;
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
        uint8_t& Non_SRG_obsspd_max_offset();
        uint8_t& SRG_obsspd_min_offset();
        uint8_t& SRG_obsspd_max_offset();
        uint64_t& SRG_bss_color_bitmap();
        uint64_t& SRG_partial_bssid_bitmap();
        uint64_t& Neighbor_bss_color_in_use_bitmap();
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
        uint8_t* m_Non_SRG_obsspd_max_offset = nullptr;
        uint8_t* m_SRG_obsspd_min_offset = nullptr;
        uint8_t* m_SRG_obsspd_max_offset = nullptr;
        uint64_t* m_SRG_bss_color_bitmap = nullptr;
        uint64_t* m_SRG_partial_bssid_bitmap = nullptr;
        uint64_t* m_Neighbor_bss_color_in_use_bitmap = nullptr;
        uint16_t* m_reserved = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVSPATIALREUSEREPORT_H_
