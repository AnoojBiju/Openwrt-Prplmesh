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

#ifndef _TLVF_WFA_MAP_TLVDPPCHIRPVALUE_H_
#define _TLVF_WFA_MAP_TLVDPPCHIRPVALUE_H_

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
#include <asm/byteorder.h>

namespace wfa_map {


class tlvDppChirpValue : public BaseClass
{
    public:
        tlvDppChirpValue(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvDppChirpValue(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvDppChirpValue();

        typedef struct sFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 6;
            uint8_t hash_validity : 1;
            uint8_t enrollee_mac_address_present : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t enrollee_mac_address_present : 1;
            uint8_t hash_validity : 1;
            uint8_t reserved : 6;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sFlags& flags();
        bool alloc_dest_sta_mac();
        sMacAddr* dest_sta_mac();
        bool set_dest_sta_mac(const sMacAddr dest_sta_mac);
        uint8_t& hash_length();
        uint8_t* hash(size_t idx = 0);
        bool set_hash(const void* buffer, size_t size);
        bool alloc_hash(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sFlags* m_flags = nullptr;
        sMacAddr* m_dest_sta_mac = nullptr;
        bool m_dest_sta_mac_allocated = false;
        uint8_t* m_hash_length = nullptr;
        uint8_t* m_hash = nullptr;
        size_t m_hash_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVDPPCHIRPVALUE_H_
