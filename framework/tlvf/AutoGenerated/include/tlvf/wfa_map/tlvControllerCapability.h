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

#ifndef _TLVF_WFA_MAP_TLVCONTROLLERCAPABILITY_H_
#define _TLVF_WFA_MAP_TLVCONTROLLERCAPABILITY_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>
#include <asm/byteorder.h>

namespace wfa_map {


class tlvControllerCapability : public BaseClass
{
    public:
        tlvControllerCapability(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvControllerCapability(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvControllerCapability();

        typedef struct sFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t kibmib_counter_supported : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t kibmib_counter_supported : 1;
            uint8_t reserved : 7;
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
        //Reserved for future expansion (length inferred from tlvLength field)
        size_t reserved_length() { return m_reserved_idx__ * sizeof(uint8_t); }
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        bool alloc_reserved(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sFlags* m_flags = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVCONTROLLERCAPABILITY_H_
