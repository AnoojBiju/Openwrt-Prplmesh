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

#ifndef _TLVF_WFA_MAP_TLVMIC_H_
#define _TLVF_WFA_MAP_TLVMIC_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>
#include "tlvf/common/sMacAddr.h"
#include <asm/byteorder.h>
#include <ostream>

namespace wfa_map {


class tlvMic : public BaseClass
{
    public:
        tlvMic(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvMic(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvMic();

        typedef struct sFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 4;
            uint8_t mic_version : 2;
            uint8_t ieee1905_gtk_key_id : 2;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t ieee1905_gtk_key_id : 2;
            uint8_t mic_version : 2;
            uint8_t reserved : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags;
        
        enum eMicVersion: uint8_t {
            VERSION_1 = 0x0,
            RESERVED = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eMicVersion_str(eMicVersion enum_value) {
            switch (enum_value) {
            case VERSION_1: return "VERSION_1";
            case RESERVED:  return "RESERVED";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eMicVersion value) { return out << eMicVersion_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sFlags& flags();
        //This variable is a 6-octet integer. Unfortunately this is not a native type, which the tlvf
        //does not support.
        //For now, define it as a list of 6 octets though it is wrong since it means it will not get
        //swapped. Will Be address as part of PPM-2013.
        uint8_t* integrity_transmission_counter(size_t idx = 0);
        bool set_integrity_transmission_counter(const void* buffer, size_t size);
        sMacAddr& source_1905_al_mac_address();
        uint16_t& mic_length();
        //Message Integrity Code
        uint8_t* mic(size_t idx = 0);
        bool set_mic(const void* buffer, size_t size);
        bool alloc_mic(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sFlags* m_flags = nullptr;
        uint8_t* m_integrity_transmission_counter = nullptr;
        size_t m_integrity_transmission_counter_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sMacAddr* m_source_1905_al_mac_address = nullptr;
        uint16_t* m_mic_length = nullptr;
        uint8_t* m_mic = nullptr;
        size_t m_mic_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVMIC_H_
