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

#ifndef _TLVF_WFA_MAP_TLV1905ENCAPDPP_H_
#define _TLVF_WFA_MAP_TLV1905ENCAPDPP_H_

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
#include <ostream>

namespace wfa_map {


class tlv1905EncapDpp : public BaseClass
{
    public:
        tlv1905EncapDpp(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlv1905EncapDpp(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlv1905EncapDpp();

        typedef struct sFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved2 : 5;
            uint8_t dpp_frame_indicator : 1;
            uint8_t reserved1 : 1;
            uint8_t enrollee_mac_address_present : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t enrollee_mac_address_present : 1;
            uint8_t reserved1 : 1;
            uint8_t dpp_frame_indicator : 1;
            uint8_t reserved2 : 5;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags;
        
        enum eFrameType: uint8_t {
            DPP_PUBLIC_ACTION_FRAME = 0x0,
            GAS_FRAME = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eFrameType_str(eFrameType enum_value) {
            switch (enum_value) {
            case DPP_PUBLIC_ACTION_FRAME: return "DPP_PUBLIC_ACTION_FRAME";
            case GAS_FRAME:               return "GAS_FRAME";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eFrameType value) { return out << eFrameType_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sFlags& frame_flags();
        bool alloc_dest_sta_mac();
        sMacAddr* dest_sta_mac();
        bool set_dest_sta_mac(const sMacAddr dest_sta_mac);
        eFrameType& frame_type();
        uint16_t& encapsulated_frame_length();
        uint8_t* encapsulated_frame(size_t idx = 0);
        bool set_encapsulated_frame(const void* buffer, size_t size);
        bool alloc_encapsulated_frame(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sFlags* m_frame_flags = nullptr;
        sMacAddr* m_dest_sta_mac = nullptr;
        bool m_dest_sta_mac_allocated = false;
        eFrameType* m_frame_type = nullptr;
        uint16_t* m_encapsulated_frame_length = nullptr;
        uint8_t* m_encapsulated_frame = nullptr;
        size_t m_encapsulated_frame_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLV1905ENCAPDPP_H_
