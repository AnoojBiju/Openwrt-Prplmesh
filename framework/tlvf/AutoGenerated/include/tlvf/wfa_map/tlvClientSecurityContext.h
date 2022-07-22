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

#ifndef _TLVF_WFA_MAP_TLVCLIENTSECURITYCONTEXT_H_
#define _TLVF_WFA_MAP_TLVCLIENTSECURITYCONTEXT_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tuple>
#include <asm/byteorder.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/wfa_map/eVirtualBssSubtype.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class ClientSecurityContext : public BaseClass
{
    public:
        ClientSecurityContext(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit ClientSecurityContext(std::shared_ptr<BaseClass> base, bool parse = false);
        ~ClientSecurityContext();

        typedef struct sClientConnectedFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t client_connected : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t client_connected : 1;
            uint8_t reserved : 7;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sClientConnectedFlags;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        const eVirtualBssSubtype& subtype();
        ClientSecurityContext::sClientConnectedFlags& client_connected_flags();
        //if the network is open, then this field is 0.
        uint16_t& key_length();
        uint8_t* ptk(size_t idx = 0);
        bool set_ptk(const void* buffer, size_t size);
        bool alloc_ptk(size_t count = 1);
        uint64_t& tx_packet_num();
        uint16_t& group_key_length();
        uint8_t* gtk(size_t idx = 0);
        bool set_gtk(const void* buffer, size_t size);
        bool alloc_gtk(size_t count = 1);
        uint64_t& group_tx_packet_num();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eVirtualBssSubtype* m_subtype = nullptr;
        ClientSecurityContext::sClientConnectedFlags* m_client_connected_flags = nullptr;
        uint16_t* m_key_length = nullptr;
        uint8_t* m_ptk = nullptr;
        size_t m_ptk_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint64_t* m_tx_packet_num = nullptr;
        uint16_t* m_group_key_length = nullptr;
        uint8_t* m_gtk = nullptr;
        size_t m_gtk_idx__ = 0;
        uint64_t* m_group_tx_packet_num = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVCLIENTSECURITYCONTEXT_H_
