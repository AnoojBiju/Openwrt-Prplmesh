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

#ifndef _TLVF_WFA_MAP_TLVENCRYPTEDPAYLOAD_H_
#define _TLVF_WFA_MAP_TLVENCRYPTEDPAYLOAD_H_

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

namespace wfa_map {


class tlvEncryptedPayload : public BaseClass
{
    public:
        tlvEncryptedPayload(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvEncryptedPayload(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvEncryptedPayload();

        const eTlvTypeMap& type();
        const uint16_t& length();
        //This variable is a 6-octet integer. Unfortunately this is not a native type, which the tlvf
        //does not support.
        //For now, define it as a list of 6 octets though it is wrong since it means it will not get
        //swapped. Will Be address as part of PPM-2013.
        uint8_t* encryption_transmission_counter(size_t idx = 0);
        bool set_encryption_transmission_counter(const void* buffer, size_t size);
        sMacAddr& source_1905_al_mac_address();
        sMacAddr& destination_1905_al_mac_address();
        uint16_t& aes_siv_length();
        //AES-SIV Encryption Output (i.e., SIV concatenated with all the encrypted TLVs)
        uint8_t* aes_siv(size_t idx = 0);
        bool set_aes_siv(const void* buffer, size_t size);
        bool alloc_aes_siv(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_encryption_transmission_counter = nullptr;
        size_t m_encryption_transmission_counter_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sMacAddr* m_source_1905_al_mac_address = nullptr;
        sMacAddr* m_destination_1905_al_mac_address = nullptr;
        uint16_t* m_aes_siv_length = nullptr;
        uint8_t* m_aes_siv = nullptr;
        size_t m_aes_siv_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVENCRYPTEDPAYLOAD_H_
