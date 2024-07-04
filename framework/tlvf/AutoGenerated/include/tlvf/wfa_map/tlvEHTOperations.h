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

#ifndef _TLVF_WFA_MAP_TLVEHTOPERATIONS_H_
#define _TLVF_WFA_MAP_TLVEHTOPERATIONS_H_

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

class cRadioEntry;
class cBssEntry;

class tlvEHTOperations : public BaseClass
{
    public:
        tlvEHTOperations(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvEHTOperations(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvEHTOperations();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint8_t& num_radio();
        std::tuple<bool, cRadioEntry&> radio_entries(size_t idx);
        std::shared_ptr<cRadioEntry> create_radio_entries();
        bool add_radio_entries(std::shared_ptr<cRadioEntry> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_radio = nullptr;
        cRadioEntry* m_radio_entries = nullptr;
        size_t m_radio_entries_idx__ = 0;
        std::vector<std::shared_ptr<cRadioEntry>> m_radio_entries_vector;
        bool m_lock_allocation__ = false;
};

class cRadioEntry : public BaseClass
{
    public:
        cRadioEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRadioEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRadioEntry();

        sMacAddr& ruid();
        uint8_t& num_bss();
        std::tuple<bool, cBssEntry&> bss_entries(size_t idx);
        std::shared_ptr<cBssEntry> create_bss_entries();
        bool add_bss_entries(std::shared_ptr<cBssEntry> ptr);
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_ruid = nullptr;
        uint8_t* m_num_bss = nullptr;
        cBssEntry* m_bss_entries = nullptr;
        size_t m_bss_entries_idx__ = 0;
        std::vector<std::shared_ptr<cBssEntry>> m_bss_entries_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
};

class cBssEntry : public BaseClass
{
    public:
        cBssEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBssEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBssEntry();

        typedef struct sFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 2;
            uint8_t group_addressed_bu_indication_exponent : 2;
            uint8_t group_addressed_bu_indication_limit : 1;
            uint8_t eht_default_pe_duration : 1;
            uint8_t disabled_subchannel_valid : 1;
            uint8_t eht_operation_information_valid : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t eht_operation_information_valid : 1;
            uint8_t disabled_subchannel_valid : 1;
            uint8_t eht_default_pe_duration : 1;
            uint8_t group_addressed_bu_indication_limit : 1;
            uint8_t group_addressed_bu_indication_exponent : 2;
            uint8_t reserved : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags;
        
        sMacAddr& bssid();
        sFlags& flags();
        uint8_t* basic_eht_mcs_and_nss_set(size_t idx = 0);
        bool set_basic_eht_mcs_and_nss_set(const void* buffer, size_t size);
        uint8_t& control();
        uint8_t& ccfs0();
        uint8_t& ccfs1();
        uint16_t& disabled_subchannel_bitmap();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bssid = nullptr;
        sFlags* m_flags = nullptr;
        uint8_t* m_basic_eht_mcs_and_nss_set = nullptr;
        size_t m_basic_eht_mcs_and_nss_set_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_control = nullptr;
        uint8_t* m_ccfs0 = nullptr;
        uint8_t* m_ccfs1 = nullptr;
        uint16_t* m_disabled_subchannel_bitmap = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVEHTOPERATIONS_H_
