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

namespace wfa_map {

class cRadioEntry;
class cBSSEntry;

class tlvEHTOperations : public BaseClass
{
    public:
        tlvEHTOperations(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvEHTOperations(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvEHTOperations();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint32_t& reserved();
        uint8_t& num_radio();
        std::tuple<bool, cRadioEntry&> radioEntries(size_t idx);
        std::shared_ptr<cRadioEntry> create_radioEntries();
        bool add_radioEntries(std::shared_ptr<cRadioEntry> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint32_t* m_reserved = nullptr;
        uint8_t* m_num_radio = nullptr;
        cRadioEntry* m_radioEntries = nullptr;
        size_t m_radioEntries_idx__ = 0;
        std::vector<std::shared_ptr<cRadioEntry>> m_radioEntries_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cRadioEntry : public BaseClass
{
    public:
        cRadioEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRadioEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRadioEntry();

        sMacAddr& ruid();
        uint8_t& num_BSS();
        std::tuple<bool, cBSSEntry&> bssEntries(size_t idx);
        std::shared_ptr<cBSSEntry> create_bssEntries();
        bool add_bssEntries(std::shared_ptr<cBSSEntry> ptr);
        uint8_t* reserved_2(size_t idx = 0);
        bool set_reserved_2(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_ruid = nullptr;
        uint8_t* m_num_BSS = nullptr;
        cBSSEntry* m_bssEntries = nullptr;
        size_t m_bssEntries_idx__ = 0;
        std::vector<std::shared_ptr<cBSSEntry>> m_bssEntries_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
        uint8_t* m_reserved_2 = nullptr;
        size_t m_reserved_2_idx__ = 0;
};

class cBSSEntry : public BaseClass
{
    public:
        cBSSEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBSSEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBSSEntry();

        sMacAddr& bssid();
        uint8_t& EHT_Operation_Information_Valid();
        uint8_t& disabled_Subchannel_Valid();
        uint8_t& EHT_Default_PE_Duration();
        uint8_t& group_Addressed_BU_Indication_Limit();
        uint8_t& group_Addressed_BU_Indication_Exponent();
        uint8_t& reserved();
        uint32_t& basic_EHT_MCS_And_Nss_Set();
        uint8_t& control();
        uint8_t& ccfs0();
        uint8_t& ccfs1();
        uint16_t& disabled_Subchannel_Bitmap();
        uint8_t* reserved_1(size_t idx = 0);
        bool set_reserved_1(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bssid = nullptr;
        uint8_t* m_EHT_Operation_Information_Valid = nullptr;
        uint8_t* m_disabled_Subchannel_Valid = nullptr;
        uint8_t* m_EHT_Default_PE_Duration = nullptr;
        uint8_t* m_group_Addressed_BU_Indication_Limit = nullptr;
        uint8_t* m_group_Addressed_BU_Indication_Exponent = nullptr;
        uint8_t* m_reserved = nullptr;
        uint32_t* m_basic_EHT_MCS_And_Nss_Set = nullptr;
        uint8_t* m_control = nullptr;
        uint8_t* m_ccfs0 = nullptr;
        uint8_t* m_ccfs1 = nullptr;
        uint16_t* m_disabled_Subchannel_Bitmap = nullptr;
        uint8_t* m_reserved_1 = nullptr;
        size_t m_reserved_1_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVEHTOPERATIONS_H_
