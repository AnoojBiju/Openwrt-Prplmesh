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

#ifndef _TLVF_WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_
#define _TLVF_WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_

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

class cAPMLDEntry;
class cAffiliatedAPEntry;

class tlvAgentApMLDconfiguration : public BaseClass
{
    public:
        tlvAgentApMLDconfiguration(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvAgentApMLDconfiguration(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvAgentApMLDconfiguration();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& num_APMLD();
        std::tuple<bool, cAPMLDEntry&> apMLDEntries(size_t idx);
        std::shared_ptr<cAPMLDEntry> create_apMLDEntries();
        bool add_apMLDEntries(std::shared_ptr<cAPMLDEntry> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_num_APMLD = nullptr;
        cAPMLDEntry* m_apMLDEntries = nullptr;
        size_t m_apMLDEntries_idx__ = 0;
        std::vector<std::shared_ptr<cAPMLDEntry>> m_apMLDEntries_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cAPMLDEntry : public BaseClass
{
    public:
        cAPMLDEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAPMLDEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAPMLDEntry();

        uint8_t& AP_MLD_MAC_Addr_Valid();
        uint8_t& reserved_1();
        uint8_t& ssid_length();
        std::string ssid_str();
        char* ssid(size_t length = 0);
        bool set_ssid(const std::string& str);
        bool set_ssid(const char buffer[], size_t size);
        bool alloc_ssid(size_t count = 1);
        sMacAddr& AP_MLD_MAC_Addr();
        uint8_t& STR();
        uint8_t& NSTR();
        uint8_t& EMLSR();
        uint8_t& EMLMR();
        uint8_t& reserved_2();
        uint8_t* reserved_3(size_t idx = 0);
        bool set_reserved_3(const void* buffer, size_t size);
        uint8_t& num_AffiliatedAP();
        std::tuple<bool, cAffiliatedAPEntry&> affiliatedAPEntries(size_t idx);
        std::shared_ptr<cAffiliatedAPEntry> create_affiliatedAPEntries();
        bool add_affiliatedAPEntries(std::shared_ptr<cAffiliatedAPEntry> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_AP_MLD_MAC_Addr_Valid = nullptr;
        uint8_t* m_reserved_1 = nullptr;
        uint8_t* m_ssid_length = nullptr;
        char* m_ssid = nullptr;
        size_t m_ssid_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sMacAddr* m_AP_MLD_MAC_Addr = nullptr;
        uint8_t* m_STR = nullptr;
        uint8_t* m_NSTR = nullptr;
        uint8_t* m_EMLSR = nullptr;
        uint8_t* m_EMLMR = nullptr;
        uint8_t* m_reserved_2 = nullptr;
        uint8_t* m_reserved_3 = nullptr;
        size_t m_reserved_3_idx__ = 0;
        uint8_t* m_num_AffiliatedAP = nullptr;
        cAffiliatedAPEntry* m_affiliatedAPEntries = nullptr;
        size_t m_affiliatedAPEntries_idx__ = 0;
        std::vector<std::shared_ptr<cAffiliatedAPEntry>> m_affiliatedAPEntries_vector;
        bool m_lock_allocation__ = false;
};

class cAffiliatedAPEntry : public BaseClass
{
    public:
        cAffiliatedAPEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAffiliatedAPEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAffiliatedAPEntry();

        uint8_t& affiliated_AP_MAC_Addr_Valid();
        uint8_t& linkid_Valid();
        uint8_t& reserved_2();
        sMacAddr& ruid();
        sMacAddr& affiliated_AP_MAC_Addr();
        uint8_t& linkid();
        uint8_t& reserved_4();
        uint8_t* reserved_5(size_t idx = 0);
        bool set_reserved_5(const void* buffer, size_t size);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_affiliated_AP_MAC_Addr_Valid = nullptr;
        uint8_t* m_linkid_Valid = nullptr;
        uint8_t* m_reserved_2 = nullptr;
        sMacAddr* m_ruid = nullptr;
        sMacAddr* m_affiliated_AP_MAC_Addr = nullptr;
        uint8_t* m_linkid = nullptr;
        uint8_t* m_reserved_4 = nullptr;
        uint8_t* m_reserved_5 = nullptr;
        size_t m_reserved_5_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVAGENTAPMLDCONFIGURATION_H_
