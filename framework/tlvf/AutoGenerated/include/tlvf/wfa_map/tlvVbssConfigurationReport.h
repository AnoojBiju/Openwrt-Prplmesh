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

#ifndef _TLVF_WFA_MAP_TLVVBSSCONFIGURATIONREPORT_H_
#define _TLVF_WFA_MAP_TLVVBSSCONFIGURATIONREPORT_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tuple>
#include <vector>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/wfa_map/eVirtualBssSubtype.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {

class cVbssRadioInfo;
class cVbssBssInfo;

class VbssConfigurationReport : public BaseClass
{
    public:
        VbssConfigurationReport(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit VbssConfigurationReport(std::shared_ptr<BaseClass> base, bool parse = false);
        ~VbssConfigurationReport();

        const eTlvTypeMap& type();
        const uint16_t& length();
        const eVirtualBssSubtype& subtype();
        uint8_t& number_of_radios();
        std::tuple<bool, cVbssRadioInfo&> radio_list(size_t idx);
        std::shared_ptr<cVbssRadioInfo> create_radio_list();
        bool add_radio_list(std::shared_ptr<cVbssRadioInfo> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eVirtualBssSubtype* m_subtype = nullptr;
        uint8_t* m_number_of_radios = nullptr;
        cVbssRadioInfo* m_radio_list = nullptr;
        size_t m_radio_list_idx__ = 0;
        std::vector<std::shared_ptr<cVbssRadioInfo>> m_radio_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cVbssRadioInfo : public BaseClass
{
    public:
        cVbssRadioInfo(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cVbssRadioInfo(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cVbssRadioInfo();

        sMacAddr& radio_uid();
        uint8_t& number_bss();
        std::tuple<bool, cVbssBssInfo&> bss_list(size_t idx);
        std::shared_ptr<cVbssBssInfo> create_bss_list();
        bool add_bss_list(std::shared_ptr<cVbssBssInfo> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_radio_uid = nullptr;
        uint8_t* m_number_bss = nullptr;
        cVbssBssInfo* m_bss_list = nullptr;
        size_t m_bss_list_idx__ = 0;
        std::vector<std::shared_ptr<cVbssBssInfo>> m_bss_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cVbssBssInfo : public BaseClass
{
    public:
        cVbssBssInfo(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cVbssBssInfo(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cVbssBssInfo();

        sMacAddr& bssid();
        uint8_t& ssid_length();
        std::string ssid_str();
        char* ssid(size_t length = 0);
        bool set_ssid(const std::string& str);
        bool set_ssid(const char buffer[], size_t size);
        bool alloc_ssid(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bssid = nullptr;
        uint8_t* m_ssid_length = nullptr;
        char* m_ssid = nullptr;
        size_t m_ssid_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVVBSSCONFIGURATIONREPORT_H_
