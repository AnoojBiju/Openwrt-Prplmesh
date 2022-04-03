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

#ifndef _TLVF_WFA_MAP_TLVBSSCONFIGURATIONREPORT_H_
#define _TLVF_WFA_MAP_TLVBSSCONFIGURATIONREPORT_H_

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
#include <vector>

namespace wfa_map {

class cBssConf;
class cRadio;

class tlvBssConfigurationReport : public BaseClass
{
    public:
        tlvBssConfigurationReport(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvBssConfigurationReport(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvBssConfigurationReport();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& number_of_reported_radios();
        bool isPostInitSucceeded() override;
        std::shared_ptr<cRadio> create_radios();
        bool add_radios(std::shared_ptr<cRadio> ptr);
        std::shared_ptr<cRadio> radios() { return m_radios_ptr; }
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_number_of_reported_radios = nullptr;
        cRadio *m_radios = nullptr;
        std::shared_ptr<cRadio> m_radios_ptr = nullptr;
        bool m_radios_init = false;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cBssConf : public BaseClass
{
    public:
        cBssConf(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBssConf(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBssConf();

        typedef struct sBssInformationElement {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 2;
            uint8_t transmitted_bssid : 1;
            uint8_t multiple_bssid : 1;
            uint8_t r2_disallowed : 1;
            uint8_t r1_disallowed : 1;
            uint8_t fronthaul_bss : 1;
            uint8_t backhaul_bss : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t backhaul_bss : 1;
            uint8_t fronthaul_bss : 1;
            uint8_t r1_disallowed : 1;
            uint8_t r2_disallowed : 1;
            uint8_t multiple_bssid : 1;
            uint8_t transmitted_bssid : 1;
            uint8_t reserved : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sBssInformationElement;
        
        sMacAddr& bssid();
        sBssInformationElement& bss_ie();
        uint8_t& reserved();
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
        sBssInformationElement* m_bss_ie = nullptr;
        uint8_t* m_reserved = nullptr;
        uint8_t* m_ssid_length = nullptr;
        char* m_ssid = nullptr;
        size_t m_ssid_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cRadio : public BaseClass
{
    public:
        cRadio(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRadio(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRadio();

        sMacAddr& ruid();
        uint8_t& number_of_bss();
        std::tuple<bool, cBssConf&> bss_info(size_t idx);
        std::shared_ptr<cBssConf> create_bss_info();
        bool add_bss_info(std::shared_ptr<cBssConf> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_ruid = nullptr;
        uint8_t* m_number_of_bss = nullptr;
        cBssConf* m_bss_info = nullptr;
        size_t m_bss_info_idx__ = 0;
        std::vector<std::shared_ptr<cBssConf>> m_bss_info_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVBSSCONFIGURATIONREPORT_H_
