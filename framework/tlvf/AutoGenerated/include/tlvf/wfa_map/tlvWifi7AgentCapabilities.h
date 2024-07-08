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

#ifndef _TLVF_WFA_MAP_TLVWIFI7AGENTCAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVWIFI7AGENTCAPABILITIES_H_

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
#include <asm/byteorder.h>
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {

class cRadioWifi7Capabilities;
class cWifi7Capabilities;
class cRadioConfig;

class tlvWifi7AgentCapabilities : public BaseClass
{
    public:
        tlvWifi7AgentCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvWifi7AgentCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvWifi7AgentCapabilities();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t bsta_maximum_links : 4;
            uint8_t ap_maximum_links : 4;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t ap_maximum_links : 4;
            uint8_t bsta_maximum_links : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags1;
        
        typedef struct sFlags2 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 6;
            uint8_t tid_to_link_mapping_capability : 2;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t tid_to_link_mapping_capability : 2;
            uint8_t reserved : 6;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags2;
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& max_num_mlds();
        sFlags1& flags1();
        sFlags2& flags2();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        uint8_t& num_radio();
        std::tuple<bool, cRadioWifi7Capabilities&> radio_wifi7_capabilities(size_t idx);
        std::shared_ptr<cRadioWifi7Capabilities> create_radio_wifi7_capabilities();
        bool add_radio_wifi7_capabilities(std::shared_ptr<cRadioWifi7Capabilities> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_max_num_mlds = nullptr;
        sFlags1* m_flags1 = nullptr;
        sFlags2* m_flags2 = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_radio = nullptr;
        cRadioWifi7Capabilities* m_radio_wifi7_capabilities = nullptr;
        size_t m_radio_wifi7_capabilities_idx__ = 0;
        std::vector<std::shared_ptr<cRadioWifi7Capabilities>> m_radio_wifi7_capabilities_vector;
        bool m_lock_allocation__ = false;
};

class cRadioWifi7Capabilities : public BaseClass
{
    public:
        cRadioWifi7Capabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRadioWifi7Capabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRadioWifi7Capabilities();

        typedef struct sWifi7CapabilitiesSupport {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 4;
            uint8_t emlmr_support : 1;
            uint8_t emlsr_support : 1;
            uint8_t nstr_support : 1;
            uint8_t str_support : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t str_support : 1;
            uint8_t nstr_support : 1;
            uint8_t emlsr_support : 1;
            uint8_t emlmr_support : 1;
            uint8_t reserved : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sWifi7CapabilitiesSupport;
        
        sMacAddr& ruid();
        uint8_t* reserved(size_t idx = 0);
        bool set_reserved(const void* buffer, size_t size);
        sWifi7CapabilitiesSupport& ap_modes_support();
        sWifi7CapabilitiesSupport& bsta_modes_support();
        bool isPostInitSucceeded() override;
        std::shared_ptr<cWifi7Capabilities> create_ap_wifi7_capabilities();
        bool add_ap_wifi7_capabilities(std::shared_ptr<cWifi7Capabilities> ptr);
        std::shared_ptr<cWifi7Capabilities> ap_wifi7_capabilities() { return m_ap_wifi7_capabilities_ptr; }
        std::shared_ptr<cWifi7Capabilities> create_bsta_wifi7_capabilities();
        bool add_bsta_wifi7_capabilities(std::shared_ptr<cWifi7Capabilities> ptr);
        std::shared_ptr<cWifi7Capabilities> bsta_wifi7_capabilities() { return m_bsta_wifi7_capabilities_ptr; }
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_ruid = nullptr;
        uint8_t* m_reserved = nullptr;
        size_t m_reserved_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sWifi7CapabilitiesSupport* m_ap_modes_support = nullptr;
        sWifi7CapabilitiesSupport* m_bsta_modes_support = nullptr;
        cWifi7Capabilities *m_ap_wifi7_capabilities = nullptr;
        std::shared_ptr<cWifi7Capabilities> m_ap_wifi7_capabilities_ptr = nullptr;
        bool m_ap_wifi7_capabilities_init = false;
        bool m_lock_allocation__ = false;
        cWifi7Capabilities *m_bsta_wifi7_capabilities = nullptr;
        std::shared_ptr<cWifi7Capabilities> m_bsta_wifi7_capabilities_ptr = nullptr;
        bool m_bsta_wifi7_capabilities_init = false;
};

class cWifi7Capabilities : public BaseClass
{
    public:
        cWifi7Capabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cWifi7Capabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cWifi7Capabilities();

        uint8_t& num_str_records();
        std::tuple<bool, cRadioConfig&> str_config(size_t idx);
        std::shared_ptr<cRadioConfig> create_str_config();
        bool add_str_config(std::shared_ptr<cRadioConfig> ptr);
        uint8_t& num_nstr_records();
        std::tuple<bool, cRadioConfig&> nstr_config(size_t idx);
        std::shared_ptr<cRadioConfig> create_nstr_config();
        bool add_nstr_config(std::shared_ptr<cRadioConfig> ptr);
        uint8_t& num_emlsr_records();
        std::tuple<bool, cRadioConfig&> emlsr_config(size_t idx);
        std::shared_ptr<cRadioConfig> create_emlsr_config();
        bool add_emlsr_config(std::shared_ptr<cRadioConfig> ptr);
        uint8_t& num_emlmr_records();
        std::tuple<bool, cRadioConfig&> emlmr_config(size_t idx);
        std::shared_ptr<cRadioConfig> create_emlmr_config();
        bool add_emlmr_config(std::shared_ptr<cRadioConfig> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_num_str_records = nullptr;
        cRadioConfig* m_str_config = nullptr;
        size_t m_str_config_idx__ = 0;
        std::vector<std::shared_ptr<cRadioConfig>> m_str_config_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_nstr_records = nullptr;
        cRadioConfig* m_nstr_config = nullptr;
        size_t m_nstr_config_idx__ = 0;
        std::vector<std::shared_ptr<cRadioConfig>> m_nstr_config_vector;
        uint8_t* m_num_emlsr_records = nullptr;
        cRadioConfig* m_emlsr_config = nullptr;
        size_t m_emlsr_config_idx__ = 0;
        std::vector<std::shared_ptr<cRadioConfig>> m_emlsr_config_vector;
        uint8_t* m_num_emlmr_records = nullptr;
        cRadioConfig* m_emlmr_config = nullptr;
        size_t m_emlmr_config_idx__ = 0;
        std::vector<std::shared_ptr<cRadioConfig>> m_emlmr_config_vector;
};

class cRadioConfig : public BaseClass
{
    public:
        cRadioConfig(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRadioConfig(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRadioConfig();

        typedef struct sFrequencySeparation {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved : 3;
            uint8_t freq_separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t freq_separation : 5;
            uint8_t reserved : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFrequencySeparation;
        
        sMacAddr& ruid();
        sFrequencySeparation& frequency_separation();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_ruid = nullptr;
        sFrequencySeparation* m_frequency_separation = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVWIFI7AGENTCAPABILITIES_H_
