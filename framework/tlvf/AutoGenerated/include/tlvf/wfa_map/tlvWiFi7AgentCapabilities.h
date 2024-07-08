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
#include <ostream>
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {

class cRadioEntry;
class cAP_STR_Records;
class cAP_NSTR_Records;
class cAP_EMLSR_Records;
class cAP_EMLMR_Records;
class cBSTA_STR_Records;
class cBSTA_NSTR_Records;
class cBSTA_EMLSR_Records;
class cBSTA_EMLMR_Records;

class tlvWiFi7AgentCapabilities : public BaseClass
{
    public:
        tlvWiFi7AgentCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvWiFi7AgentCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvWiFi7AgentCapabilities();

        typedef struct sFlags1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t bSTA_Maximum_Links : 4;
            uint8_t AP_Maximum_Links : 4;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t AP_Maximum_Links : 4;
            uint8_t bSTA_Maximum_Links : 4;
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
            uint8_t reserved_1 : 6;
            uint8_t TID_To_Link_Mapping_Capability : 2;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t TID_To_Link_Mapping_Capability : 2;
            uint8_t reserved_1 : 6;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags2;
        
        enum eCapabilitysupport: uint8_t {
            AGENT_DOES_NOT_SUPPORT_TID_TO_LINK_MAPPING = 0x0,
            AGENT_SUPPORTS_SAME_OR_DIFFERENT_LINK_SET = 0x1,
            RESERVED = 0x2,
            AGENT_SUPPORTS_SAME_LINK_SET_FOR_ALL_TIDS = 0x3,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eCapabilitysupport_str(eCapabilitysupport enum_value) {
            switch (enum_value) {
            case AGENT_DOES_NOT_SUPPORT_TID_TO_LINK_MAPPING: return "AGENT_DOES_NOT_SUPPORT_TID_TO_LINK_MAPPING";
            case AGENT_SUPPORTS_SAME_OR_DIFFERENT_LINK_SET:  return "AGENT_SUPPORTS_SAME_OR_DIFFERENT_LINK_SET";
            case RESERVED:                                   return "RESERVED";
            case AGENT_SUPPORTS_SAME_LINK_SET_FOR_ALL_TIDS:  return "AGENT_SUPPORTS_SAME_LINK_SET_FOR_ALL_TIDS";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eCapabilitysupport value) { return out << eCapabilitysupport_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& maxnumMLDs();
        sFlags2& flags();
        uint8_t* reserved_2(size_t idx = 0);
        bool set_reserved_2(const void* buffer, size_t size);
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
        uint8_t* m_maxnumMLDs = nullptr;
        sFlags2* m_flags = nullptr;
        uint8_t* m_reserved_2 = nullptr;
        size_t m_reserved_2_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_radio = nullptr;
        cRadioEntry* m_radioEntries = nullptr;
        size_t m_radioEntries_idx__ = 0;
        std::vector<std::shared_ptr<cRadioEntry>> m_radioEntries_vector;
        bool m_lock_allocation__ = false;
};

class cRadioEntry : public BaseClass
{
    public:
        cRadioEntry(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cRadioEntry(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cRadioEntry();

        typedef struct sFlags3 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_4 : 4;
            uint8_t AP_EMLMR_Support : 1;
            uint8_t AP_EMLSR_Support : 1;
            uint8_t AP_NSTR_Support : 1;
            uint8_t AP_STR_Support : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t AP_STR_Support : 1;
            uint8_t AP_NSTR_Support : 1;
            uint8_t AP_EMLSR_Support : 1;
            uint8_t AP_EMLMR_Support : 1;
            uint8_t reserved_4 : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags3;
        
        typedef struct sFlags4 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_5 : 4;
            uint8_t bSTA_EMLMR_Support : 1;
            uint8_t bSTA_EMLSR_Support : 1;
            uint8_t bSTA_NSTR_Support : 1;
            uint8_t bSTA_STR_Support : 1;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bSTA_STR_Support : 1;
            uint8_t bSTA_NSTR_Support : 1;
            uint8_t bSTA_EMLSR_Support : 1;
            uint8_t bSTA_EMLMR_Support : 1;
            uint8_t reserved_5 : 4;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags4;
        
        sMacAddr& ruid();
        uint8_t* reserved_3(size_t idx = 0);
        bool set_reserved_3(const void* buffer, size_t size);
        sFlags4& flags();
        uint8_t& num_AP_STR_Records();
        std::tuple<bool, cAP_STR_Records&> AP_STR_Records(size_t idx);
        std::shared_ptr<cAP_STR_Records> create_AP_STR_Records();
        bool add_AP_STR_Records(std::shared_ptr<cAP_STR_Records> ptr);
        uint8_t& num_AP_NSTR_Records();
        std::tuple<bool, cAP_NSTR_Records&> AP_NSTR_Records(size_t idx);
        std::shared_ptr<cAP_NSTR_Records> create_AP_NSTR_Records();
        bool add_AP_NSTR_Records(std::shared_ptr<cAP_NSTR_Records> ptr);
        uint8_t& num_AP_EMLSR_Records();
        std::tuple<bool, cAP_EMLSR_Records&> AP_EMLSR_Records(size_t idx);
        std::shared_ptr<cAP_EMLSR_Records> create_AP_EMLSR_Records();
        bool add_AP_EMLSR_Records(std::shared_ptr<cAP_EMLSR_Records> ptr);
        uint8_t& num_AP_EMLMR_Records();
        std::tuple<bool, cAP_EMLMR_Records&> AP_EMLMR_Records(size_t idx);
        std::shared_ptr<cAP_EMLMR_Records> create_AP_EMLMR_Records();
        bool add_AP_EMLMR_Records(std::shared_ptr<cAP_EMLMR_Records> ptr);
        uint8_t& num_bSTA_STR_Records();
        std::tuple<bool, cBSTA_STR_Records&> bSTA_STR_Records(size_t idx);
        std::shared_ptr<cBSTA_STR_Records> create_bSTA_STR_Records();
        bool add_bSTA_STR_Records(std::shared_ptr<cBSTA_STR_Records> ptr);
        uint8_t& num_bSTA_NSTR_Records();
        std::tuple<bool, cBSTA_NSTR_Records&> bSTA_NSTR_Records(size_t idx);
        std::shared_ptr<cBSTA_NSTR_Records> create_bSTA_NSTR_Records();
        bool add_bSTA_NSTR_Records(std::shared_ptr<cBSTA_NSTR_Records> ptr);
        uint8_t& num_bSTA_EMLSR_Records();
        std::tuple<bool, cBSTA_EMLSR_Records&> bSTA_EMLSR_Records(size_t idx);
        std::shared_ptr<cBSTA_EMLSR_Records> create_bSTA_EMLSR_Records();
        bool add_bSTA_EMLSR_Records(std::shared_ptr<cBSTA_EMLSR_Records> ptr);
        uint8_t& num_bSTA_EMLMR_Records();
        std::tuple<bool, cBSTA_EMLMR_Records&> bSTA_EMLMR_Records(size_t idx);
        std::shared_ptr<cBSTA_EMLMR_Records> create_bSTA_EMLMR_Records();
        bool add_bSTA_EMLMR_Records(std::shared_ptr<cBSTA_EMLMR_Records> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_ruid = nullptr;
        uint8_t* m_reserved_3 = nullptr;
        size_t m_reserved_3_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sFlags4* m_flags = nullptr;
        uint8_t* m_num_AP_STR_Records = nullptr;
        cAP_STR_Records* m_AP_STR_Records = nullptr;
        size_t m_AP_STR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cAP_STR_Records>> m_AP_STR_Records_vector;
        bool m_lock_allocation__ = false;
        uint8_t* m_num_AP_NSTR_Records = nullptr;
        cAP_NSTR_Records* m_AP_NSTR_Records = nullptr;
        size_t m_AP_NSTR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cAP_NSTR_Records>> m_AP_NSTR_Records_vector;
        uint8_t* m_num_AP_EMLSR_Records = nullptr;
        cAP_EMLSR_Records* m_AP_EMLSR_Records = nullptr;
        size_t m_AP_EMLSR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cAP_EMLSR_Records>> m_AP_EMLSR_Records_vector;
        uint8_t* m_num_AP_EMLMR_Records = nullptr;
        cAP_EMLMR_Records* m_AP_EMLMR_Records = nullptr;
        size_t m_AP_EMLMR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cAP_EMLMR_Records>> m_AP_EMLMR_Records_vector;
        uint8_t* m_num_bSTA_STR_Records = nullptr;
        cBSTA_STR_Records* m_bSTA_STR_Records = nullptr;
        size_t m_bSTA_STR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cBSTA_STR_Records>> m_bSTA_STR_Records_vector;
        uint8_t* m_num_bSTA_NSTR_Records = nullptr;
        cBSTA_NSTR_Records* m_bSTA_NSTR_Records = nullptr;
        size_t m_bSTA_NSTR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cBSTA_NSTR_Records>> m_bSTA_NSTR_Records_vector;
        uint8_t* m_num_bSTA_EMLSR_Records = nullptr;
        cBSTA_EMLSR_Records* m_bSTA_EMLSR_Records = nullptr;
        size_t m_bSTA_EMLSR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cBSTA_EMLSR_Records>> m_bSTA_EMLSR_Records_vector;
        uint8_t* m_num_bSTA_EMLMR_Records = nullptr;
        cBSTA_EMLMR_Records* m_bSTA_EMLMR_Records = nullptr;
        size_t m_bSTA_EMLMR_Records_idx__ = 0;
        std::vector<std::shared_ptr<cBSTA_EMLMR_Records>> m_bSTA_EMLMR_Records_vector;
};

class cAP_STR_Records : public BaseClass
{
    public:
        cAP_STR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAP_STR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAP_STR_Records();

        typedef struct sFlags5 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_5 : 3;
            uint8_t AP_STR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t AP_STR_Freq_Separation : 5;
            uint8_t reserved_5 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags5;
        
        sMacAddr& AP_STR_RUID();
        sFlags5& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_AP_STR_RUID = nullptr;
        sFlags5* m_flags = nullptr;
};

class cAP_NSTR_Records : public BaseClass
{
    public:
        cAP_NSTR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAP_NSTR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAP_NSTR_Records();

        typedef struct sFlags6 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_6 : 3;
            uint8_t AP_NSTR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t AP_NSTR_Freq_Separation : 5;
            uint8_t reserved_6 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags6;
        
        sMacAddr& AP_NSTR_RUID();
        sFlags6& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_AP_NSTR_RUID = nullptr;
        sFlags6* m_flags = nullptr;
};

class cAP_EMLSR_Records : public BaseClass
{
    public:
        cAP_EMLSR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAP_EMLSR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAP_EMLSR_Records();

        typedef struct sFlags7 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_7 : 3;
            uint8_t AP_EMLSR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t AP_EMLSR_Freq_Separation : 5;
            uint8_t reserved_7 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags7;
        
        sMacAddr& AP_EMLSR_RUID();
        sFlags7& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_AP_EMLSR_RUID = nullptr;
        sFlags7* m_flags = nullptr;
};

class cAP_EMLMR_Records : public BaseClass
{
    public:
        cAP_EMLMR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cAP_EMLMR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cAP_EMLMR_Records();

        typedef struct sFlags8 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_8 : 3;
            uint8_t AP_EMLMR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t AP_EMLMR_Freq_Separation : 5;
            uint8_t reserved_8 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags8;
        
        sMacAddr& AP_EMLMR_RUID();
        sFlags8& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_AP_EMLMR_RUID = nullptr;
        sFlags8* m_flags = nullptr;
};

class cBSTA_STR_Records : public BaseClass
{
    public:
        cBSTA_STR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBSTA_STR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBSTA_STR_Records();

        typedef struct sFlags9 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_9 : 3;
            uint8_t bSTA_STR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bSTA_STR_Freq_Separation : 5;
            uint8_t reserved_9 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags9;
        
        sMacAddr& bSTA_STR_RUID();
        sFlags9& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bSTA_STR_RUID = nullptr;
        sFlags9* m_flags = nullptr;
};

class cBSTA_NSTR_Records : public BaseClass
{
    public:
        cBSTA_NSTR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBSTA_NSTR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBSTA_NSTR_Records();

        typedef struct sFlags10 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_10 : 3;
            uint8_t bSTA_NSTR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bSTA_NSTR_Freq_Separation : 5;
            uint8_t reserved_10 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags10;
        
        sMacAddr& bSTA_NSTR_RUID();
        sFlags10& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bSTA_NSTR_RUID = nullptr;
        sFlags10* m_flags = nullptr;
};

class cBSTA_EMLSR_Records : public BaseClass
{
    public:
        cBSTA_EMLSR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBSTA_EMLSR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBSTA_EMLSR_Records();

        typedef struct sFlags11 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_11 : 3;
            uint8_t bSTA_EMLSR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bSTA_EMLSR_Freq_Separation : 5;
            uint8_t reserved_11 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags11;
        
        sMacAddr& bSTA_EMLSR_RUID();
        sFlags11& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bSTA_EMLSR_RUID = nullptr;
        sFlags11* m_flags = nullptr;
};

class cBSTA_EMLMR_Records : public BaseClass
{
    public:
        cBSTA_EMLMR_Records(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cBSTA_EMLMR_Records(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cBSTA_EMLMR_Records();

        typedef struct sFlags12 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t reserved_12 : 3;
            uint8_t bSTA_EMLMR_Freq_Separation : 5;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t bSTA_EMLMR_Freq_Separation : 5;
            uint8_t reserved_12 : 3;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFlags12;
        
        sMacAddr& bSTA_EMLMR_RUID();
        sFlags12& flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_bSTA_EMLMR_RUID = nullptr;
        sFlags12* m_flags = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVWIFI7AGENTCAPABILITIES_H_
