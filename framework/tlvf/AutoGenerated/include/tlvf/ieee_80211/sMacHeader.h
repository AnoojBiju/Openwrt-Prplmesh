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

#ifndef _TLVF_IEEE_80211_SMACHEADER_H_
#define _TLVF_IEEE_80211_SMACHEADER_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <asm/byteorder.h>
#include <ostream>
#include "tlvf/common/sMacAddr.h"

namespace ieee80211 {


class sMacHeader : public BaseClass
{
    public:
        sMacHeader(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit sMacHeader(std::shared_ptr<BaseClass> base, bool parse = false);
        ~sMacHeader();

        typedef struct sFrameControlB1 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t protocol_version : 2;
            uint8_t type : 2;
            uint8_t subtype : 4;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t subtype : 4;
            uint8_t type : 2;
            uint8_t protocol_version : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFrameControlB1;
        
        typedef struct sFrameControlB2 {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t unused : 8;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t unused : 8;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sFrameControlB2;
        
        enum class eType : uint8_t {
            MGMT = 0x0,
            CTRL = 0x1,
            DATA = 0x2,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eType_str(eType enum_value) {
            switch (enum_value) {
            case eType::MGMT: return "eType::MGMT";
            case eType::CTRL: return "eType::CTRL";
            case eType::DATA: return "eType::DATA";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eType value) { return out << eType_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        class eTypeValidate {
        public:
            static bool check(uint8_t value) {
                bool ret = false;
                switch (value) {
                case 0x0:
                case 0x1:
                case 0x2:
                        ret = true;
                        break;
                    default:
                        ret = false;
                        break;
                }
                return ret;
            }
        };
        
        enum class eSubtypeMgmt : uint8_t {
            ASSOC_REQ = 0x0,
            ASSOC_RESP = 0x1,
            REASSOC_REQ = 0x2,
            REASSOC_RESP = 0x3,
            PROBE_REQ = 0x4,
            PROBE_RESP = 0x5,
            BEACON = 0x8,
            ATIM = 0x9,
            DISASSOC = 0xa,
            AUTH = 0xb,
            DEAUTH = 0xc,
            ACTION = 0xd,
            ACTION_NO_ACK = 0xe,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eSubtypeMgmt_str(eSubtypeMgmt enum_value) {
            switch (enum_value) {
            case eSubtypeMgmt::ASSOC_REQ:     return "eSubtypeMgmt::ASSOC_REQ";
            case eSubtypeMgmt::ASSOC_RESP:    return "eSubtypeMgmt::ASSOC_RESP";
            case eSubtypeMgmt::REASSOC_REQ:   return "eSubtypeMgmt::REASSOC_REQ";
            case eSubtypeMgmt::REASSOC_RESP:  return "eSubtypeMgmt::REASSOC_RESP";
            case eSubtypeMgmt::PROBE_REQ:     return "eSubtypeMgmt::PROBE_REQ";
            case eSubtypeMgmt::PROBE_RESP:    return "eSubtypeMgmt::PROBE_RESP";
            case eSubtypeMgmt::BEACON:        return "eSubtypeMgmt::BEACON";
            case eSubtypeMgmt::ATIM:          return "eSubtypeMgmt::ATIM";
            case eSubtypeMgmt::DISASSOC:      return "eSubtypeMgmt::DISASSOC";
            case eSubtypeMgmt::AUTH:          return "eSubtypeMgmt::AUTH";
            case eSubtypeMgmt::DEAUTH:        return "eSubtypeMgmt::DEAUTH";
            case eSubtypeMgmt::ACTION:        return "eSubtypeMgmt::ACTION";
            case eSubtypeMgmt::ACTION_NO_ACK: return "eSubtypeMgmt::ACTION_NO_ACK";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eSubtypeMgmt value) { return out << eSubtypeMgmt_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        class eSubtypeMgmtValidate {
        public:
            static bool check(uint8_t value) {
                bool ret = false;
                switch (value) {
                case 0x0:
                case 0x1:
                case 0x2:
                case 0x3:
                case 0x4:
                case 0x5:
                case 0x8:
                case 0x9:
                case 0xa:
                case 0xb:
                case 0xc:
                case 0xd:
                case 0xe:
                        ret = true;
                        break;
                    default:
                        ret = false;
                        break;
                }
                return ret;
            }
        };
        
        enum class eSubtypeCtrl : uint8_t {
            PSPOLL = 0xa,
            RTS = 0xb,
            CTS = 0xc,
            ACK = 0xd,
            CFEND = 0xe,
            CFENDACK = 0xf,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eSubtypeCtrl_str(eSubtypeCtrl enum_value) {
            switch (enum_value) {
            case eSubtypeCtrl::PSPOLL:   return "eSubtypeCtrl::PSPOLL";
            case eSubtypeCtrl::RTS:      return "eSubtypeCtrl::RTS";
            case eSubtypeCtrl::CTS:      return "eSubtypeCtrl::CTS";
            case eSubtypeCtrl::ACK:      return "eSubtypeCtrl::ACK";
            case eSubtypeCtrl::CFEND:    return "eSubtypeCtrl::CFEND";
            case eSubtypeCtrl::CFENDACK: return "eSubtypeCtrl::CFENDACK";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eSubtypeCtrl value) { return out << eSubtypeCtrl_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        class eSubtypeCtrlValidate {
        public:
            static bool check(uint8_t value) {
                bool ret = false;
                switch (value) {
                case 0xa:
                case 0xb:
                case 0xc:
                case 0xd:
                case 0xe:
                case 0xf:
                        ret = true;
                        break;
                    default:
                        ret = false;
                        break;
                }
                return ret;
            }
        };
        
        enum class eSubtypeData : uint8_t {
            DATA = 0x0,
            DATA_CFACK = 0x1,
            DATA_CFPOLL = 0x2,
            DATA_CFACKPOLL = 0x3,
            NULLFUNC = 0x4,
            CFACK = 0x5,
            CFPOLL = 0x6,
            CFACKPOLL = 0x7,
            QOS_DATA = 0x8,
            QOS_DATA_CFACK = 0x9,
            QOS_DATA_CFPOLL = 0xa,
            QOS_DATA_CFACKPOLL = 0xb,
            QOS_NULL = 0xc,
            QOS_CFPOLL = 0xe,
            QOS_CFACKPOLL = 0xf,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eSubtypeData_str(eSubtypeData enum_value) {
            switch (enum_value) {
            case eSubtypeData::DATA:               return "eSubtypeData::DATA";
            case eSubtypeData::DATA_CFACK:         return "eSubtypeData::DATA_CFACK";
            case eSubtypeData::DATA_CFPOLL:        return "eSubtypeData::DATA_CFPOLL";
            case eSubtypeData::DATA_CFACKPOLL:     return "eSubtypeData::DATA_CFACKPOLL";
            case eSubtypeData::NULLFUNC:           return "eSubtypeData::NULLFUNC";
            case eSubtypeData::CFACK:              return "eSubtypeData::CFACK";
            case eSubtypeData::CFPOLL:             return "eSubtypeData::CFPOLL";
            case eSubtypeData::CFACKPOLL:          return "eSubtypeData::CFACKPOLL";
            case eSubtypeData::QOS_DATA:           return "eSubtypeData::QOS_DATA";
            case eSubtypeData::QOS_DATA_CFACK:     return "eSubtypeData::QOS_DATA_CFACK";
            case eSubtypeData::QOS_DATA_CFPOLL:    return "eSubtypeData::QOS_DATA_CFPOLL";
            case eSubtypeData::QOS_DATA_CFACKPOLL: return "eSubtypeData::QOS_DATA_CFACKPOLL";
            case eSubtypeData::QOS_NULL:           return "eSubtypeData::QOS_NULL";
            case eSubtypeData::QOS_CFPOLL:         return "eSubtypeData::QOS_CFPOLL";
            case eSubtypeData::QOS_CFACKPOLL:      return "eSubtypeData::QOS_CFACKPOLL";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eSubtypeData value) { return out << eSubtypeData_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        class eSubtypeDataValidate {
        public:
            static bool check(uint8_t value) {
                bool ret = false;
                switch (value) {
                case 0x0:
                case 0x1:
                case 0x2:
                case 0x3:
                case 0x4:
                case 0x5:
                case 0x6:
                case 0x7:
                case 0x8:
                case 0x9:
                case 0xa:
                case 0xb:
                case 0xc:
                case 0xe:
                case 0xf:
                        ret = true;
                        break;
                    default:
                        ret = false;
                        break;
                }
                return ret;
            }
        };
        
        sFrameControlB1& frame_control_b1();
        sFrameControlB2& frame_control_b2();
        uint16_t& duration_id();
        sMacAddr& addr1();
        sMacAddr& addr2();
        sMacAddr& addr3();
        uint16_t& seq_ctrl();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sFrameControlB1* m_frame_control_b1 = nullptr;
        sFrameControlB2* m_frame_control_b2 = nullptr;
        uint16_t* m_duration_id = nullptr;
        sMacAddr* m_addr1 = nullptr;
        sMacAddr* m_addr2 = nullptr;
        sMacAddr* m_addr3 = nullptr;
        uint16_t* m_seq_ctrl = nullptr;
};

}; // close namespace: ieee80211

#endif //_TLVF/IEEE_80211_SMACHEADER_H_
