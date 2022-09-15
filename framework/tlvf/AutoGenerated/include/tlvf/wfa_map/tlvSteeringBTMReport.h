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

#ifndef _TLVF_WFA_MAP_TLVSTEERINGBTMREPORT_H_
#define _TLVF_WFA_MAP_TLVSTEERINGBTMREPORT_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"
#include <ostream>

namespace wfa_map {


class tlvSteeringBTMReport : public BaseClass
{
    public:
        tlvSteeringBTMReport(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvSteeringBTMReport(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvSteeringBTMReport();

        enum eBTMStatusCode: uint8_t {
            ACCEPT = 0x0,
            REJECT_UNSPECIFIED = 0x1,
            REJECT_INSUFFICIENT_BEACON_RESPONSES = 0x2,
            REJECT_INSUFFICIENT_CAPACITY = 0x3,
            REJECT_BSS_TERMINATION_NOT_DESIRED = 0x4,
            REJECT_BSS_TERMINATION_REQUEST_DELAY = 0x5,
            REJECT_STA_BSS_CANDIDATE_LIST_PROVIDED = 0x6,
            REJECT_NO_SUITABLE_CANDIDATES = 0x7,
            REJECT_LEAVING_ESS = 0x8,
            REJECT_RESERVED = 0x9,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eBTMStatusCode_str(eBTMStatusCode enum_value) {
            switch (enum_value) {
            case ACCEPT:                                 return "ACCEPT";
            case REJECT_UNSPECIFIED:                     return "REJECT_UNSPECIFIED";
            case REJECT_INSUFFICIENT_BEACON_RESPONSES:   return "REJECT_INSUFFICIENT_BEACON_RESPONSES";
            case REJECT_INSUFFICIENT_CAPACITY:           return "REJECT_INSUFFICIENT_CAPACITY";
            case REJECT_BSS_TERMINATION_NOT_DESIRED:     return "REJECT_BSS_TERMINATION_NOT_DESIRED";
            case REJECT_BSS_TERMINATION_REQUEST_DELAY:   return "REJECT_BSS_TERMINATION_REQUEST_DELAY";
            case REJECT_STA_BSS_CANDIDATE_LIST_PROVIDED: return "REJECT_STA_BSS_CANDIDATE_LIST_PROVIDED";
            case REJECT_NO_SUITABLE_CANDIDATES:          return "REJECT_NO_SUITABLE_CANDIDATES";
            case REJECT_LEAVING_ESS:                     return "REJECT_LEAVING_ESS";
            case REJECT_RESERVED:                        return "REJECT_RESERVED";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eBTMStatusCode value) { return out << eBTMStatusCode_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        sMacAddr& bssid();
        sMacAddr& sta_mac();
        eBTMStatusCode& btm_status_code();
        bool alloc_target_bssid();
        sMacAddr* target_bssid();
        bool set_target_bssid(const sMacAddr target_bssid);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_bssid = nullptr;
        sMacAddr* m_sta_mac = nullptr;
        eBTMStatusCode* m_btm_status_code = nullptr;
        sMacAddr* m_target_bssid = nullptr;
        bool m_target_bssid_allocated = false;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVSTEERINGBTMREPORT_H_
