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

#ifndef _TLVF_WFA_MAP_EVIRTUALBSSSUBTYPE_H_
#define _TLVF_WFA_MAP_EVIRTUALBSSSUBTYPE_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace wfa_map {

enum class eVirtualBssSubtype : uint16_t {
    AP_RADIO_VBSS_CAPABILITIES = 0x1,
    VIRTUAL_BSS_CREATION = 0x2,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eVirtualBssSubtype_str(eVirtualBssSubtype enum_value) {
    switch (enum_value) {
    case eVirtualBssSubtype::AP_RADIO_VBSS_CAPABILITIES: return "eVirtualBssSubtype::AP_RADIO_VBSS_CAPABILITIES";
    case eVirtualBssSubtype::VIRTUAL_BSS_CREATION:       return "eVirtualBssSubtype::VIRTUAL_BSS_CREATION";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eVirtualBssSubtype value) { return out << eVirtualBssSubtype_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end
class eVirtualBssSubtypeValidate {
public:
    static bool check(uint16_t value) {
        bool ret = false;
        switch (value) {
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


}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_EVIRTUALBSSSUBTYPE_H_
