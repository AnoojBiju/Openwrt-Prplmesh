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

#ifndef _TLVF_WEC_EWECCONNECTORKEY_H_
#define _TLVF_WEC_EWECCONNECTORKEY_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace WSC {

enum eWecConnectorKey: uint8_t {
    CONFIG_REUSEKEY = 0x0,
    CONFIG_REPLACEKEY = 0x1,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWecConnectorKey_str(eWecConnectorKey enum_value) {
    switch (enum_value) {
    case CONFIG_REUSEKEY:   return "CONFIG_REUSEKEY";
    case CONFIG_REPLACEKEY: return "CONFIG_REPLACEKEY";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWecConnectorKey value) { return out << eWecConnectorKey_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end


}; // close namespace: WSC

#endif //_TLVF/WEC_EWECCONNECTORKEY_H_
