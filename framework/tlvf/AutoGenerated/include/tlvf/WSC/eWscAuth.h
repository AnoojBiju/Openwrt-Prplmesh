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

#ifndef _TLVF_WSC_EWSCAUTH_H_
#define _TLVF_WSC_EWSCAUTH_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace WSC {

enum eWscAuth: uint16_t {
    WSC_AUTH_OPEN = 0x1,
    WSC_AUTH_WPAPSK = 0x2,
    WSC_AUTH_SHARED = 0x4,
    WSC_AUTH_WPA = 0x8,
    WSC_AUTH_WPA2 = 0x10,
    WSC_AUTH_WPA2PSK = 0x20,
    WSC_AUTH_SAE = 0x40,
    WSC_AUTH_INVALID = 0xffff,
};


}; // close namespace: WSC

#endif //_TLVF/WSC_EWSCAUTH_H_
