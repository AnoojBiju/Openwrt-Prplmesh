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

#ifndef _TLVF_WEC_EWECLENGTHS_H_
#define _TLVF_WEC_EWECLENGTHS_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace WEC {

enum eWecLengths: uint16_t {
    WEC_MAC_LENGTH = 0x6,
    WEC_NONCE_LENGTH = 0x10,
    WEC_SHA256_LENGTH = 0x20,
    WEC_PUBLIC_PROTOCOL_KEY_LENGTH = 0x40,
    WEC_PUBLIC_PROTOCOL_KEY_COORDINATE_LENGTH = 0x20,
    WEC_PRIVATE_PROTOCOL_KEY_LENGTH = 0x20,
    WEC_ENCRYPTED_KEY_LENGTH = 0x40,
    WEC_CODE_IDENTIFIER_MAX_LENGTH = 0x50,
};


}; // close namespace: WEC

#endif //_TLVF/WEC_EWECLENGTHS_H_
