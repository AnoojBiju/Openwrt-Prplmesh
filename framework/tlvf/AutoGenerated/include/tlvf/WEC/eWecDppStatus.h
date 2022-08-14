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

#ifndef _TLVF_WEC_EWECDPPSTATUS_H_
#define _TLVF_WEC_EWECDPPSTATUS_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace WEC {

enum eWecDppStatus: uint8_t {
    STATUS_OK = 0x0,
    STATUS_NOT_COMPATIBLE = 0x1,
    STATUS_AUTH_FAILURE = 0x2,
    STATUS_BAD_CODE = 0x3,
    STATUS_BAD_GROUP = 0x4,
    STATUS_CONFIGURE_FAILURE = 0x4,
    STATUS_RESPONSE_PENDING = 0x6,
    STATUS_INVALID_CONNECTOR = 0x7,
    STATUS_NO_MATCH = 0x8,
    STATUS_CONFIG_REJECTED = 0x9,
    STATUS_NO_AP = 0xa,
    STATUS_CONFIGURE_PENDING = 0xb,
    STATUS_CSR_NEEDED = 0xc,
    STATUS_CSR_BAD = 0xd,
    STATUS_NEW_KEY_NEEDED = 0xe,
};


}; // close namespace: WEC

#endif //_TLVF/WEC_EWECDPPSTATUS_H_
