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

#ifndef _TLVF_ASSOCIATION_FRAME_EELEMENTID_H_
#define _TLVF_ASSOCIATION_FRAME_EELEMENTID_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>
enum eElementID: uint8_t {
    ID_SSID = 0x0,
    ID_SUPPORT_RATES = 0x1,
    ID_EDCA_PARAM_SET = 0xc,
    ID_POWER_CAPABILITY = 0x21,
    ID_SUP_CHANNELS = 0x24,
    ID_HT_CAPABILITY = 0x2d,
    ID_QOS_CAPABILITY = 0x2e,
    ID_RSN = 0x30,
    ID_EXTENDED_SUP_RATES = 0x32,
    ID_MOBILITY_DOMAIN = 0x36,
    ID_FAST_BSS_TRANS = 0x37,
    ID_SUP_OP_CLASSES = 0x3b,
    ID_RM_ENABLED_CAPS = 0x46,
    ID_BSS_COEXISTENCE20_40 = 0x48,
    ID_RIC = 0x4b,
    ID_FMS_REQUEST = 0x57,
    ID_QOS_TRAFFIC_CAP = 0x59,
    ID_TIM_BROADCAST_REQUEST = 0x5e,
    ID_DMS_REQUEST = 0x63,
    ID_INTERWORKING = 0x6b,
    ID_EXTENDED_CAPABILITY = 0x7f,
    ID_MULTI_BAND = 0x9e,
    ID_MMS = 0xaa,
    ID_VHT_CAPS = 0xbf,
    ID_DMG_CAPS = 0xc2,
    ID_OP_MODE_NOTIFICATION = 0xc7,
    ID_VENDOR_SPECIFIC = 0xdd,
};


#endif //_TLVF/ASSOCIATION_FRAME_EELEMENTID_H_
