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

#ifndef _TLVF_WEC_EWECDPPATTRIBUTES_H_
#define _TLVF_WEC_EWECDPPATTRIBUTES_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace WEC {

enum eWecDppAttributes: uint16_t {
    ATTR_DPP_STATUS = 0x1000,
    ATTR_INITIATOR_BOOTSTRAPPING_KEY_HASH = 0x1001,
    ATTR_RESPONDER_BOOTSTRAPPING_KEY_HASH = 0x1002,
    ATTR_INITIATOR_PROTOCOL_KEY = 0x1003,
    ATTR_WRAPPED_DATA = 0x1004,
    ATTR_INITIATOR_NONCE = 0x1005,
    ATTR_INITIATOR_CAPABILITIES = 0x1006,
    ATTR_RESPONDER_NONCE = 0x1007,
    ATTR_RESPONDER_CAPABILITIES = 0x1008,
    ATTR_RESPONDER_PROTOCOL_KEY = 0x1009,
    ATTR_INITIATOR_AUTHENTICATING_TAG = 0x100a,
    ATTR_RESPONDER_AUTHENTICATING_TAG = 0x100b,
    ATTR_DPP_CONFIGURATION_OBJECT = 0x100c,
    ATTR_DPP_CONNECTOR = 0x100d,
    ATTR_DPP_CONFIGURATION_REQUEST_OBJECT = 0x100e,
    ATTR_BOOTSTRAPPING_KEY = 0x100f,
    ATTR_FINITE_CYCLIC_GROUP = 0x1012,
    ATTR_ENCRYPTED_KEY = 0x1013,
    ATTR_ENROLLEE_NONCE = 0x1014,
    ATTR_CODE_IDENTIFIER = 0x1015,
    ATTR_TRANSACTION_ID = 0x1016,
    ATTR_BOOTSTRAPPING_INFO = 0x1017,
    ATTR_CHANNEL = 0x1018,
    ATTR_PROTOCOL_VERSION = 0x1019,
    ATTR_DPP_ENVELOPED_DATA = 0x101a,
    ATTR_SEND_CONN_STATUS = 0x101b,
    ATTR_CONN_STATUS_OBJECT = 0x101c,
    ATTR_RECONFIGURATION_FLAGS = 0x101d,
    ATTR_C_SIGN_KEY_HASH = 0x101e,
    ATTR_A_NONCE = 0x1020,
    ATTR_E_TAG_ID = 0x1021,
    ATTR_CONFIGURATOR_NONCE = 0x1022,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWecDppAttributes_str(eWecDppAttributes enum_value) {
    switch (enum_value) {
    case ATTR_DPP_STATUS:                       return "ATTR_DPP_STATUS";
    case ATTR_INITIATOR_BOOTSTRAPPING_KEY_HASH: return "ATTR_INITIATOR_BOOTSTRAPPING_KEY_HASH";
    case ATTR_RESPONDER_BOOTSTRAPPING_KEY_HASH: return "ATTR_RESPONDER_BOOTSTRAPPING_KEY_HASH";
    case ATTR_INITIATOR_PROTOCOL_KEY:           return "ATTR_INITIATOR_PROTOCOL_KEY";
    case ATTR_WRAPPED_DATA:                     return "ATTR_WRAPPED_DATA";
    case ATTR_INITIATOR_NONCE:                  return "ATTR_INITIATOR_NONCE";
    case ATTR_INITIATOR_CAPABILITIES:           return "ATTR_INITIATOR_CAPABILITIES";
    case ATTR_RESPONDER_NONCE:                  return "ATTR_RESPONDER_NONCE";
    case ATTR_RESPONDER_CAPABILITIES:           return "ATTR_RESPONDER_CAPABILITIES";
    case ATTR_RESPONDER_PROTOCOL_KEY:           return "ATTR_RESPONDER_PROTOCOL_KEY";
    case ATTR_INITIATOR_AUTHENTICATING_TAG:     return "ATTR_INITIATOR_AUTHENTICATING_TAG";
    case ATTR_RESPONDER_AUTHENTICATING_TAG:     return "ATTR_RESPONDER_AUTHENTICATING_TAG";
    case ATTR_DPP_CONFIGURATION_OBJECT:         return "ATTR_DPP_CONFIGURATION_OBJECT";
    case ATTR_DPP_CONNECTOR:                    return "ATTR_DPP_CONNECTOR";
    case ATTR_DPP_CONFIGURATION_REQUEST_OBJECT: return "ATTR_DPP_CONFIGURATION_REQUEST_OBJECT";
    case ATTR_BOOTSTRAPPING_KEY:                return "ATTR_BOOTSTRAPPING_KEY";
    case ATTR_FINITE_CYCLIC_GROUP:              return "ATTR_FINITE_CYCLIC_GROUP";
    case ATTR_ENCRYPTED_KEY:                    return "ATTR_ENCRYPTED_KEY";
    case ATTR_ENROLLEE_NONCE:                   return "ATTR_ENROLLEE_NONCE";
    case ATTR_CODE_IDENTIFIER:                  return "ATTR_CODE_IDENTIFIER";
    case ATTR_TRANSACTION_ID:                   return "ATTR_TRANSACTION_ID";
    case ATTR_BOOTSTRAPPING_INFO:               return "ATTR_BOOTSTRAPPING_INFO";
    case ATTR_CHANNEL:                          return "ATTR_CHANNEL";
    case ATTR_PROTOCOL_VERSION:                 return "ATTR_PROTOCOL_VERSION";
    case ATTR_DPP_ENVELOPED_DATA:               return "ATTR_DPP_ENVELOPED_DATA";
    case ATTR_SEND_CONN_STATUS:                 return "ATTR_SEND_CONN_STATUS";
    case ATTR_CONN_STATUS_OBJECT:               return "ATTR_CONN_STATUS_OBJECT";
    case ATTR_RECONFIGURATION_FLAGS:            return "ATTR_RECONFIGURATION_FLAGS";
    case ATTR_C_SIGN_KEY_HASH:                  return "ATTR_C_SIGN_KEY_HASH";
    case ATTR_A_NONCE:                          return "ATTR_A_NONCE";
    case ATTR_E_TAG_ID:                         return "ATTR_E_TAG_ID";
    case ATTR_CONFIGURATOR_NONCE:               return "ATTR_CONFIGURATOR_NONCE";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWecDppAttributes value) { return out << eWecDppAttributes_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end


}; // close namespace: WEC

#endif //_TLVF/WEC_EWECDPPATTRIBUTES_H_
