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

#ifndef _TLVF_WFA_MAP_ETLVTYPEMAP_H_
#define _TLVF_WFA_MAP_ETLVTYPEMAP_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <ostream>

namespace wfa_map {

enum class eTlvTypeMap : uint8_t {
    TLV_SUPPORTED_SERVICE = 0x80,
    TLV_SEARCHED_SERVICE = 0x81,
    TLV_AP_RADIO_IDENTIFIER = 0x82,
    TLV_AP_OPERATIONAL_BSS = 0x83,
    TLV_ASSOCIATED_CLIENTS = 0x84,
    TLV_AP_RADIO_BASIC_CAPABILITIES = 0x85,
    TLV_AP_HT_CAPABILITIES = 0x86,
    TLV_AP_VHT_CAPABILITIES = 0x87,
    TLV_AP_HE_CAPABILITIES = 0x88,
    TLV_STEERING_POLICY = 0x89,
    TLV_METRIC_REPORTING_POLICY = 0x8a,
    TLV_CHANNEL_PREFERENCE = 0x8b,
    TLV_RADIO_OPERATION_RESTRICTION = 0x8c,
    TLV_TRANSMIT_POWER_LIMIT = 0x8d,
    TLV_CHANNEL_SELECTION_RESPONSE = 0x8e,
    TLV_OPERATING_CHANNEL_REPORT = 0x8f,
    TLV_CLIENT_INFO = 0x90,
    TLV_CLIENT_CAPABILITY_REPORT = 0x91,
    TLV_CLIENT_ASSOCIATION_EVENT = 0x92,
    TLV_AP_METRIC_QUERY = 0x93,
    TLV_AP_METRIC = 0x94,
    TLV_STAMAC_ADDRESS_TYPE = 0x95,
    TLV_ASSOCIATED_STA_LINK_METRICS = 0x96,
    TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY = 0x97,
    TLV_UNASSOCIATED_STA_LINK_METRICS_RESPONSE = 0x98,
    TLV_BEACON_METRICS_QUERY = 0x99,
    TLV_BEACON_METRICS_RESPONSE = 0x9a,
    TLV_STEERING_REQUEST = 0x9b,
    TLV_STEERING_BTM_REPORT = 0x9c,
    TLV_CLIENT_ASSOCIATION_CONTROL_REQUEST = 0x9d,
    TLV_BACKHAUL_STEERING_REQUEST = 0x9e,
    TLV_BACKHAUL_STEERING_RESPONSE = 0x9f,
    TLV_HIGHER_LAYER_DATA = 0xa0,
    TLV_AP_CAPABILITY = 0xa1,
    TLV_ASSOCIATED_STA_TRAFFIC_STATS = 0xa2,
    TLV_ERROR_CODE = 0xa3,
    TLV_CHANNEL_SCAN_REPORTING_POLICY = 0xa4,
    TLV_CHANNEL_SCAN_CAPABILITIES = 0xa5,
    TLV_CHANNEL_SCAN_REQUEST = 0xa6,
    TLV_CHANNEL_SCAN_RESULT = 0xa7,
    TLV_TIMESTAMP = 0xa8,
    TLV_1905_LAYER_SECURITY_CAPABILITY = 0xa9,
    TLV_MIC = 0xab,
    TLV_ENCRYPTED_PAYLOAD = 0xac,
    TLV_PROFILE2_CAC_REQUEST = 0xad,
    TLV_PROFILE2_CAC_TERMINATION = 0xae,
    TLV_PROFILE2_CAC_COMPLETION_REPORT = 0xaf,
    TLV_ASSOCIATED_WIFI_6_STA_STATUS_REPORT = 0xb0,
    TLV_PROFILE2_CAC_STATUS_REPORT = 0xb1,
    TLV_PROFILE2_CAC_CAPABILITIES = 0xb2,
    TLV_PROFILE2_MULTIAP_PROFILE = 0xb3,
    TLV_PROFILE2_AP_CAPABILITY = 0xb4,
    TLV_PROFILE2_DEFAULT_802_1Q_SETTINGS = 0xb5,
    TLV_PROFILE2_TRAFFIC_SEPARATION_POLICY = 0xb6,
    TLV_BSS_CONFIGURATION_REPORT = 0xb7,
    TLV_SERVICE_PRIORITIZATION_RULE = 0xb9,
    TLV_DSCP_MAPPING_TABLE = 0xba,
    TLV_BSS_CONFIGURATION_REQUEST = 0xbb,
    TLV_PROFILE2_ERROR_CODE = 0xbc,
    TLV_BSS_CONFIGURATION_RESPONSE = 0xbd,
    TLV_PROFILE2_AP_RADIO_ADVANCED_CAPABILITIES = 0xbe,
    TLV_PROFILE2_ASSOCIATION_STATUS_NOTIFICATION = 0xbf,
    TLV_TUNNELLED_SOURCE_INFO = 0xc0,
    TLV_TUNNELLED_PROTOCOL_TYPE = 0xc1,
    TLV_TUNNELLED_DATA = 0xc2,
    TLV_PROFILE2_STEERING_REQUEST = 0xc3,
    TLV_PROFILE2_UNSUCCESSFUL_ASSOCIATION_POLICY = 0xc4,
    TLV_PROFILE2_METRIC_COLLECTION_INTERVAL = 0xc5,
    TLV_PROFILE2_RADIO_METRICS = 0xc6,
    TLV_AP_EXTENDED_METRICS = 0xc7,
    TLV_ASSOCIATED_STA_EXTENDED_LINK_METRICS = 0xc8,
    TLV_PROFILE2_STATUS_CODE = 0xc9,
    TLV_PROFILE2_REASON_CODE = 0xca,
    TLV_BACKHAUL_STA_RADIO_CAPABILITIES = 0xcb,
    TLV_AKM_SUITE_CAPABILITIES = 0xcc,
    TLV_1905_ENCAP_DPP = 0xcd,
    TLV_1905_ENCAP_EAPOL = 0xce,
    TLV_DPP_BOOTSTRAPPING_URI_NOTIFICATION = 0xcf,
    TLV_BACKHAUL_BSS_CONFIGURATION = 0xd0,
    TLV_DPP_MESSAGE = 0xd1,
    TLV_DPP_CCE_INDICATION = 0xd2,
    TLV_DPP_CHIRP_VALUE = 0xd3,
    TLV_DEVICE_INVENTORY = 0xd4,
    TLV_AGENT_LIST = 0xd5,
    TLV_TEAM_MEMBERS = 0xd6,
};
class eTlvTypeMapValidate {
public:
    static bool check(uint8_t value) {
        bool ret = false;
        switch (value) {
        case 0x80:
        case 0x81:
        case 0x82:
        case 0x83:
        case 0x84:
        case 0x85:
        case 0x86:
        case 0x87:
        case 0x88:
        case 0x89:
        case 0x8a:
        case 0x8b:
        case 0x8c:
        case 0x8d:
        case 0x8e:
        case 0x8f:
        case 0x90:
        case 0x91:
        case 0x92:
        case 0x93:
        case 0x94:
        case 0x95:
        case 0x96:
        case 0x97:
        case 0x98:
        case 0x99:
        case 0x9a:
        case 0x9b:
        case 0x9c:
        case 0x9d:
        case 0x9e:
        case 0x9f:
        case 0xa0:
        case 0xa1:
        case 0xa2:
        case 0xa3:
        case 0xa4:
        case 0xa5:
        case 0xa6:
        case 0xa7:
        case 0xa8:
        case 0xa9:
        case 0xab:
        case 0xac:
        case 0xad:
        case 0xae:
        case 0xaf:
        case 0xb0:
        case 0xb1:
        case 0xb2:
        case 0xb3:
        case 0xb4:
        case 0xb5:
        case 0xb6:
        case 0xb7:
        case 0xb9:
        case 0xba:
        case 0xbb:
        case 0xbc:
        case 0xbd:
        case 0xbe:
        case 0xbf:
        case 0xc0:
        case 0xc1:
        case 0xc2:
        case 0xc3:
        case 0xc4:
        case 0xc5:
        case 0xc6:
        case 0xc7:
        case 0xc8:
        case 0xc9:
        case 0xca:
        case 0xcb:
        case 0xcc:
        case 0xcd:
        case 0xce:
        case 0xcf:
        case 0xd0:
        case 0xd1:
        case 0xd2:
        case 0xd3:
        case 0xd4:
        case 0xd5:
        case 0xd6:
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

#endif //_TLVF/WFA_MAP_ETLVTYPEMAP_H_
