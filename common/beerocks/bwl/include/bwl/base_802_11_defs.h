/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_802_11_DEFS_H_
#define _BWL_802_11_DEFS_H_

#include <iostream>
#include <stdint.h>
#include <tlvf/common/sMacAddr.h>

namespace bwl {

/**
 * @brief 802.11 management frame
 * More info here: https://en.wikipedia.org/wiki/802.11_Frame_Types
 */
struct s80211MgmtFrame {

    /**
     * @brief Management frame types
     */
    enum class eType : uint8_t {
        ASSOC_REQ    = 0,  /*<< Association Request */
        ASSOC_RESP   = 1,  /*<< Association Response */
        REASSOC_REQ  = 2,  /*<< Re-association Request */
        REASSOC_RESP = 3,  /*<< Re-association Response */
        PROBE_REQ    = 4,  /*<< Probe Request */
        PROBE_RESP   = 5,  /*<< Probe Response */
        BEACON       = 8,  /*<< Beacon */
        ATIM         = 9,  /*<< Announcement Traffic Indication Message */
        DISASSOC     = 10, /*<< Disassociation */
        AUTH         = 11, /*<< Authentication */
        DEAUTH       = 12, /*<< De-authentication */
        ACTION       = 13  /*<< Action */
    };
    // Enum AutoPrint generated code snippet begining- DON'T EDIT!
    // clang-format off
    static const char *eType_str(eType enum_value) {
        switch (enum_value) {
        case eType::ASSOC_REQ:    return "eType::ASSOC_REQ";
        case eType::ASSOC_RESP:   return "eType::ASSOC_RESP";
        case eType::REASSOC_REQ:  return "eType::REASSOC_REQ";
        case eType::REASSOC_RESP: return "eType::REASSOC_RESP";
        case eType::PROBE_REQ:    return "eType::PROBE_REQ";
        case eType::PROBE_RESP:   return "eType::PROBE_RESP";
        case eType::BEACON:       return "eType::BEACON";
        case eType::ATIM:         return "eType::ATIM";
        case eType::DISASSOC:     return "eType::DISASSOC";
        case eType::AUTH:         return "eType::AUTH";
        case eType::DEAUTH:       return "eType::DEAUTH";
        case eType::ACTION:       return "eType::ACTION";
        }
        static std::string out_str = std::to_string(int(enum_value));
        return out_str.c_str();
    }
    friend inline std::ostream &operator<<(std::ostream &out, eType value) { return out << eType_str(value); }
    // clang-format on
    // Enum AutoPrint generated code snippet end

    // Header
    struct sHeader {
        // Frame Control
        union uFrameControl {
            uint16_t val; // Raw 16-bit value

            // Bitfield
            struct sFrameControl {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                uint16_t protocol_version : 2; // Protocol version (currently is 0)
                uint16_t type : 2;             // Frame type (00 - Mgmt, 01 - Control, 10 - Data)
                uint16_t subtype : 4;          // Frame subtype (e.g. Assoc Req, Action etc.)
                uint16_t to_ds : 1;            // If destined to Distribution System
                uint16_t from_ds : 1;          // If originated from Distribution System
                uint16_t more_fragments : 1;   // If the frame is fragmented
                uint16_t retry : 1;            // Retransmission of the earlier frame
                uint16_t power_mgmt : 1;       // If power management is enabled
                uint16_t more_data : 1;        // TBD
                uint16_t protected_frame : 1;  // If the data is encrypted
                uint16_t order : 1;            // QoS
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                uint16_t subtype : 4;          // Frame subtype (e.g. Assoc Req, Action etc.)
                uint16_t type : 2;             // Frame type (00 - Mgmt, 01 - Control, 10 - Data)
                uint16_t protocol_version : 2; // Protocol version (currently is 0)
                uint16_t order : 1;            // QoS
                uint16_t protected_frame : 1;  // If the data is encrypted
                uint16_t more_data : 1;        // TBD
                uint16_t power_mgmt : 1;       // If power management is enabled
                uint16_t retry : 1;            // Retransmission of the earlier frame
                uint16_t more_fragments : 1;   // If the frame is fragmented
                uint16_t from_ds : 1;          // If originated from Distribution System
                uint16_t to_ds : 1;            // If destined to Distribution System
#endif
            } __attribute__((packed)) bits;
        } __attribute__((packed)) frame_control;

        uint16_t duration; // Duration / ID
        sMacAddr da;       // Destination MAC Address
        sMacAddr sa;       // Source MAC Address
        sMacAddr bssid;    // BSSID (AP MAC Address)
        uint16_t seq_ctrl; // Sequence number

    } __attribute__((packed)) header;

    union uBody {
        // Action Frame
        struct sAction {
            /**
             * @brief Action frame categories (IEEE Std 802.11-2016, 9.4.1.11, Table 9-76) 
             */
            enum class eCategory {
                SPECTRUM_MGMT             = 0,
                QOS                       = 1,
                DLS                       = 2,
                BLOCK_ACK                 = 3,
                PUBLIC                    = 4,
                RADIO_MEASUREMENT         = 5,
                FT                        = 6,
                HT                        = 7,
                SA_QUERY                  = 8,
                PROTECTED_DUAL            = 9,
                WNM                       = 10,
                UNPROTECTED_WNM           = 11,
                TDLS                      = 12,
                MESH                      = 13,
                MULTIHOP                  = 14,
                SELF_PROTECTED            = 15,
                DMG                       = 16,
                WMM                       = 17,
                FST                       = 18,
                ROBUST_AV_STREAMING       = 19,
                UNPROTECTED_DMG           = 20,
                VHT                       = 21,
                FILS                      = 26,
                VENDOR_SPECIFIC_PROTECTED = 126,
                VENDOR_SPECIFIC           = 127
                /* Note: 128-255 used to report errors by setting category | 0x80 */
            };
            // Enum AutoPrint generated code snippet begining- DON'T EDIT!
            // clang-format off
            static const char *eCategory_str(eCategory enum_value) {
                switch (enum_value) {
                case eCategory::SPECTRUM_MGMT:             return "eCategory::SPECTRUM_MGMT";
                case eCategory::QOS:                       return "eCategory::QOS";
                case eCategory::DLS:                       return "eCategory::DLS";
                case eCategory::BLOCK_ACK:                 return "eCategory::BLOCK_ACK";
                case eCategory::PUBLIC:                    return "eCategory::PUBLIC";
                case eCategory::RADIO_MEASUREMENT:         return "eCategory::RADIO_MEASUREMENT";
                case eCategory::FT:                        return "eCategory::FT";
                case eCategory::HT:                        return "eCategory::HT";
                case eCategory::SA_QUERY:                  return "eCategory::SA_QUERY";
                case eCategory::PROTECTED_DUAL:            return "eCategory::PROTECTED_DUAL";
                case eCategory::WNM:                       return "eCategory::WNM";
                case eCategory::UNPROTECTED_WNM:           return "eCategory::UNPROTECTED_WNM";
                case eCategory::TDLS:                      return "eCategory::TDLS";
                case eCategory::MESH:                      return "eCategory::MESH";
                case eCategory::MULTIHOP:                  return "eCategory::MULTIHOP";
                case eCategory::SELF_PROTECTED:            return "eCategory::SELF_PROTECTED";
                case eCategory::DMG:                       return "eCategory::DMG";
                case eCategory::WMM:                       return "eCategory::WMM";
                case eCategory::FST:                       return "eCategory::FST";
                case eCategory::ROBUST_AV_STREAMING:       return "eCategory::ROBUST_AV_STREAMING";
                case eCategory::UNPROTECTED_DMG:           return "eCategory::UNPROTECTED_DMG";
                case eCategory::VHT:                       return "eCategory::VHT";
                case eCategory::FILS:                      return "eCategory::FILS";
                case eCategory::VENDOR_SPECIFIC_PROTECTED: return "eCategory::VENDOR_SPECIFIC_PROTECTED";
                case eCategory::VENDOR_SPECIFIC:           return "eCategory::VENDOR_SPECIFIC";
                }
                static std::string out_str = std::to_string(int(enum_value));
                return out_str.c_str();
            }
            friend inline std::ostream &operator<<(std::ostream &out, eCategory value) { return out << eCategory_str(value); }
            // clang-format on
            // Enum AutoPrint generated code snippet end

            /**
             * @brief 802.11 action frame codes
             * Listing only the codes that are currently used by prplMesh
             */
            enum class eCode {
                WNM_BSS_TRANS_MGMT_QUERY = 6,  /**< WNM BTM Query (WNM Category [10]) */
                ANQP_REQ                 = 10, /**< ANQP Request (Public Category [4]) */
                WNM_NOTIFICATION_REQ     = 26  /**< WNM Notification Request (WNM Category [10]) */
            };
            // Enum AutoPrint generated code snippet begining- DON'T EDIT!
            // clang-format off
            static const char *eCode_str(eCode enum_value) {
                switch (enum_value) {
                case eCode::WNM_BSS_TRANS_MGMT_QUERY: return "eCode::WNM_BSS_TRANS_MGMT_QUERY";
                case eCode::ANQP_REQ:                 return "eCode::ANQP_REQ";
                case eCode::WNM_NOTIFICATION_REQ:     return "eCode::WNM_NOTIFICATION_REQ";
                }
                static std::string out_str = std::to_string(int(enum_value));
                return out_str.c_str();
            }
            friend inline std::ostream &operator<<(std::ostream &out, eCode value) { return out << eCode_str(value); }
            // clang-format on
            // Enum AutoPrint generated code snippet end

            uint8_t category; // Action frame category
            uint8_t code;     // Action frame code

        } __attribute__((packed)) action;
    } __attribute__((packed)) body;
} __attribute__((packed));

/*
 * @brief channel width number from the standard IEEE 802.11-2020
 * (Table 9-175 HT/VHT Operation Information subfields).
 * (values 5-255 are reserved)
 */
enum eChanWidthNr : uint8_t {
    NR_CHAN_WIDTH_20    = 0,
    NR_CHAN_WIDTH_40    = 1,
    NR_CHAN_WIDTH_80    = 2,
    NR_CHAN_WIDTH_160   = 3,
    NR_CHAN_WIDTH_80P80 = 4,
    NR_CHAN_WIDTH_MAX,
    NR_CHAN_WIDTH_UNKNOWN = 0xFF,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eChanWidthNr_str(eChanWidthNr enum_value) {
    switch (enum_value) {
    case NR_CHAN_WIDTH_20:      return "NR_CHAN_WIDTH_20";
    case NR_CHAN_WIDTH_40:      return "NR_CHAN_WIDTH_40";
    case NR_CHAN_WIDTH_80:      return "NR_CHAN_WIDTH_80";
    case NR_CHAN_WIDTH_160:     return "NR_CHAN_WIDTH_160";
    case NR_CHAN_WIDTH_80P80:   return "NR_CHAN_WIDTH_80P80";
    case NR_CHAN_WIDTH_MAX:     return "NR_CHAN_WIDTH_MAX";
    case NR_CHAN_WIDTH_UNKNOWN: return "NR_CHAN_WIDTH_UNKNOWN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eChanWidthNr value) { return out << eChanWidthNr_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

#define BIT(x) (1U << (x))

/* HT Capabilities Info field within HT Capabilities element */
#define HT_CAP_INFO_LDPC_CODING_CAP ((uint16_t)BIT(0))
#define HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET ((uint16_t)BIT(1))
#define HT_CAP_INFO_SMPS_MASK ((uint16_t)(BIT(2) | BIT(3)))
#define HT_CAP_INFO_SMPS_STATIC ((uint16_t)0)
#define HT_CAP_INFO_SMPS_DYNAMIC ((uint16_t)BIT(2))
#define HT_CAP_INFO_SMPS_DISABLED ((uint16_t)(BIT(2) | BIT(3)))
#define HT_CAP_INFO_GREEN_FIELD ((uint16_t)BIT(4))
#define HT_CAP_INFO_SHORT_GI20MHZ ((uint16_t)BIT(5))
#define HT_CAP_INFO_SHORT_GI40MHZ ((uint16_t)BIT(6))
#define HT_CAP_INFO_TX_STBC ((uint16_t)BIT(7))
#define HT_CAP_INFO_RX_STBC_MASK ((uint16_t)(BIT(8) | BIT(9)))
#define HT_CAP_INFO_RX_STBC_1 ((uint16_t)BIT(8))
#define HT_CAP_INFO_RX_STBC_12 ((uint16_t)BIT(9))
#define HT_CAP_INFO_RX_STBC_123 ((uint16_t)(BIT(8) | BIT(9)))
#define HT_CAP_INFO_DELAYED_BA ((uint16_t)BIT(10))
#define HT_CAP_INFO_MAX_AMSDU_SIZE ((uint16_t)BIT(11))
#define HT_CAP_INFO_DSSS_CCK40MHZ ((uint16_t)BIT(12))
/* B13 - Reserved (was PSMP support during P802.11n development) */
#define HT_CAP_INFO_40MHZ_INTOLERANT ((uint16_t)BIT(14))
#define HT_CAP_INFO_LSIG_TXOP_PROTECT_SUPPORT	((uint16_t) BIT(15)

/* Radio Measurement capabilities (from RM Enabled Capabilities element)
 * IEEE Std 802.11-2016, 9.4.2.45, Table 9-157 */
/* byte 1 (out of 5) */
#define WLAN_RRM_CAPS_LINK_MEASUREMENT BIT(0)
#define WLAN_RRM_CAPS_NEIGHBOR_REPORT BIT(1)
#define WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE BIT(4)
#define WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE BIT(5)
#define WLAN_RRM_CAPS_BEACON_REPORT_TABLE BIT(6)
/* byte 2 (out of 5) */
#define WLAN_RRM_CAPS_CHANNEL_LOAD BIT(1)
#define WLAN_RRM_CAPS_NOISE_HISTOGRAM BIT(2)
#define WLAN_RRM_CAPS_STATISTICS_MEASUREMENT BIT(3)
#define WLAN_RRM_CAPS_LCI_MEASUREMENT BIT(4)
/* byte 5 (out of 5) */
#define WLAN_RRM_CAPS_FTM_RANGE_REPORT BIT(2)

} // namespace bwl

#endif // _BWL_802_11_DEFS_H_
