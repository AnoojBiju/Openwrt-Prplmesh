/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_DEFINES_H_
#define _BEEROCKS_DEFINES_H_

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdint.h>

constexpr char BEEROCKS_CONTROLLER[] = "beerocks_controller";
constexpr char BEEROCKS_AGENT[]      = "beerocks_agent";
constexpr char BEEROCKS_BACKHAUL[]   = "beerocks_backhaul";
constexpr char BEEROCKS_FRONTHAUL[]  = "beerocks_fronthaul";
constexpr char BEEROCKS_AP_MANAGER[] = "beerocks_ap_manager";
constexpr char BEEROCKS_MONITOR[]    = "beerocks_monitor";
constexpr char BEEROCKS_CLI[]        = "beerocks_cli";

constexpr char BEEROCKS_BROKER_UDS[]     = "uds_broker";
constexpr char BEEROCKS_AGENT_UDS[]      = "uds_agent";
constexpr char BEEROCKS_FRONTHAUL_UDS[]  = "uds_fronthaul";
constexpr char BEEROCKS_CONTROLLER_UDS[] = "uds_controller";
constexpr char BEEROCKS_PLATFORM_UDS[]   = "uds_platform";
constexpr char BEEROCKS_BACKHAUL_UDS[]   = "uds_backhaul";

constexpr uint8_t IEEE80211_QOS_TID_MAX_UP =
    8; // Maximum number of user priorities for class of service

// configuration files path
#ifdef BEEROCKS_RDKB
#define CONF_FILES_WRITABLE_PATH std::string("/nvram/")
#else
#define CONF_FILES_WRITABLE_PATH std::string("./")
#endif

#if __GNUC__ >= 7 || __cplussplus >= 201703L
#define FALLTHROUGH __attribute__((fallthrough))
#else
// clang-format off
#define FALLTHROUGH do { } while (0)
// clang-format on
#endif

namespace beerocks {
namespace ieee1905_1_consts {
static constexpr int DISCOVERY_NOTIFICATION_TIMEOUT_SEC = 60;
static constexpr uint8_t AUTOCONFIG_M2_TIMEOUT_SECONDS  = 5;
} // namespace ieee1905_1_consts

namespace message {

enum eStructsConsts {
    VERSION_LENGTH            = 16,
    NODE_NAME_LENGTH          = 32,
    IFACE_NAME_LENGTH         = 32 + 4, //need extra 1 byte for null termination + alignment
    SUPPORTED_CHANNELS_LENGTH = 128,    //support upto # channels, every channel item is 32-bit
    HOSTAP_ERR_MSG_LENGTH     = 64,
    WIFI_SSID_MAX_LENGTH      = 32 + 1 + 3, //need extra 1 byte for null termination + alignment
    // The absolute maximum size of any frame according to the 802.11 specification
    // is MMPDU size of 2304 bytes. The actual size of an (re)association frame
    // should be in the range of a couple of hundreds of bytes, so be on the safe side
    // and set the maximum size to 2KB
    ASSOCIATION_MAX_LENGTH        = 2048,
    WIFI_PASS_MAX_LENGTH          = 64 + 1 + 3, //need extra 1 byte for null termination + alignment
    USER_PASS_LEN                 = 64 + 1 + 3, //need extra 1 byte for null termination + alignment
    DEV_INFO_STR_MAX_LEN          = 32,
    WPA_SCAN_FREQ_SEGMENTS        = 3,
    WPA_SCAN_MAX_RESULTS          = 8,
    RESTRICTED_CHANNEL_LENGTH     = 40,
    WIFI_SECURITY_TYPE_MAX_LENGTH = 32,
    BACKHAUL_SCAN_MEASUREMENT_MAX_LENGTH = 16,
    PLATFORM_ERROR_DATA_SIZE             = 256,
    WIFI_GENERIC_STRING_LENGTH           = 64,
    WIFI_OPERATING_STRING_LENGTH         = 16,
    WIFI_DATA_TRANSFER_RATES_LIST_LENGTH = 256,
    CHANNEL_SCAN_LIST_LENGTH             = 8,
    HT_MCS_SET_SIZE                      = 16,
    VHT_MCS_SET_SIZE                     = 32,
    HE_MCS_SET_SIZE                      = 32,
    DEV_MAX_RADIOS                       = 3,
};

enum eMessageConsts {
    MESSAGE_VERSION       = 6,
    MESSAGE_MAGIC         = 0x55CDABEF,
    MESSAGE_BUFFER_LENGTH = 4096,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eMessageConsts_str(eMessageConsts enum_value) {
    switch (enum_value) {
    case MESSAGE_VERSION:       return "MESSAGE_VERSION";
    case MESSAGE_MAGIC:         return "MESSAGE_MAGIC";
    case MESSAGE_BUFFER_LENGTH: return "MESSAGE_BUFFER_LENGTH";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eMessageConsts value) { return out << eMessageConsts_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end
} //namespace message

enum eGlobals {
    HIERARCHY_MAX                           = 14,
    MAX_RADIOS_PER_AGENT                    = 4,
    RSSI_MAX                                = 20,
    RSSI_MIN                                = -100,
    RSSI_INVALID                            = -127,
    RCPI_MIN                                = 0,
    RCPI_MAX                                = 220,
    RCPI_INVALID                            = 255,
    SNR_MIN                                 = 1,
    SNR_INVALID                             = 0,
    BRIDGE_RATE_100KB                       = 20000,
    PHY_RATE_100KB_MAX                      = 8666,
    PHY_RATE_100KB_MIN                      = 72,
    PHY_RATE_100KB_INVALID                  = 0,
    BSS_STEER_DISASSOC_TIMER_MS             = 200, // ~200ms
    SON_SLAVE_WATCHDOG_INTERVAL_MSC         = 5000,
    SON_SLAVE_INTERFACE_STATUS_INTERVAL_MSC = 2000,
    BH_SIGNAL_RSSI_THRESHOLD_LOW            = -75,
    BH_SIGNAL_RSSI_THRESHOLD_HIGH           = -40,
    BH_SIGNAL_RSSI_THRESHOLD_HYSTERESIS     = 8,
    TOUCH_PID_TIMEOUT_SECONDS               = 4, // beerocks_watchdog cycle (10 secs) / 2 - 1
    UCC_LISTENER_PORT                       = 8002,
};

enum eBeeRocksProcesses : uint8_t {
    BEEROCKS_PROCESS_NONE = 0,
    BEEROCKS_PROCESS_ALL,
    BEEROCKS_PROCESS_MASTER,
    BEEROCKS_PROCESS_SLAVE,
    BEEROCKS_PROCESS_MONITOR,
    BEEROCKS_PROCESS_PLATFORM,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eBeeRocksProcesses_str(eBeeRocksProcesses enum_value) {
    switch (enum_value) {
    case BEEROCKS_PROCESS_NONE:     return "BEEROCKS_PROCESS_NONE";
    case BEEROCKS_PROCESS_ALL:      return "BEEROCKS_PROCESS_ALL";
    case BEEROCKS_PROCESS_MASTER:   return "BEEROCKS_PROCESS_MASTER";
    case BEEROCKS_PROCESS_SLAVE:    return "BEEROCKS_PROCESS_SLAVE";
    case BEEROCKS_PROCESS_MONITOR:  return "BEEROCKS_PROCESS_MONITOR";
    case BEEROCKS_PROCESS_PLATFORM: return "BEEROCKS_PROCESS_PLATFORM";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eBeeRocksProcesses value) { return out << eBeeRocksProcesses_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eBeeRocksEntities : uint8_t {
    BEEROCKS_ENTITY_NONE             = 0,
    BEEROCKS_ENTITY_MASTER           = 1,
    BEEROCKS_ENTITY_SLAVE            = 2,
    BEEROCKS_ENTITY_AP_MANAGER       = 3,
    BEEROCKS_ENTITY_MONITOR          = 4,
    BEEROCKS_ENTITY_BACKHAUL_MANAGER = 5,
    BEEROCKS_ENTITY_PLATFORM_MANAGER = 6,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eBeeRocksEntities_str(eBeeRocksEntities enum_value) {
    switch (enum_value) {
    case BEEROCKS_ENTITY_NONE:             return "BEEROCKS_ENTITY_NONE";
    case BEEROCKS_ENTITY_MASTER:           return "BEEROCKS_ENTITY_MASTER";
    case BEEROCKS_ENTITY_SLAVE:            return "BEEROCKS_ENTITY_SLAVE";
    case BEEROCKS_ENTITY_AP_MANAGER:       return "BEEROCKS_ENTITY_AP_MANAGER";
    case BEEROCKS_ENTITY_MONITOR:          return "BEEROCKS_ENTITY_MONITOR";
    case BEEROCKS_ENTITY_BACKHAUL_MANAGER: return "BEEROCKS_ENTITY_BACKHAUL_MANAGER";
    case BEEROCKS_ENTITY_PLATFORM_MANAGER: return "BEEROCKS_ENTITY_PLATFORM_MANAGER";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eBeeRocksEntities value) { return out << eBeeRocksEntities_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eBeeRocksIfaceIds {
    IFACE_ID_INVALID = -2,
    IFACE_RADIO_ID   = -1,
    IFACE_VAP_ID_MIN = 0,
    IFACE_TOTAL_VAPS = 16,
    IFACE_VAP_ID_MAX = IFACE_TOTAL_VAPS - 1,
};

enum eBeeRocksMessageDirection : uint8_t {
    BEEROCKS_DIRECTION_CONTROLLER = 0,
    BEEROCKS_DIRECTION_AGENT      = 1,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eBeeRocksMessageDirection_str(eBeeRocksMessageDirection enum_value) {
    switch (enum_value) {
    case BEEROCKS_DIRECTION_CONTROLLER: return "BEEROCKS_DIRECTION_CONTROLLER";
    case BEEROCKS_DIRECTION_AGENT:      return "BEEROCKS_DIRECTION_AGENT";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eBeeRocksMessageDirection value) { return out << eBeeRocksMessageDirection_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eOperatingMode : int8_t {
    // same as on bpl_cfg.h
    OPER_MODE_UNDEFINED    = -1,
    OPER_MODE_GATEWAY      = 0,
    OPER_MODE_GATEWAY_WISP = 1,
    OPER_MODE_WDS_EXTENDER = 2,
    OPER_MODE_WDS_REPEATER = 3,
    OPER_MODE_L2NAT_CLIENT = 4,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eOperatingMode_str(eOperatingMode enum_value) {
    switch (enum_value) {
    case OPER_MODE_UNDEFINED:    return "OPER_MODE_UNDEFINED";
    case OPER_MODE_GATEWAY:      return "OPER_MODE_GATEWAY";
    case OPER_MODE_GATEWAY_WISP: return "OPER_MODE_GATEWAY_WISP";
    case OPER_MODE_WDS_EXTENDER: return "OPER_MODE_WDS_EXTENDER";
    case OPER_MODE_WDS_REPEATER: return "OPER_MODE_WDS_REPEATER";
    case OPER_MODE_L2NAT_CLIENT: return "OPER_MODE_L2NAT_CLIENT";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eOperatingMode value) { return out << eOperatingMode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eProtocolPorts {
    MASTER_TCP_PORT          = 15060,
    MASTER_UDP_DISCOVER_PORT = 15060,
    CLI_PROXY_TCP_PORT       = 15061,
    ANALYZER_TCP_PORT        = 10000,
    UDP_4ADDR_PORT           = 16000,
};

enum eWiFiBandwidth : uint8_t {
    BANDWIDTH_UNKNOWN = 0,
    BANDWIDTH_20,
    BANDWIDTH_40,
    BANDWIDTH_80,
    BANDWIDTH_80_80,
    BANDWIDTH_160,
    BANDWIDTH_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiBandwidth_str(eWiFiBandwidth enum_value) {
    switch (enum_value) {
    case BANDWIDTH_UNKNOWN: return "BANDWIDTH_UNKNOWN";
    case BANDWIDTH_20:      return "BANDWIDTH_20";
    case BANDWIDTH_40:      return "BANDWIDTH_40";
    case BANDWIDTH_80:      return "BANDWIDTH_80";
    case BANDWIDTH_80_80:   return "BANDWIDTH_80_80";
    case BANDWIDTH_160:     return "BANDWIDTH_160";
    case BANDWIDTH_MAX:     return "BANDWIDTH_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiBandwidth value) { return out << eWiFiBandwidth_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

/**
 * enum eDfsState  DFS states for channels
 *
 * Channel states used by the DFS code.
 *
 * @USABLE: The channel can be used, but channel availability
 *	check (CAC) must be performed before using it for AP or IBSS.
 * @UNAVAILABLE: A radar has been detected on this channel, it
 *	is therefore marked as not available.
 * @AVAILABLE: The channel has been CAC checked and is available.
 */
enum eDfsState : uint8_t {
    USABLE,
    UNAVAILABLE,
    AVAILABLE,
    DFS_STATE_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eDfsState_str(eDfsState enum_value) {
    switch (enum_value) {
    case USABLE:        return "USABLE";
    case UNAVAILABLE:   return "UNAVAILABLE";
    case AVAILABLE:     return "AVAILABLE";
    case DFS_STATE_MAX: return "DFS_STATE_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eDfsState value) { return out << eDfsState_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiGuardInterval : uint8_t {
    LONG_GI  = 0,
    SHORT_GI = 1,
    MAX_GI,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiGuardInterval_str(eWiFiGuardInterval enum_value) {
    switch (enum_value) {
    case LONG_GI:  return "LONG_GI";
    case SHORT_GI: return "SHORT_GI";
    case MAX_GI:   return "MAX_GI";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiGuardInterval value) { return out << eWiFiGuardInterval_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiSS : uint8_t {
    SS_1 = 1,
    SS_2,
    SS_3,
    SS_4,
    SS_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiSS_str(eWiFiSS enum_value) {
    switch (enum_value) {
    case SS_1:   return "SS_1";
    case SS_2:   return "SS_2";
    case SS_3:   return "SS_3";
    case SS_4:   return "SS_4";
    case SS_MAX: return "SS_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiSS value) { return out << eWiFiSS_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiMCS : uint8_t {
    MCS_0 = 0,
    MCS_1,
    MCS_2,
    MCS_3,
    MCS_4,
    MCS_5,
    MCS_6,
    MCS_7,
    MCS_8,
    MCS_9,
    MCS_10,
    MCS_11,
    MCS_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiMCS_str(eWiFiMCS enum_value) {
    switch (enum_value) {
    case MCS_0:   return "MCS_0";
    case MCS_1:   return "MCS_1";
    case MCS_2:   return "MCS_2";
    case MCS_3:   return "MCS_3";
    case MCS_4:   return "MCS_4";
    case MCS_5:   return "MCS_5";
    case MCS_6:   return "MCS_6";
    case MCS_7:   return "MCS_7";
    case MCS_8:   return "MCS_8";
    case MCS_9:   return "MCS_9";
    case MCS_10:  return "MCS_10";
    case MCS_11:  return "MCS_11";
    case MCS_MAX: return "MCS_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiMCS value) { return out << eWiFiMCS_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiAntNum : uint8_t {
    ANT_NONE = 0,
    ANT_1X1,
    ANT_2X2,
    ANT_3X3,
    ANT_4X4,
    ANT_NUM_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiAntNum_str(eWiFiAntNum enum_value) {
    switch (enum_value) {
    case ANT_NONE:    return "ANT_NONE";
    case ANT_1X1:     return "ANT_1X1";
    case ANT_2X2:     return "ANT_2X2";
    case ANT_3X3:     return "ANT_3X3";
    case ANT_4X4:     return "ANT_4X4";
    case ANT_NUM_MAX: return "ANT_NUM_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiAntNum value) { return out << eWiFiAntNum_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiAntMode : uint8_t {
    ANT_MODE_1X1_SS1 = 0,
    ANT_MODE_2X2_SS1,
    ANT_MODE_2X2_SS2,
    ANT_MODE_3X3_SS1,
    ANT_MODE_3X3_SS2,
    ANT_MODE_3X3_SS3,
    ANT_MODE_4X4_SS1,
    ANT_MODE_4X4_SS2,
    ANT_MODE_4X4_SS3,
    ANT_MODE_4X4_SS4,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiAntMode_str(eWiFiAntMode enum_value) {
    switch (enum_value) {
    case ANT_MODE_1X1_SS1: return "ANT_MODE_1X1_SS1";
    case ANT_MODE_2X2_SS1: return "ANT_MODE_2X2_SS1";
    case ANT_MODE_2X2_SS2: return "ANT_MODE_2X2_SS2";
    case ANT_MODE_3X3_SS1: return "ANT_MODE_3X3_SS1";
    case ANT_MODE_3X3_SS2: return "ANT_MODE_3X3_SS2";
    case ANT_MODE_3X3_SS3: return "ANT_MODE_3X3_SS3";
    case ANT_MODE_4X4_SS1: return "ANT_MODE_4X4_SS1";
    case ANT_MODE_4X4_SS2: return "ANT_MODE_4X4_SS2";
    case ANT_MODE_4X4_SS3: return "ANT_MODE_4X4_SS3";
    case ANT_MODE_4X4_SS4: return "ANT_MODE_4X4_SS4";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiAntMode value) { return out << eWiFiAntMode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiStandard : uint8_t {
    STANDARD_NONE = 0x00,
    STANDARD_A    = 0x01,
    STANDARD_B    = 0x02,
    STANDARD_G    = 0x04,
    STANDARD_N    = 0x08,
    STANDARD_AC   = 0x10,
    STANDARD_AX   = 0x20,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiStandard_str(eWiFiStandard enum_value) {
    switch (enum_value) {
    case STANDARD_NONE: return "STANDARD_NONE";
    case STANDARD_A:    return "STANDARD_A";
    case STANDARD_B:    return "STANDARD_B";
    case STANDARD_G:    return "STANDARD_G";
    case STANDARD_N:    return "STANDARD_N";
    case STANDARD_AC:   return "STANDARD_AC";
    case STANDARD_AX:   return "STANDARD_AX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiStandard value) { return out << eWiFiStandard_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiRfFilterFreq : uint16_t {
    RF_FILTER_FREQ_2_4G_LOW_START = 2412,
    RF_FILTER_FREQ_2_4G_LOW_END   = 2484,
    RF_FILTER_FREQ_5G_LOW_START   = 5180,
    RF_FILTER_FREQ_5G_LOW_END     = 5330,
    RF_FILTER_FREQ_5G_HIGH_START  = 5490,
    RF_FILTER_FREQ_5G_HIGH_END    = 5835,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiRfFilterFreq_str(eWiFiRfFilterFreq enum_value) {
    switch (enum_value) {
    case RF_FILTER_FREQ_2_4G_LOW_START: return "RF_FILTER_FREQ_2_4G_LOW_START";
    case RF_FILTER_FREQ_2_4G_LOW_END:   return "RF_FILTER_FREQ_2_4G_LOW_END";
    case RF_FILTER_FREQ_5G_LOW_START:   return "RF_FILTER_FREQ_5G_LOW_START";
    case RF_FILTER_FREQ_5G_LOW_END:     return "RF_FILTER_FREQ_5G_LOW_END";
    case RF_FILTER_FREQ_5G_HIGH_START:  return "RF_FILTER_FREQ_5G_HIGH_START";
    case RF_FILTER_FREQ_5G_HIGH_END:    return "RF_FILTER_FREQ_5G_HIGH_END";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiRfFilterFreq value) { return out << eWiFiRfFilterFreq_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWifiChannelType : uint8_t {
    CH_PRIMARY   = 0,
    CH_SECONDARY = 1,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWifiChannelType_str(eWifiChannelType enum_value) {
    switch (enum_value) {
    case CH_PRIMARY:   return "CH_PRIMARY";
    case CH_SECONDARY: return "CH_SECONDARY";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWifiChannelType value) { return out << eWifiChannelType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWiFiChSwitchReason : uint8_t {
    CH_SWITCH_REASON_UNKNOWN        = 0,
    CH_SWITCH_REASON_RADAR          = 1,
    CH_SWITCH_REASON_20_COEXISTANCE = 2,
    CH_SWITCH_REASON_40_COEXISTANCE = 3,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eWiFiChSwitchReason_str(eWiFiChSwitchReason enum_value) {
    switch (enum_value) {
    case CH_SWITCH_REASON_UNKNOWN:        return "CH_SWITCH_REASON_UNKNOWN";
    case CH_SWITCH_REASON_RADAR:          return "CH_SWITCH_REASON_RADAR";
    case CH_SWITCH_REASON_20_COEXISTANCE: return "CH_SWITCH_REASON_20_COEXISTANCE";
    case CH_SWITCH_REASON_40_COEXISTANCE: return "CH_SWITCH_REASON_40_COEXISTANCE";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eWiFiChSwitchReason value) { return out << eWiFiChSwitchReason_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWifiChannelOverLaptype : uint8_t {
    CHANNEL_1_START_CH  = 1,
    CHANNEL_1_END_CH    = 5,
    CHANNEL_3_START_CH  = 1,
    CHANNEL_3_END_CH    = 8,
    CHANNEL_6_START_CH  = 6,
    CHANNEL_6_END_CH    = 10,
    CHANNEL_11_START_CH = 11,
    CHANNEL_11_END_CH   = 14,
};

enum eBeaconMeasurementSupportLevel : uint8_t {
    // bit field
    BEACON_MEAS_UNSUPPORTED     = 0x00,
    BEACON_MEAS_SSID_SUPPORTED  = 0x01,
    BEACON_MEAS_BSSID_SUPPORTED = 0x02,
    BEACON_MEAS_ALL_SUPPORTED   = 0x03,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eBeaconMeasurementSupportLevel_str(eBeaconMeasurementSupportLevel enum_value) {
    switch (enum_value) {
    case BEACON_MEAS_UNSUPPORTED:     return "BEACON_MEAS_UNSUPPORTED";
    case BEACON_MEAS_SSID_SUPPORTED:  return "BEACON_MEAS_SSID_SUPPORTED";
    case BEACON_MEAS_BSSID_SUPPORTED: return "BEACON_MEAS_BSSID_SUPPORTED";
    case BEACON_MEAS_ALL_SUPPORTED:   return "BEACON_MEAS_ALL_SUPPORTED";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eBeaconMeasurementSupportLevel value) { return out << eBeaconMeasurementSupportLevel_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eMeasurementMode11K : uint8_t {
    MEASURE_MODE_PASSIVE = 0,
    MEASURE_MODE_ACTIVE,
    MEASURE_MODE_TABLE,
    MEASURE_MODE_UNDEFINED,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eMeasurementMode11K_str(eMeasurementMode11K enum_value) {
    switch (enum_value) {
    case MEASURE_MODE_PASSIVE:   return "MEASURE_MODE_PASSIVE";
    case MEASURE_MODE_ACTIVE:    return "MEASURE_MODE_ACTIVE";
    case MEASURE_MODE_TABLE:     return "MEASURE_MODE_TABLE";
    case MEASURE_MODE_UNDEFINED: return "MEASURE_MODE_UNDEFINED";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eMeasurementMode11K value) { return out << eMeasurementMode11K_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eWifiDefaultBeaconMeasurementParams : int8_t {
    BEACON_MEASURE_DEFAULT_RANDOMIZATION_INTERVAL   = 0,
    BEACON_MEASURE_DEFAULT_ACTIVE_DURATION          = 50,
    BEACON_MEASURE_DEFAULT_PASSIVE_DURATION         = 120,
    BEACON_MEASURE_DEFAULT_ALL_BANDS_OPERATION_CODE = 0,
    BEACON_MEASURE_DEFAULT_AUTO_OPERATION_CODE      = -1,
    BEACON_MEASURE_DEFAULT_CHANNEL_ALL_CHANNELS     = 0,
    BEACON_MEASURE_DEFAULT_REPEATS                  = 0,
};

enum eHtCapsSmPowerSaveMode : uint8_t {
    HT_SM_POWER_SAVE_MODE_STATIC   = 0,
    HT_SM_POWER_SAVE_MODE_DYNAMIC  = 1,
    HT_SM_POWER_SAVE_MODE_RESERVED = 2,
    HT_SM_POWER_SAVE_MODE_DISABLED = 3,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eHtCapsSmPowerSaveMode_str(eHtCapsSmPowerSaveMode enum_value) {
    switch (enum_value) {
    case HT_SM_POWER_SAVE_MODE_STATIC:   return "HT_SM_POWER_SAVE_MODE_STATIC";
    case HT_SM_POWER_SAVE_MODE_DYNAMIC:  return "HT_SM_POWER_SAVE_MODE_DYNAMIC";
    case HT_SM_POWER_SAVE_MODE_RESERVED: return "HT_SM_POWER_SAVE_MODE_RESERVED";
    case HT_SM_POWER_SAVE_MODE_DISABLED: return "HT_SM_POWER_SAVE_MODE_DISABLED";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eHtCapsSmPowerSaveMode value) { return out << eHtCapsSmPowerSaveMode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eLogLevel : uint8_t {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_ALL,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_TRACE,
    LOG_LEVEL_WARNING,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eLogLevel_str(eLogLevel enum_value) {
    switch (enum_value) {
    case LOG_LEVEL_NONE:    return "LOG_LEVEL_NONE";
    case LOG_LEVEL_ALL:     return "LOG_LEVEL_ALL";
    case LOG_LEVEL_INFO:    return "LOG_LEVEL_INFO";
    case LOG_LEVEL_DEBUG:   return "LOG_LEVEL_DEBUG";
    case LOG_LEVEL_ERROR:   return "LOG_LEVEL_ERROR";
    case LOG_LEVEL_FATAL:   return "LOG_LEVEL_FATAL";
    case LOG_LEVEL_TRACE:   return "LOG_LEVEL_TRACE";
    case LOG_LEVEL_WARNING: return "LOG_LEVEL_WARNING";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eLogLevel value) { return out << eLogLevel_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eIfaceType : uint8_t {
    IFACE_TYPE_UNSUPPORTED = 0x00,
    //Wi-Fi
    IFACE_TYPE_WIFI_INTEL       = 0x01,
    IFACE_TYPE_WIFI_UNSPECIFIED = 0x40,
    IFACE_TYPE_WIFI_END         = 0xF0,
    //
    IFACE_TYPE_ETHERNET  = 0xF1,
    IFACE_TYPE_BRIDGE    = 0xFE,
    IFACE_TYPE_GW_BRIDGE = 0xFF,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eIfaceType_str(eIfaceType enum_value) {
    switch (enum_value) {
    case IFACE_TYPE_UNSUPPORTED:      return "IFACE_TYPE_UNSUPPORTED";
    case IFACE_TYPE_WIFI_INTEL:       return "IFACE_TYPE_WIFI_INTEL";
    case IFACE_TYPE_WIFI_UNSPECIFIED: return "IFACE_TYPE_WIFI_UNSPECIFIED";
    case IFACE_TYPE_WIFI_END:         return "IFACE_TYPE_WIFI_END";
    case IFACE_TYPE_ETHERNET:         return "IFACE_TYPE_ETHERNET";
    case IFACE_TYPE_BRIDGE:           return "IFACE_TYPE_BRIDGE";
    case IFACE_TYPE_GW_BRIDGE:        return "IFACE_TYPE_GW_BRIDGE";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eIfaceType value) { return out << eIfaceType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

#define IFACE_TYPE_STR_UNSUPPORTED "UNSUPPORTED"
#define IFACE_TYPE_STR_WIFI_INTEL "WIFI_INTEL"
#define IFACE_TYPE_STR_WIFI_UNSPECIFIED "WIFI_UNSPECIFIED"

#define IFACE_TYPE_STR_ETHERNET "ETHERNET"
#define IFACE_TYPE_STR_BRIDGE "BRIDGE"
#define IFACE_TYPE_STR_GW_BRIDGE "GW_BRIDGE"

enum eNodeState : uint8_t {
    STATE_DISCONNECTED = 0,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_ANY,
    STATE_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eNodeState_str(eNodeState enum_value) {
    switch (enum_value) {
    case STATE_DISCONNECTED: return "STATE_DISCONNECTED";
    case STATE_CONNECTING:   return "STATE_CONNECTING";
    case STATE_CONNECTED:    return "STATE_CONNECTED";
    case STATE_ANY:          return "STATE_ANY";
    case STATE_MAX:          return "STATE_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eNodeState value) { return out << eNodeState_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eType : uint8_t {
    TYPE_GW           = 0, // GW Bridge
    TYPE_IRE          = 1, // IRE Bridge
    TYPE_IRE_BACKHAUL = 2, // IRE Backhaul
    TYPE_SLAVE        = 3, // HOSTAP managed by BeeRocks slave
    TYPE_CLIENT       = 4, // Client Wi-Fi or Eth
    TYPE_ETH_SWITCH   = 5, // Eth switch under GW or IRE Bridge
    TYPE_ANY          = 6,
    TYPE_UNDEFINED    = 7,
    TYPE_MAX,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eType_str(eType enum_value) {
    switch (enum_value) {
    case TYPE_GW:           return "TYPE_GW";
    case TYPE_IRE:          return "TYPE_IRE";
    case TYPE_IRE_BACKHAUL: return "TYPE_IRE_BACKHAUL";
    case TYPE_SLAVE:        return "TYPE_SLAVE";
    case TYPE_CLIENT:       return "TYPE_CLIENT";
    case TYPE_ETH_SWITCH:   return "TYPE_ETH_SWITCH";
    case TYPE_ANY:          return "TYPE_ANY";
    case TYPE_UNDEFINED:    return "TYPE_UNDEFINED";
    case TYPE_MAX:          return "TYPE_MAX";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eType value) { return out << eType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eArpStatus : uint8_t {
    ARP_NUD_INCOMPLETE = 0x01,
    ARP_NUD_REACHABLE  = 0x02,
    ARP_NUD_STALE      = 0x04,
    ARP_NUD_DELAY      = 0x08,
    ARP_NUD_PROBE      = 0x10,
    ARP_NUD_FAILED     = 0x20,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eArpStatus_str(eArpStatus enum_value) {
    switch (enum_value) {
    case ARP_NUD_INCOMPLETE: return "ARP_NUD_INCOMPLETE";
    case ARP_NUD_REACHABLE:  return "ARP_NUD_REACHABLE";
    case ARP_NUD_STALE:      return "ARP_NUD_STALE";
    case ARP_NUD_DELAY:      return "ARP_NUD_DELAY";
    case ARP_NUD_PROBE:      return "ARP_NUD_PROBE";
    case ARP_NUD_FAILED:     return "ARP_NUD_FAILED";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eArpStatus value) { return out << eArpStatus_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eArpSource : uint8_t {
    ARP_SRC_ETH_BACK = 0,
    ARP_SRC_ETH_FRONT,
    ARP_SRC_WIRELESS_BACK,
    ARP_SRC_WIRELESS_FRONT
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eArpSource_str(eArpSource enum_value) {
    switch (enum_value) {
    case ARP_SRC_ETH_BACK:       return "ARP_SRC_ETH_BACK";
    case ARP_SRC_ETH_FRONT:      return "ARP_SRC_ETH_FRONT";
    case ARP_SRC_WIRELESS_BACK:  return "ARP_SRC_WIRELESS_BACK";
    case ARP_SRC_WIRELESS_FRONT: return "ARP_SRC_WIRELESS_FRONT";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eArpSource value) { return out << eArpSource_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eArpType : uint8_t { ARP_TYPE_NEWNEIGH = 0, ARP_TYPE_DELNEIGH, ARP_TYPE_GETNEIGH };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eArpType_str(eArpType enum_value) {
    switch (enum_value) {
    case ARP_TYPE_NEWNEIGH: return "ARP_TYPE_NEWNEIGH";
    case ARP_TYPE_DELNEIGH: return "ARP_TYPE_DELNEIGH";
    case ARP_TYPE_GETNEIGH: return "ARP_TYPE_GETNEIGH";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eArpType value) { return out << eArpType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eFreqType {
    FREQ_24G    = 0,
    FREQ_5G     = 1,
    FREQ_58G    = 2,
    FREQ_24G_5G = 3,
    FREQ_6G     = 4,
    FREQ_AUTO,
    FREQ_UNKNOWN,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eFreqType_str(eFreqType enum_value) {
    switch (enum_value) {
    case FREQ_24G:     return "FREQ_24G";
    case FREQ_5G:      return "FREQ_5G";
    case FREQ_58G:     return "FREQ_58G";
    case FREQ_24G_5G:  return "FREQ_24G_5G";
    case FREQ_6G:      return "FREQ_6G";
    case FREQ_AUTO:    return "FREQ_AUTO";
    case FREQ_UNKNOWN: return "FREQ_UNKNOWN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eFreqType value) { return out << eFreqType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eSubbandType {
    LOW_SUBBAND          = 0,
    LOW_SUBBAND_NON_DFS  = 1,
    LOW_SUBBAND_DFS      = 2,
    HIGH_SUBBAND         = 3,
    HIGH_SUBBAND_NON_DFS = 4,
    HIGH_SUBBAND_DFS,
    ANY_SUBBAND,
    SUBBAND_UNKNOWN,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eSubbandType_str(eSubbandType enum_value) {
    switch (enum_value) {
    case LOW_SUBBAND:          return "LOW_SUBBAND";
    case LOW_SUBBAND_NON_DFS:  return "LOW_SUBBAND_NON_DFS";
    case LOW_SUBBAND_DFS:      return "LOW_SUBBAND_DFS";
    case HIGH_SUBBAND:         return "HIGH_SUBBAND";
    case HIGH_SUBBAND_NON_DFS: return "HIGH_SUBBAND_NON_DFS";
    case HIGH_SUBBAND_DFS:     return "HIGH_SUBBAND_DFS";
    case ANY_SUBBAND:          return "ANY_SUBBAND";
    case SUBBAND_UNKNOWN:      return "SUBBAND_UNKNOWN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eSubbandType value) { return out << eSubbandType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eDfsSubbandType {
    DFS_LOW_SUBBAND         = 0,
    DFS_HIGH_FIRST_SUBBAND  = 1,
    DFS_HIGH_SECOND_SUBBAND = 2,
    DFS_HIGH_THIRD_SUBBAND  = 3,
    DFS_SUBBAND_UNKNOWN,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eDfsSubbandType_str(eDfsSubbandType enum_value) {
    switch (enum_value) {
    case DFS_LOW_SUBBAND:         return "DFS_LOW_SUBBAND";
    case DFS_HIGH_FIRST_SUBBAND:  return "DFS_HIGH_FIRST_SUBBAND";
    case DFS_HIGH_SECOND_SUBBAND: return "DFS_HIGH_SECOND_SUBBAND";
    case DFS_HIGH_THIRD_SUBBAND:  return "DFS_HIGH_THIRD_SUBBAND";
    case DFS_SUBBAND_UNKNOWN:     return "DFS_SUBBAND_UNKNOWN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eDfsSubbandType value) { return out << eDfsSubbandType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eRadioBandCapability {
    LOW_SUBBAND_ONLY = 0,
    HIGH_SUBBAND_ONLY,
    BOTH_SUBBAND,
    SUBBAND_CAPABILITY_UNKNOWN,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eRadioBandCapability_str(eRadioBandCapability enum_value) {
    switch (enum_value) {
    case LOW_SUBBAND_ONLY:           return "LOW_SUBBAND_ONLY";
    case HIGH_SUBBAND_ONLY:          return "HIGH_SUBBAND_ONLY";
    case BOTH_SUBBAND:               return "BOTH_SUBBAND";
    case SUBBAND_CAPABILITY_UNKNOWN: return "SUBBAND_CAPABILITY_UNKNOWN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eRadioBandCapability value) { return out << eRadioBandCapability_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eSlaveJoinResponseErrCode {
    JOIN_RESP_NO_ERROR = 0,
    JOIN_RESP_VERSION_MISMATCH,
    JOIN_RESP_SSID_MISMATCH,
    JOIN_RESP_REJECT,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eSlaveJoinResponseErrCode_str(eSlaveJoinResponseErrCode enum_value) {
    switch (enum_value) {
    case JOIN_RESP_NO_ERROR:         return "JOIN_RESP_NO_ERROR";
    case JOIN_RESP_VERSION_MISMATCH: return "JOIN_RESP_VERSION_MISMATCH";
    case JOIN_RESP_SSID_MISMATCH:    return "JOIN_RESP_SSID_MISMATCH";
    case JOIN_RESP_REJECT:           return "JOIN_RESP_REJECT";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eSlaveJoinResponseErrCode value) { return out << eSlaveJoinResponseErrCode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eApActiveMode : uint8_t { AP_IDLE_MODE = 0, AP_ACTIVE_MODE, AP_INVALID_MODE };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eApActiveMode_str(eApActiveMode enum_value) {
    switch (enum_value) {
    case AP_IDLE_MODE:    return "AP_IDLE_MODE";
    case AP_ACTIVE_MODE:  return "AP_ACTIVE_MODE";
    case AP_INVALID_MODE: return "AP_INVALID_MODE";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eApActiveMode value) { return out << eApActiveMode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eBssType {
    BSS_TYPE_TEARDOWN = 0,
    BSS_TYPE_BACKHAUL,
    BSS_TYPE_FRONTHAUL,
    BSS_TYPE_BACK_FRONTHAUL,
    BSS_TYPE_INVALID
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eBssType_str(eBssType enum_value) {
    switch (enum_value) {
    case BSS_TYPE_TEARDOWN:       return "BSS_TYPE_TEARDOWN";
    case BSS_TYPE_BACKHAUL:       return "BSS_TYPE_BACKHAUL";
    case BSS_TYPE_FRONTHAUL:      return "BSS_TYPE_FRONTHAUL";
    case BSS_TYPE_BACK_FRONTHAUL: return "BSS_TYPE_BACK_FRONTHAUL";
    case BSS_TYPE_INVALID:        return "BSS_TYPE_INVALID";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eBssType value) { return out << eBssType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class eChannelScanStatusCode : uint8_t {
    SUCCESS = 0,
    INTERNAL_FAILURE,
    POOL_TOO_BIG,
    TRIGGERED_EVENT_TIMEOUT,
    RESULTS_READY_EVENT_TIMEOUT,
    RESULTS_DUMP_EVENT_TIMEOUT,
    ABORTED_BY_DRIVER,
    RESULTS_EMPTY,
    INVALID_PARAMS,
    CHANNEL_SCAN_REPORT_TIMEOUT
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eChannelScanStatusCode_str(eChannelScanStatusCode enum_value) {
    switch (enum_value) {
    case eChannelScanStatusCode::SUCCESS:                     return "eChannelScanStatusCode::SUCCESS";
    case eChannelScanStatusCode::INTERNAL_FAILURE:            return "eChannelScanStatusCode::INTERNAL_FAILURE";
    case eChannelScanStatusCode::POOL_TOO_BIG:                return "eChannelScanStatusCode::POOL_TOO_BIG";
    case eChannelScanStatusCode::TRIGGERED_EVENT_TIMEOUT:     return "eChannelScanStatusCode::TRIGGERED_EVENT_TIMEOUT";
    case eChannelScanStatusCode::RESULTS_READY_EVENT_TIMEOUT: return "eChannelScanStatusCode::RESULTS_READY_EVENT_TIMEOUT";
    case eChannelScanStatusCode::RESULTS_DUMP_EVENT_TIMEOUT:  return "eChannelScanStatusCode::RESULTS_DUMP_EVENT_TIMEOUT";
    case eChannelScanStatusCode::ABORTED_BY_DRIVER:           return "eChannelScanStatusCode::ABORTED_BY_DRIVER";
    case eChannelScanStatusCode::RESULTS_EMPTY:               return "eChannelScanStatusCode::RESULTS_EMPTY";
    case eChannelScanStatusCode::INVALID_PARAMS:              return "eChannelScanStatusCode::INVALID_PARAMS";
    case eChannelScanStatusCode::CHANNEL_SCAN_REPORT_TIMEOUT: return "eChannelScanStatusCode::CHANNEL_SCAN_REPORT_TIMEOUT";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eChannelScanStatusCode value) { return out << eChannelScanStatusCode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class eChannelScanOperationCode : uint8_t {
    SUCCESS = 0,
    ERROR,
    SCAN_IN_PROGRESS,
    INVALID_PARAMS_ENABLE,
    INVALID_PARAMS_DWELLTIME,
    INVALID_PARAMS_SCANTIME,
    INVALID_PARAMS_CHANNELPOOL
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eChannelScanOperationCode_str(eChannelScanOperationCode enum_value) {
    switch (enum_value) {
    case eChannelScanOperationCode::SUCCESS:                    return "eChannelScanOperationCode::SUCCESS";
    case eChannelScanOperationCode::ERROR:                      return "eChannelScanOperationCode::ERROR";
    case eChannelScanOperationCode::SCAN_IN_PROGRESS:           return "eChannelScanOperationCode::SCAN_IN_PROGRESS";
    case eChannelScanOperationCode::INVALID_PARAMS_ENABLE:      return "eChannelScanOperationCode::INVALID_PARAMS_ENABLE";
    case eChannelScanOperationCode::INVALID_PARAMS_DWELLTIME:   return "eChannelScanOperationCode::INVALID_PARAMS_DWELLTIME";
    case eChannelScanOperationCode::INVALID_PARAMS_SCANTIME:    return "eChannelScanOperationCode::INVALID_PARAMS_SCANTIME";
    case eChannelScanOperationCode::INVALID_PARAMS_CHANNELPOOL: return "eChannelScanOperationCode::INVALID_PARAMS_CHANNELPOOL";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eChannelScanOperationCode value) { return out << eChannelScanOperationCode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class eChannelSwitchStatus : uint8_t {
    SUCCESS = 0,
    ERROR,
    INVALID_BANDWIDTH_AND_CHANNEL,
    INOPERABLE_CHANNEL
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eChannelSwitchStatus_str(eChannelSwitchStatus enum_value) {
    switch (enum_value) {
    case eChannelSwitchStatus::SUCCESS:                       return "eChannelSwitchStatus::SUCCESS";
    case eChannelSwitchStatus::ERROR:                         return "eChannelSwitchStatus::ERROR";
    case eChannelSwitchStatus::INVALID_BANDWIDTH_AND_CHANNEL: return "eChannelSwitchStatus::INVALID_BANDWIDTH_AND_CHANNEL";
    case eChannelSwitchStatus::INOPERABLE_CHANNEL:            return "eChannelSwitchStatus::INOPERABLE_CHANNEL";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eChannelSwitchStatus value) { return out << eChannelSwitchStatus_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class eChannelPreferenceRankingConsts : int8_t {
    INVALID      = -1,
    NON_OPERABLE = 0,
    LOWEST       = 1,
    BEST         = 15
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eChannelPreferenceRankingConsts_str(eChannelPreferenceRankingConsts enum_value) {
    switch (enum_value) {
    case eChannelPreferenceRankingConsts::INVALID:      return "eChannelPreferenceRankingConsts::INVALID";
    case eChannelPreferenceRankingConsts::NON_OPERABLE: return "eChannelPreferenceRankingConsts::NON_OPERABLE";
    case eChannelPreferenceRankingConsts::LOWEST:       return "eChannelPreferenceRankingConsts::LOWEST";
    case eChannelPreferenceRankingConsts::BEST:         return "eChannelPreferenceRankingConsts::BEST";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eChannelPreferenceRankingConsts value) { return out << eChannelPreferenceRankingConsts_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

#define CHANNEL_SCAN_INVALID_PARAM -1
#define SCAN_ALL_CHANNELS 0

constexpr int PARAMETER_NOT_CONFIGURED = -1;

// array of allowed ifname prefix strings
static const char *const ifname_prefix_list[] = {"wlan", "wl"};

// string of separator characters delimiting the ifname prefix
static const char *const ifname_separators = ".-";

enum class eZWDFS_flags : uint8_t {
    DISABLE      = 0b00000000,
    ON_RADAR     = 0b00000001,
    ON_SELECTION = 0b00000010,
    PRE_CAC      = 0b00000100,
    ALL          = 0b11111111
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eZWDFS_flags_str(eZWDFS_flags enum_value) {
    switch (enum_value) {
    case eZWDFS_flags::DISABLE:      return "eZWDFS_flags::DISABLE";
    case eZWDFS_flags::ON_RADAR:     return "eZWDFS_flags::ON_RADAR";
    case eZWDFS_flags::ON_SELECTION: return "eZWDFS_flags::ON_SELECTION";
    case eZWDFS_flags::PRE_CAC:      return "eZWDFS_flags::PRE_CAC";
    case eZWDFS_flags::ALL:          return "eZWDFS_flags::ALL";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eZWDFS_flags value) { return out << eZWDFS_flags_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

} // namespace beerocks

#endif //_BEEROCKS_DEFINES_H_
