/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_BASE_WLAN_HAL_TYPES_H_
#define _BWL_BASE_WLAN_HAL_TYPES_H_

#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_message_structs.h>
#include <bcl/network/net_struct.h>

#include <stdint.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace bwl {

enum class HALType {
    Invalid = 0,

    AccessPoint,
    Monitor,
    Station
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *HALType_str(HALType enum_value) {
    switch (enum_value) {
    case HALType::Invalid:     return "HALType::Invalid";
    case HALType::AccessPoint: return "HALType::AccessPoint";
    case HALType::Monitor:     return "HALType::Monitor";
    case HALType::Station:     return "HALType::Station";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, HALType value) { return out << HALType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class IfaceType {
    Unsupported = 0x00,
    Intel       = 0x01,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *IfaceType_str(IfaceType enum_value) {
    switch (enum_value) {
    case IfaceType::Unsupported: return "IfaceType::Unsupported";
    case IfaceType::Intel:       return "IfaceType::Intel";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, IfaceType value) { return out << IfaceType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class HALState {
    Uninitialized = 0, /*!< Not initialized */
    Initializing  = 1, /*!< Initializing in progress */
    Operational   = 2, /*!< Initialized and active */
    Failed        = 3  /*!< Failed to initialize */
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *HALState_str(HALState enum_value) {
    switch (enum_value) {
    case HALState::Uninitialized: return "HALState::Uninitialized";
    case HALState::Initializing:  return "HALState::Initializing";
    case HALState::Operational:   return "HALState::Operational";
    case HALState::Failed:        return "HALState::Failed";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, HALState value) { return out << HALState_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class AntMode { Invalid = 0, ANT_1X1, ANT_2X2, ANT_3X3, ANT_4X4 };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *AntMode_str(AntMode enum_value) {
    switch (enum_value) {
    case AntMode::Invalid: return "AntMode::Invalid";
    case AntMode::ANT_1X1: return "AntMode::ANT_1X1";
    case AntMode::ANT_2X2: return "AntMode::ANT_2X2";
    case AntMode::ANT_3X3: return "AntMode::ANT_3X3";
    case AntMode::ANT_4X4: return "AntMode::ANT_4X4";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, AntMode value) { return out << AntMode_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

struct VAPElement {
    /**
     * Basic Service Set (i.e.: VAP name, e.g.: wlan0.0, wlan0.1, wlan0.2, ...).
     */
    std::string bss;
    std::string ssid;
    std::string mac;
    bool fronthaul;
    bool backhaul;
    bool profile1_backhaul_sta_association_disallowed = false;
    bool profile2_backhaul_sta_association_disallowed = false;

    bool operator==(const VAPElement &other) const
    {
        return (bss == other.bss && ssid == other.ssid && mac == other.mac);
    }

    bool operator!=(const VAPElement &other) const { return !(*this == other); }
};

enum class ChanSwReason { Unknown = 0, Radar = 1, CoEx_20 = 2, CoEx_40 = 3 };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *ChanSwReason_str(ChanSwReason enum_value) {
    switch (enum_value) {
    case ChanSwReason::Unknown: return "ChanSwReason::Unknown";
    case ChanSwReason::Radar:   return "ChanSwReason::Radar";
    case ChanSwReason::CoEx_20: return "ChanSwReason::CoEx_20";
    case ChanSwReason::CoEx_40: return "ChanSwReason::CoEx_40";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, ChanSwReason value) { return out << ChanSwReason_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

// WLAN Security Types
enum class WiFiSec { Invalid = 0, None, WEP_64, WEP_128, WPA_PSK, WPA2_PSK, WPA_WPA2_PSK };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *WiFiSec_str(WiFiSec enum_value) {
    switch (enum_value) {
    case WiFiSec::Invalid:      return "WiFiSec::Invalid";
    case WiFiSec::None:         return "WiFiSec::None";
    case WiFiSec::WEP_64:       return "WiFiSec::WEP_64";
    case WiFiSec::WEP_128:      return "WiFiSec::WEP_128";
    case WiFiSec::WPA_PSK:      return "WiFiSec::WPA_PSK";
    case WiFiSec::WPA2_PSK:     return "WiFiSec::WPA2_PSK";
    case WiFiSec::WPA_WPA2_PSK: return "WiFiSec::WPA_WPA2_PSK";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, WiFiSec value) { return out << WiFiSec_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum eRadioState : uint8_t {
    UNINITIALIZED,
    DISABLED,
    COUNTRY_UPDATE,
    ACS,
    ACS_DONE,
    HT_SCAN,
    DFS,
    ENABLED,
    UNKNOWN
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eRadioState_str(eRadioState enum_value) {
    switch (enum_value) {
    case UNINITIALIZED:  return "UNINITIALIZED";
    case DISABLED:       return "DISABLED";
    case COUNTRY_UPDATE: return "COUNTRY_UPDATE";
    case ACS:            return "ACS";
    case ACS_DONE:       return "ACS_DONE";
    case HT_SCAN:        return "HT_SCAN";
    case DFS:            return "DFS";
    case ENABLED:        return "ENABLED";
    case UNKNOWN:        return "UNKNOWN";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eRadioState value) { return out << eRadioState_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

struct sChannelInfo {
    int8_t tx_power_dbm;
    beerocks::eDfsState dfs_state;
    // Key: eWiFiBandwidth, Value: Rank
    std::map<beerocks::eWiFiBandwidth, int32_t> bw_info_list;
};

struct RadioInfo {
    std::string iface_name;
    IfaceType iface_type               = IfaceType::Unsupported;
    eRadioState radio_state            = eRadioState::UNKNOWN;
    int wifi_ctrl_enabled              = 0; // Hostapd / wpa_supplicant
    bool tx_enabled                    = false;
    bool is_5ghz                       = false;
    int channel                        = 0;
    int bandwidth                      = 0;
    int channel_ext_above              = 0;
    int vht_center_freq                = 0;
    bool is_dfs_channel                = false;
    int ant_num                        = 0;
    int tx_power                       = 0;
    beerocks::eFreqType frequency_band = beerocks::eFreqType::FREQ_UNKNOWN; /**< Frequency band */
    beerocks::eWiFiBandwidth max_bandwidth =
        beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN; /**< Maximum supported bandwidth */
    bool ht_supported     = false;                   /**< Is HT supported flag */
    uint8_t ht_capability = 0;                       /**< HT capabilities */

    /**< 16-byte attribute containing the MCS set as defined in 802.11n */
    std::array<uint8_t, beerocks::message::HT_MCS_SET_SIZE> ht_mcs_set;
    bool vht_supported      = false; /**< Is VHT supported flag */
    uint16_t vht_capability = 0;     /**< VHT capabilities */

    /**< 32-byte attribute containing the MCS set as defined in 802.11ac */
    std::array<uint8_t, beerocks::message::VHT_MCS_SET_SIZE> vht_mcs_set;

    bool he_supported      = false; /**< Is HE supported flag */
    uint16_t he_capability = 0;     /**< HE capabilities */
    /**< 32-byte attribute containing the MCS set as defined in 802.11ax */
    std::array<uint8_t, beerocks::message::HE_MCS_SET_SIZE> he_mcs_set;

    ChanSwReason last_csa_sw_reason = ChanSwReason::Unknown;
    // Key = channel
    std::map<uint8_t, sChannelInfo> channels_list;
    std::unordered_map<int, VAPElement> available_vaps; // key = vap_id
};

struct hal_conf_t {
    bool ap_acs_enabled = false;
    std::string wpa_ctrl_path;
    std::set<std::string> monitored_BSSs;
};

//sta_wlan_hal
typedef struct {
    beerocks::net::sScanResult result;
    char iface_name[beerocks::message::IFACE_NAME_LENGTH];
    uint16_t rx_phy_rate_100kb;
    uint16_t tx_phy_rate_100kb;
    int8_t rx_rssi;
    uint8_t rx_snr;
    int8_t rx_packets;
    uint8_t src_module;
    int8_t vap_id;
} sNodeRssiMeasurement;

typedef struct {
    uint8_t multi_ap_profile;
    uint16_t multi_ap_primary_vlan_id;
} sACTION_BACKHAUL_CONNECTED_NOTIFICATION;

typedef struct {
    uint32_t disconnect_reason;
    sMacAddr bssid;
} sACTION_BACKHAUL_DISCONNECT_REASON_NOTIFICATION;

typedef struct {
    sNodeRssiMeasurement params;
} sACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE;

//ap_wlan_hal

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

typedef struct {
    sNodeRssiMeasurement params;
} sACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE;

typedef struct {
    sMacAddr client_mac;
    sMacAddr bssid;
    uint8_t rx_snr;
    uint8_t blocked;   // True if response blocked.
    uint8_t broadcast; // True if broadcast probe.
} sSteeringEvProbeReq;

typedef struct {
    sSteeringEvProbeReq params;
} sACTION_APMANAGER_STEERING_EVENT_PROBE_REQ_NOTIFICATION;

typedef struct {
    sMacAddr client_mac;
    sMacAddr bssid;
    uint8_t rx_snr;
    uint8_t reason;
    uint8_t blocked; // True if response blocked.
    uint8_t reject;  // True Auth Req is rejected by AP and Auth response is sent to STA with reason
} sSteeringEvAuthFail;

typedef struct {
    sSteeringEvAuthFail params;
} sACTION_APMANAGER_STEERING_EVENT_AUTH_FAIL_NOTIFICATION;

typedef struct {
    sMacAddr mac;
    sMacAddr bssid;
    beerocks::message::sRadioCapabilities capabilities;
    int8_t vap_id;
    uint8_t reserved1;
    uint8_t reserved2;
    uint8_t multi_ap_profile;
    size_t association_frame_length;
    uint8_t association_frame[beerocks::message::ASSOCIATION_MAX_LENGTH];
} sClientAssociationParams;

typedef struct {
    sMacAddr mac;
    int8_t vap_id;
    uint8_t reason;
    uint8_t source;
    uint8_t type;
} sClientDisconnectionParams;

typedef struct {
    sClientDisconnectionParams params;
} sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION;

typedef struct {
    char hash[65];
    sMacAddr enrollee_mac;
} sACTION_APMANAGER_DPP_PRESENCE_ANNOUNCEMENT;

typedef struct {
    sMacAddr enrollee_mac;
} sACTION_APMANAGER_DPP_AUTHENTICATION_RESPONSE;

typedef struct {
    sMacAddr enrollee_mac;
} sACTION_APMANAGER_DPP_CONFIGURATION_REQUEST;

typedef struct {
    sClientAssociationParams params;
} sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION;

typedef struct {
    sMacAddr mac;
    int8_t vap_id;
} sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION;

typedef struct {
    sMacAddr mac;
} sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION;

typedef struct {
    sMacAddr mac;
    sMacAddr source_bssid;
    sMacAddr target_bssid;
    uint8_t status_code;
} sNodeBssSteerResponse;

typedef struct {
    sNodeBssSteerResponse params;
} sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE;

typedef struct {
    uint32_t timeout;
    uint32_t frequency;
    uint16_t center_frequency1;
    uint16_t center_frequency2;
    uint8_t success;
    uint8_t channel;
    uint8_t bandwidth;
    uint8_t reserved1;
} sDfsCacCompleted;

typedef struct {
    sDfsCacCompleted params;
} sACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION;

typedef struct {
    uint8_t channel;
    uint8_t secondary_channel;
    beerocks::eWiFiBandwidth bandwidth;
    uint16_t cac_duration_sec;
} sCacStartedNotificationParams;

typedef struct {
    sCacStartedNotificationParams params;
} sACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION;

typedef struct {
    uint32_t frequency;
    uint8_t channel;
    uint8_t bandwidth; //beerocks::eWiFiBandwidth
    uint16_t vht_center_frequency;
} sDfsChannelAvailable;

typedef struct {
    sDfsChannelAvailable params;
} sACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION;

typedef struct {
    int8_t vap_id;
} sHOSTAP_DISABLED_NOTIFICATION;

typedef struct {
    int8_t vap_id;
} sHOSTAP_ENABLED_NOTIFICATION;

#define SSID_MAX_SIZE beerocks::message::WIFI_SSID_MAX_LENGTH
// ASSOCIATION_MAX_LENGTH is defined to be the maximum of the binary frame
// but since it is represented as hex here. we need two hex characters per byte + a terminating \0.
#define ASSOCIATION_FRAME_SIZE (2 * beerocks::message::ASSOCIATION_MAX_LENGTH + 1)
#define MAC_ADDR_SIZE 18
constexpr size_t MAX_TEMP_BUFFER_SIZE = 64;
constexpr char BSS_IFNAME_PREFIX[]    = "wlan";

/**
 * @brief Supported 802.11 management frame types.
 */
enum class eManagementFrameType {
    ASSOCIATION_REQUEST   = 0x00, /**< Association Request */
    REASSOCIATION_REQUEST = 0x01, /**< Re-association Request */
    BTM_QUERY             = 0x02, /**< BSS transition query */
    WNM_REQUEST           = 0x03, /**< 802.11v transition request */
    ANQP_REQUEST          = 0x04  /**< Access Network Query Protocol request */
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *eManagementFrameType_str(eManagementFrameType enum_value) {
    switch (enum_value) {
    case eManagementFrameType::ASSOCIATION_REQUEST:   return "eManagementFrameType::ASSOCIATION_REQUEST";
    case eManagementFrameType::REASSOCIATION_REQUEST: return "eManagementFrameType::REASSOCIATION_REQUEST";
    case eManagementFrameType::BTM_QUERY:             return "eManagementFrameType::BTM_QUERY";
    case eManagementFrameType::WNM_REQUEST:           return "eManagementFrameType::WNM_REQUEST";
    case eManagementFrameType::ANQP_REQUEST:          return "eManagementFrameType::ANQP_REQUEST";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, eManagementFrameType value) { return out << eManagementFrameType_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

/**
 * @brief 802.11 management frame notification event.
 * 
 * This structure contains the payload of a 802.11 management frame received
 * from a station. This frame can analyzed in the agent or tunnelled to the controller.
 */
struct sMGMT_FRAME_NOTIFICATION {
    sMacAddr mac;              /**< The MAC address of the station */
    sMacAddr bssid;            /**< The MAC address of the AP */
    eManagementFrameType type; /**< The type of the management frame */
    std::vector<uint8_t> data; /**< Frame body */
};

/**
 * @brief station connection failure related parameters.
 * 
 * This structure contains the parameters of the station connection failure
 * message like the mac address of the station and the bssid of the interface.
 */
struct sStaConnectionFail {
    sMacAddr bssid;   /**< The BSSID of the AP's interface */
    sMacAddr sta_mac; /**< The MAC address of the station */
};
} // namespace bwl

#endif // _BWL_BASE_WLAN_HAL_TYPES_H_
