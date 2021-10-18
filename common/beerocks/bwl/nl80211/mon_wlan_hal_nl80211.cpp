/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "mon_wlan_hal_nl80211.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

#include <easylogging++.h>

#include <cmath>

extern "C" {
#include <wpa_ctrl.h>
}

#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

namespace bwl {
namespace nl80211 {

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

enum ie_type : uint8_t {
    TYPE_SSID                     = 0,
    TYPE_SUPPORTED_RATES          = 1,
    TYPE_TIM                      = 5,
    TYPE_BSS_LOAD                 = 11,
    TYPE_RSN                      = 48,
    TYPE_EXTENDED_SUPPORTED_RATES = 50,
    TYPE_HT_OPERATION             = 61,
    TYPE_VHT_OPERATION            = 192,
    TYPE_VENDOR                   = 221,
    TYPE_EXTENISON                = 255
};
/* Element ID Extension (EID 255) values */
enum ie_id_extension_values : uint8_t { TYPE_EXT_HE_CAPABILITIES = 35, TYPE_EXT_HE_OPERATION = 36 };

#ifndef BIT
// BIT(0) -> 0x1, BIT(1) -> 0x10, BIT(2) -> 0x100, etc.
#define BIT(x) (1ULL << (x))
#endif
#define WLAN_CAPABILITY_ESS BIT(0)
#define WLAN_CAPABILITY_IBSS BIT(1)
#define WLAN_CAPABILITY_PRIVACY BIT(4)
#define GET_OP_CLASS(channel) ((channel < 14) ? 4 : 5)
#define BUFFER_SIZE 4096

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

static mon_wlan_hal::Event wav_to_bwl_event(const std::string &opcode)
{
    if (opcode == "AP-STA-CONNECTED") {
        return mon_wlan_hal::Event::STA_Connected;
    } else if (opcode == "AP-STA-DISCONNECTED") {
        return mon_wlan_hal::Event::STA_Disconnected;
    } else if (opcode == "BEACON-REQ-TX-STATUS") {
        return mon_wlan_hal::Event::RRM_Beacon_Request_Status;
    } else if (opcode == "BEACON-RESP-RX") {
        return mon_wlan_hal::Event::RRM_Beacon_Response;
    }
    // } else if (opcode == "RRM-LINK-MEASUREMENT-RECEIVED") {

    return mon_wlan_hal::Event::Invalid;
}

static mon_wlan_hal::Event scan_nl_to_bwl_event(uint8_t cmd)
{
    switch (cmd) {
    case NL80211_CMD_TRIGGER_SCAN:
        return mon_wlan_hal::Event::Channel_Scan_Triggered;
    case NL80211_CMD_NEW_SCAN_RESULTS:
        return mon_wlan_hal::Event::Channel_Scan_Dump_Result;
    case NL80211_CMD_SCAN_ABORTED:
        return mon_wlan_hal::Event::Channel_Scan_Aborted;
    default:
        LOG(ERROR) << "Unknown event received: " << int(cmd);
        return mon_wlan_hal::Event::Invalid;
    }
}

/**
+ * @brief get channel pool frquencies for channel scan parameters.
+ *
+ * @param [in] channel_pool list of channels to be scanned.
+ * @param [in] curr_channel channel teh radio is currently on.
+ * @param [in] iface radio interface name.
+ * @param [out] scan_params for saving channel frequencies for next scan.
+ * @return true on success
+ */
static bool read_nl_data_from_msg(struct nlattr **bss, struct nl_msg *msg)
{
    struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];

    if (!bss || !msg) {
        LOG(ERROR) << "invalid input bss=" << bss << ", msg=" << msg;
        return false;
    }

    bss_policy[NL80211_BSS_BSSID]                = {};
    bss_policy[NL80211_BSS_FREQUENCY].type       = NLA_U32;
    bss_policy[NL80211_BSS_TSF].type             = NLA_U64;
    bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bss_policy[NL80211_BSS_CAPABILITY].type      = NLA_U16;
    bss_policy[NL80211_BSS_INFORMATION_ELEMENTS] = {};
    bss_policy[NL80211_BSS_SIGNAL_MBM].type      = NLA_U32;
    bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type   = NLA_U8;
    bss_policy[NL80211_BSS_STATUS].type          = NLA_U32;
    bss_policy[NL80211_BSS_SEEN_MS_AGO].type     = NLA_U32;
    bss_policy[NL80211_BSS_BEACON_IES]           = {};

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS]) {
        LOG(ERROR) << "netlink message is missing the BSS attribute";
        return false;
    }
    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy)) {
        LOG(ERROR) << "Failed parsing nested netlink BSS attribute";
        return false;
    }
    if (!bss[NL80211_BSS_BSSID]) {
        LOG(ERROR) << "netlink message is missing the BSSID attribute";
        return false;
    }

    return true;
}

static void get_ht_oper(const uint8_t *data, sChannelScanResults &results)
{
    if (!data) {
        LOG(ERROR) << "data buffer is NULL";
        return;
    }

    if (!(data[1] & 0x3)) {
        results.operating_channel_bandwidth =
            eChannelScanResultChannelBandwidth::eChannel_Bandwidth_20MHz;
    } else if ((data[1] & 0x3) != 2) {
        results.operating_channel_bandwidth =
            eChannelScanResultChannelBandwidth::eChannel_Bandwidth_40MHz;
    }

    results.supported_standards.push_back(eChannelScanResultStandards::eStandard_802_11n);
    results.operating_standards = eChannelScanResultStandards::eStandard_802_11n;
}

static void get_vht_oper(const uint8_t *data, sChannelScanResults &results)
{
    if (!data) {
        LOG(ERROR) << "data buffer is NULL";
        return;
    }

    if (data[0] == 0x01) {
        if (data[2]) {
            results.operating_channel_bandwidth =
                eChannelScanResultChannelBandwidth::eChannel_Bandwidth_160MHz;
        } else {
            results.operating_channel_bandwidth =
                eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80MHz;
        }
    }

    if (data[0] == 0x02) {
        results.operating_channel_bandwidth =
            eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80MHz;
    }

    if (data[0] == 0x03) {
        results.operating_channel_bandwidth =
            eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80_80;
    }

    if (data[0] > 0x03) {
        LOG(ERROR) << "illegal TYPE_VHT_OPERATION value=" << data[0];
    }

    if (results.operating_frequency_band ==
        eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_5GHz) {
        results.supported_standards.push_back(eChannelScanResultStandards::eStandard_802_11ac);
        results.operating_standards = eChannelScanResultStandards::eStandard_802_11ac;
    }
}

static void get_supprates(const uint8_t *data, uint8_t len, sChannelScanResults &results)
{
    if (!data) {
        LOG(ERROR) << "data buffer is NULL";
        return;
    }

    for (int i = 0; i < len; i++) {
        uint8_t rate_mbs_fp_8_1 = data[i] & 0x7f;

        if (rate_mbs_fp_8_1 / 2 == 11) {
            if (results.operating_frequency_band ==
                eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_2_4GHz) {
                results.supported_standards.push_back(
                    eChannelScanResultStandards::eStandard_802_11b);
                results.operating_standards = eChannelScanResultStandards::eStandard_802_11b;
            }
        } else if (rate_mbs_fp_8_1 / 2 == 54) {
            if (results.operating_frequency_band ==
                eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_5GHz) {
                results.supported_standards.push_back(
                    eChannelScanResultStandards::eStandard_802_11a);
                results.operating_standards = eChannelScanResultStandards::eStandard_802_11a;
            }
        }

        /**
         * rate_mbs_fp_8_1 is tx data rate in mbps
         * represented with fixed point u<8,1>.
         * converting to kbps (no fixpoint) for simplicity u<8,0>
         */
        uint32_t rate_kbs = (rate_mbs_fp_8_1 / 2) * 1000 + (5 * (rate_mbs_fp_8_1 & 1)) * 100;

        if (data[i] & 0x80) {
            results.basic_data_transfer_rates_kbps.push_back(rate_kbs);
        } else {
            results.supported_data_transfer_rates_kbps.push_back(rate_kbs);
        }
    }
}

// Allow parsing for the neighbor's HE capabilities information
static void get_he_capabilities(const uint8_t *data, uint8_t len, sChannelScanResults &results)
{
    if (len <= 7) {
        LOG(ERROR) << "Length of he capabilities elem is " << len << " <= 7";
        return;
    }
    /**
     * [0] = elem_id ; [1-6] = MAC capab ; [7-17] = PHY capab
     * PHY_capab[0] = 1 BIT resv + 7 BITs for Supported Channel Width Set
     */

    // TODO Add wifi capabilities to ChannelScanResults

    results.supported_standards.push_back(eChannelScanResultStandards::eStandard_802_11ax);
    results.operating_standards = eChannelScanResultStandards::eStandard_802_11ax;
}

// Allow parsing for the neighbor's HE operation information
static void get_he_operation(const uint8_t *data, uint8_t len, sChannelScanResults &results)
{
    if (len <= 4) {
        LOG(ERROR) << "Length of he operation elem is " << len << " <= 4";
        return;
    }

    /**
     * [0] = elem_id ; [1-3] = HE Oper Params ; [4-4] = BSS color; [5-6] = MCS NSS; [7-9] VHT oper info;
     * HE_Oper_Params.bits[14] = VHT Oper Info Present boolean
     */
    if (results.operating_frequency_band !=
            eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_5GHz ||
        !(data[2] & BIT(6))) {
        LOG(ERROR) << "Unable to parse the HE operation element";
        return;
    }

    if (len <= 9) {
        LOG(INFO) << "VHT oper info present bit is on, by len is " << len;
    }

    int center_freq_seg0 = data[7];
    int center_freq_seg1 = data[8];
    switch (center_freq_seg0) {
    // Set to 1 for 80 MHz, 160 MHz or 80+80 MHz BSS bandwidth
    case 1: {
        if (center_freq_seg1) {
            if (abs(center_freq_seg1 - center_freq_seg0) == 16) {
                results.operating_channel_bandwidth =
                    eChannelScanResultChannelBandwidth::eChannel_Bandwidth_160MHz;
            } else {
                results.operating_channel_bandwidth =
                    eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80_80;
            }
        } else {
            results.operating_channel_bandwidth =
                eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80MHz;
        }
    } break;
    case 2: {
        results.operating_channel_bandwidth =
            eChannelScanResultChannelBandwidth::eChannel_Bandwidth_160MHz;
    } break;
    case 3: {
        results.operating_channel_bandwidth =
            eChannelScanResultChannelBandwidth::eChannel_Bandwidth_80_80;
    } break;
    default: {
        if (center_freq_seg0) {
            LOG(ERROR) << "illegal, values in the range 4 to 255 are reserved.";
        }
    } break;
    }
    results.supported_standards.push_back(eChannelScanResultStandards::eStandard_802_11ax);
    results.operating_standards = eChannelScanResultStandards::eStandard_802_11ax;
}

static void parse_info_elements(unsigned char *ie, int ielen, sChannelScanResults &results)
{
    if (!ie) {
        LOG(ERROR) << "info elements buffer is NULL";
        return;
    }

    while (ielen >= 2 && ielen >= ie[1]) {
        auto key      = ie[0];
        auto length   = ie[1];
        uint8_t *data = ie + 2;

        switch (key) {
        case ie_type::TYPE_SSID: {
            if (length > 32) {
                LOG(ERROR) << "TYPE_SSID doesn't match min and max length criteria";
                break;
            }
            std::copy_n(data, length, results.ssid);
        } break;

        case ie_type::TYPE_SUPPORTED_RATES: {
            get_supprates(data, length, results);
        } break;

        case ie_type::TYPE_TIM: {
            if (length < 4) {
                LOG(ERROR) << "TYPE_TIM doesn't match min and max length criteria";
                break;
            }
            results.dtim_period = (uint32_t)data[1];
        } break;

        case ie_type::TYPE_BSS_LOAD: {
            if (length != 5) {
                LOG(ERROR) << "TYPE_BSS_LOAD doesn't match min and max length criteria";
                break;
            }
            results.channel_utilization = (uint32_t)(data[2] / 255);
        } break;

        case ie_type::TYPE_RSN: {
            if (length < 2) {
                LOG(ERROR) << "TYPE_RSN doesn't match min and max length criteria";
                break;
            }
            results.encryption_mode.push_back(
                eChannelScanResultEncryptionMode::eEncryption_Mode_AES);
            results.security_mode_enabled.push_back(
                eChannelScanResultSecurityMode::eSecurity_Mode_WPA2);
        } break;

        case ie_type::TYPE_EXTENDED_SUPPORTED_RATES: {

            if (results.operating_frequency_band ==
                eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_2_4GHz) {
                results.supported_standards.push_back(
                    eChannelScanResultStandards::eStandard_802_11g);
                results.operating_standards = eChannelScanResultStandards::eStandard_802_11g;
            }

            get_supprates(data, length, results);

        } break;

        case ie_type::TYPE_HT_OPERATION: {
            if (length != 22) {
                LOG(ERROR) << "TYPE_HT_OPERATION doesn't match min and max length criteria";
                break;
            }
            get_ht_oper(data, results);
        } break;

        case ie_type::TYPE_VHT_OPERATION: {
            if (length < 5) {
                LOG(ERROR) << "TYPE_VHT_OPERATION doesn't match min and max length criteria";
                break;
            }
            get_vht_oper(data, results);
        } break;

        case ie_type::TYPE_EXTENISON: {
            if (length == 0) {
                LOG(ERROR) << "TYPE_EXTENISON doesn't match min and max length criteria";
                break;
            }
            if (data[0] == ie_id_extension_values::TYPE_EXT_HE_CAPABILITIES) {
                get_he_capabilities(data, length, results);
            } else if (data[0] == ie_id_extension_values::TYPE_EXT_HE_OPERATION) {
                get_he_operation(data, length, results);
            }
        } break;

        default: {
            // Ignoring received element as it is unhandled
            // LOG(DEBUG) << "Unhandled element received: " << int(key);
        } break;
        }

        ielen -= length + 2;
        ie += length + 2;
    }
}

static bool translate_nl_data_to_bwl_results(sChannelScanResults &results,
                                             const struct nlattr **bss)
{
    if (!bss[NL80211_BSS_BSSID]) {
        LOG(ERROR) << "Invalid BSSID in the netlink message";
        return false;
    }

    std::copy_n(reinterpret_cast<unsigned char *>(nla_data(bss[NL80211_BSS_BSSID])),
                sizeof(results.bssid), results.bssid.oct);

    //get channel and operating frequency band
    if (bss[NL80211_BSS_FREQUENCY]) {
        int freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        if (freq >= 5180) {
            results.operating_frequency_band =
                eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_5GHz;
        } else {
            results.operating_frequency_band =
                eChannelScanResultOperatingFrequencyBand::eOperating_Freq_Band_2_4GHz;
        }
        results.channel = son::wireless_utils::freq_to_channel(freq);
    }

    // get beacon period
    if (bss[NL80211_BSS_BEACON_INTERVAL]) {
        results.beacon_period_ms = (unsigned int)nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
    }

    // get signal strength, signal strength units not specified, scaled to 0-100
    if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
        //signal strength of the probe response/beacon in unspecified units, scaled to 0..100 <u8>
        results.signal_strength_dBm = int32_t(nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]));
    } else if (bss[NL80211_BSS_SIGNAL_MBM]) {
        //signal strength of probe response/beacon in mBm (100 * dBm) <s32>
        results.signal_strength_dBm = int32_t(nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM])) / 100;
    }

    //get information elements from information-elements-buffer or from beacon
    if (bss[NL80211_BSS_BEACON_IES] || bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        enum nl80211_bss ies_index = (bss[NL80211_BSS_INFORMATION_ELEMENTS])
                                         ? NL80211_BSS_INFORMATION_ELEMENTS
                                         : NL80211_BSS_BEACON_IES;
        parse_info_elements((unsigned char *)nla_data(bss[ies_index]), nla_len(bss[ies_index]),
                            results);
    }

    //get capabilities: mode, security_mode_enabled
    if (bss[NL80211_BSS_CAPABILITY]) {
        uint16_t capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);

        if (capa & WLAN_CAPABILITY_IBSS) {
            results.mode = eChannelScanResultMode::eMode_AdHoc;
        } else if (capa & WLAN_CAPABILITY_ESS) {
            results.mode = eChannelScanResultMode::eMode_Infrastructure;
        }

        if (results.security_mode_enabled.size() == 0) {
            if (capa & WLAN_CAPABILITY_PRIVACY) {
                results.security_mode_enabled.push_back(
                    eChannelScanResultSecurityMode::eSecurity_Mode_WEP);
            } else {
                results.security_mode_enabled.push_back(
                    eChannelScanResultSecurityMode::eSecurity_Mode_None);
            }
        }
    }

    return true;
}

static bool get_scan_results_from_nl_msg(sChannelScanResults &results, struct nl_msg *msg)
{
    struct nlattr *bss[NL80211_BSS_MAX + 1];

    if (!msg) {
        LOG(ERROR) << "invalid input: msg==NULL" << msg;
        return false;
    }

    //read msg buffer into nl attributes struct
    if (!read_nl_data_from_msg(bss, msg)) {
        LOG(ERROR) << "failed to parse netlink message";
        return false;
    }

    if (!translate_nl_data_to_bwl_results(results, (const nlattr **)bss)) {
        LOG(ERROR) << "failed to translate nl data to BWL results";
        return false;
    }

    return true;
}

#if 0

static void calc_curr_traffic(std::string buff, uint64_t &total, uint32_t &curr)
{
    // Convert to numeric value
    uint64_t val = beerocks::string_utils::stoi(buff);

    if (val >= total) {
        curr = val - total;
    } else {
        curr = val;
    }
    total = val;
}

#endif

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

mon_wlan_hal_nl80211::mon_wlan_hal_nl80211(const std::string &iface_name, hal_event_cb_t callback,
                                           const bwl::hal_conf_t &hal_conf)
    : base_wlan_hal(bwl::HALType::Monitor, iface_name, IfaceType::Intel, callback, hal_conf),
      base_wlan_hal_nl80211(bwl::HALType::Monitor, iface_name, callback, BUFFER_SIZE, hal_conf)
{
}

mon_wlan_hal_nl80211::~mon_wlan_hal_nl80211() {}

bool mon_wlan_hal_nl80211::update_radio_stats(SRadioStats &radio_stats)
{
    beerocks::net::sInterfaceStats iface_stats;
    if (!beerocks::net::network_utils::get_iface_stats(get_iface_name(), iface_stats)) {
        LOG(ERROR) << "Failed to get interface statistics for interface " << get_iface_name();
        return false;
    }

    calc_curr_traffic(iface_stats.tx_bytes, radio_stats.tx_bytes_cnt, radio_stats.tx_bytes);
    calc_curr_traffic(iface_stats.rx_bytes, radio_stats.rx_bytes_cnt, radio_stats.rx_bytes);
    calc_curr_traffic(iface_stats.tx_packets, radio_stats.tx_packets_cnt, radio_stats.tx_packets);
    calc_curr_traffic(iface_stats.rx_packets, radio_stats.rx_packets_cnt, radio_stats.rx_packets);

    radio_stats.errors_sent     = iface_stats.tx_errors;
    radio_stats.errors_received = iface_stats.rx_errors;
    radio_stats.noise           = 0;

    return true;
}

bool mon_wlan_hal_nl80211::update_vap_stats(const std::string &vap_iface_name, SVapStats &vap_stats)
{
    beerocks::net::sInterfaceStats iface_stats;
    if (!beerocks::net::network_utils::get_iface_stats(vap_iface_name, iface_stats)) {
        LOG(ERROR) << "Failed to get interface statistics for interface " << vap_iface_name;
        return false;
    }

    calc_curr_traffic(iface_stats.tx_bytes, vap_stats.tx_bytes_cnt, vap_stats.tx_bytes);
    calc_curr_traffic(iface_stats.rx_bytes, vap_stats.rx_bytes_cnt, vap_stats.rx_bytes);
    calc_curr_traffic(iface_stats.tx_packets, vap_stats.tx_packets_cnt, vap_stats.tx_packets);
    calc_curr_traffic(iface_stats.rx_packets, vap_stats.rx_packets_cnt, vap_stats.rx_packets);

    vap_stats.errors_sent     = iface_stats.tx_errors;
    vap_stats.errors_received = iface_stats.rx_errors;
    vap_stats.retrans_count   = 0;

    return true;
}

bool mon_wlan_hal_nl80211::update_stations_stats(const std::string &vap_iface_name,
                                                 const std::string &sta_mac, SStaStats &sta_stats)
{
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1];
    stats_policy[NL80211_STA_INFO_INACTIVE_TIME] = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_RX_BYTES]      = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_TX_BYTES]      = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_RX_PACKETS]    = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_TX_PACKETS]    = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_SIGNAL]        = {NLA_U8, 0, 0};
    stats_policy[NL80211_STA_INFO_T_OFFSET]      = {NLA_U64, 0, 0};
    stats_policy[NL80211_STA_INFO_TX_BITRATE]    = {NLA_NESTED, 0, 0};
    stats_policy[NL80211_STA_INFO_RX_BITRATE]    = {NLA_NESTED, 0, 0};
    stats_policy[NL80211_STA_INFO_LLID]          = {NLA_U16, 0, 0};
    stats_policy[NL80211_STA_INFO_PLID]          = {NLA_U16, 0, 0};
    stats_policy[NL80211_STA_INFO_PLINK_STATE]   = {NLA_U8, 0, 0};
    stats_policy[NL80211_STA_INFO_TX_RETRIES]    = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_TX_FAILED]     = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_STA_FLAGS]  = {NLA_UNSPEC, sizeof(struct nl80211_sta_flag_update),
                                                0};
    stats_policy[NL80211_STA_INFO_LOCAL_PM]   = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_PEER_PM]    = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_NONPEER_PM] = {NLA_U32, 0, 0};
    stats_policy[NL80211_STA_INFO_CHAIN_SIGNAL]     = {NLA_NESTED, 0, 0};
    stats_policy[NL80211_STA_INFO_CHAIN_SIGNAL_AVG] = {NLA_NESTED, 0, 0};

    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1];
    rate_policy[NL80211_RATE_INFO_BITRATE]      = {NLA_U16, 0, 0};
    rate_policy[NL80211_RATE_INFO_BITRATE32]    = {NLA_U32, 0, 0};
    rate_policy[NL80211_RATE_INFO_MCS]          = {NLA_U8, 0, 0};
    rate_policy[NL80211_RATE_INFO_40_MHZ_WIDTH] = {NLA_FLAG, 0, 0};
    rate_policy[NL80211_RATE_INFO_SHORT_GI]     = {NLA_FLAG, 0, 0};

    auto ret = send_nl80211_msg(
        NL80211_CMD_GET_STATION, 0,
        // Create the message
        [&](struct nl_msg *msg) -> bool {
            auto mac = tlvf::mac_from_string(sta_mac);
            nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac.oct);
            return true;
        },
        // Handle the reponse
        [&](struct nl_msg *msg) -> bool {
            struct nlattr *tb[NL80211_ATTR_MAX + 1];
            struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
            struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
            struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];

            // Parse the netlink message
            nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
                      NULL);

            if (!tb[NL80211_ATTR_STA_INFO]) {
                LOG(ERROR) << "sta stats missing!";
                return false;
            }

            // Parse nested station stats
            if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO],
                                 stats_policy)) {
                LOG(ERROR) << "failed to parse nested attributes!";
                return false;
            }

            // RX RSSI
            if (sinfo[NL80211_STA_INFO_SIGNAL]) {
                int8_t signal          = int8_t(nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]));
                sta_stats.rx_rssi_watt = pow(10, (signal / 10.0));
                sta_stats.rx_rssi_watt_samples_cnt++;
            }

            // RX SNR is not supported
            sta_stats.rx_snr_watt             = 0;
            sta_stats.rx_snr_watt_samples_cnt = 0;

            // Bitrate parsing helper function
            auto parse_bitrate_func = [&](struct nlattr *bitrate_attr) -> int {
                if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, bitrate_attr, rate_policy)) {
                    LOG(ERROR) << "Failed to parse nested rate attributes!";
                    return 0;
                }

                int rate = 0;
                if (rinfo[NL80211_RATE_INFO_BITRATE32])
                    rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
                else if (rinfo[NL80211_RATE_INFO_BITRATE])
                    rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);

                return rate;
            };

            // TX Phy Rate
            if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
                sta_stats.tx_phy_rate_100kb =
                    parse_bitrate_func(sinfo[NL80211_STA_INFO_TX_BITRATE]) / 100;
            }

            // RX Phy Rate
            if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
                sta_stats.rx_phy_rate_100kb =
                    parse_bitrate_func(sinfo[NL80211_STA_INFO_RX_BITRATE]) / 100;
            }

            // Traffic values calculations helper function
            auto calc_curr_traffic = [](uint64_t val, uint64_t &total, uint32_t &curr) {
                if (val >= total) {
                    curr = val - total;
                } else {
                    curr = val;
                }
                total = val;
            };

            // TX Bytes
            if (sinfo[NL80211_STA_INFO_TX_BYTES]) {
                calc_curr_traffic(nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]),
                                  sta_stats.tx_bytes_cnt, sta_stats.tx_bytes);
            }

            // RX Bytes
            if (sinfo[NL80211_STA_INFO_RX_BYTES]) {
                calc_curr_traffic(nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]),
                                  sta_stats.rx_bytes_cnt, sta_stats.rx_bytes);
            }

            // TX Packets
            if (sinfo[NL80211_STA_INFO_TX_PACKETS]) {
                calc_curr_traffic(nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]),
                                  sta_stats.tx_packets_cnt, sta_stats.tx_packets);
            }

            // RX Packets
            if (sinfo[NL80211_STA_INFO_RX_PACKETS]) {
                calc_curr_traffic(nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]),
                                  sta_stats.rx_packets_cnt, sta_stats.rx_packets);
            }

            // TX Retries
            if (sinfo[NL80211_STA_INFO_TX_RETRIES]) {
                sta_stats.retrans_count = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);
            }

            return true;
        });

    if (!ret) {
        LOG(ERROR) << "Failed updating stats for station: " << sta_mac;
        return false;
    }

    return true;
}

bool mon_wlan_hal_nl80211::sta_channel_load_11k_request(const SStaChannelLoadRequest11k &req)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool mon_wlan_hal_nl80211::sta_beacon_11k_request(const SBeaconRequest11k &req, int &dialog_token)
{
    LOG(TRACE) << __func__;

    // parameters preperations

    // Mode
    auto request = (!req.enable) ? 0 : req.request;
    auto report  = (!req.enable) ? 0 : req.report;

    uint8_t req_mode = (req.parallel | (req.enable ? 0x02 : 0) | (request ? 0x04 : 0) |
                        (report ? 0x08 : 0) | (req.mandatory_duration ? 0x10 : 0));

    auto op_class = req.op_class < 0 ? GET_OP_CLASS(get_radio_info().channel) : req.op_class;

    if (req.op_class <= 0) {
        LOG(WARNING) << __func__ << " op_class not set!";
    }

    uint8_t measurement_mode;
    switch ((SBeaconRequest11k::MeasurementMode)(req.measurement_mode)) {
    case SBeaconRequest11k::MeasurementMode::Passive:
        measurement_mode = 0;
        break;
    case SBeaconRequest11k::MeasurementMode::Active:
        measurement_mode = 1;
        break;
    case SBeaconRequest11k::MeasurementMode::Table:
        measurement_mode = 2;
        break;
    default: {
        LOG(WARNING) << "Invalid measuremetn mode: " << int(req.measurement_mode)
                     << ", using PASSIVE...";

        measurement_mode = 0;
    }
    }

    // REQ_BEACON 02:14:5f:b8:ae:9f req_mode=01 510B000011110004f021318193
    // op_class (2), channel (2), randomization_interval (4), measurement duration (4), measurement mode (2), bssid (12)

    // build command
    std::string cmd = "REQ_BEACON " + tlvf::mac_to_string(req.sta_mac.oct) +
                      " " + // Destination MAC Address
                      "req_mode=" + beerocks::string_utils::int_to_hex_string(req_mode, 2) +
                      " " + // Measurements Request Mode
                      beerocks::string_utils::int_to_hex_string(op_class, 2) +
                      beerocks::string_utils::int_to_hex_string(req.channel, 2) +
                      beerocks::string_utils::int_to_hex_string(htobe16(req.rand_ival), 4) +
                      beerocks::string_utils::int_to_hex_string(htobe16(req.duration), 4) +
                      beerocks::string_utils::int_to_hex_string(measurement_mode, 2) +
                      beerocks::string_utils::int_to_hex_string(req.bssid.oct[0], 2) +
                      beerocks::string_utils::int_to_hex_string(req.bssid.oct[1], 2) +
                      beerocks::string_utils::int_to_hex_string(req.bssid.oct[2], 2) +
                      beerocks::string_utils::int_to_hex_string(req.bssid.oct[3], 2) +
                      beerocks::string_utils::int_to_hex_string(req.bssid.oct[4], 2) +
                      beerocks::string_utils::int_to_hex_string(req.bssid.oct[5], 2) +
                      // Reporting detail subelement
                      // subelement id (2):
                      beerocks::string_utils::int_to_hex_string(2, 2) +
                      // length:
                      beerocks::string_utils::int_to_hex_string(1, 2) +
                      // value:
                      beerocks::string_utils::int_to_hex_string(req.reporting_detail, 2);

    if (req.use_optional_ap_ch_report != 0) {
        if (req.channel != 255) {
            LOG(ERROR) << "ap_ch_report is set but channel is NOT set to 255.";
            return false;
        }

        // AP channel report
        // subelement id:
        cmd += beerocks::string_utils::int_to_hex_string(51, 2) +
               // length:
               beerocks::string_utils::int_to_hex_string(req.use_optional_ap_ch_report, 2);
        // operating class followed by list of channels:
        unsigned ap_ch_report_size = req.use_optional_ap_ch_report;
        if (ap_ch_report_size > sizeof(req.ap_ch_report)) {
            LOG(ERROR)
                << "use_optional_ap_ch_report is bigger than the total size of ap_ch_report! "
                   "use_optional_ap_ch_report is "
                << req.use_optional_ap_ch_report;
            return false;
        }
        for (unsigned i = 0; i < ap_ch_report_size; i++) {
            cmd += beerocks::string_utils::int_to_hex_string(req.ap_ch_report[i], 2);
        }
    } else {
        if (req.channel == 255) {
            LOG(ERROR) << "Channel is set to 255 but ap_ch_report is NOT set.";
        }
    }

    // Print the command
    LOG(DEBUG) << __func__ << " - " << cmd;

    // Send the command
    parsed_obj_map_t reply;
    if (!wpa_ctrl_send_msg(cmd, reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    dialog_token = 0; //tmp_int;

    return true;
}

bool mon_wlan_hal_nl80211::sta_link_measurements_11k_request(const std::string &sta_mac)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool mon_wlan_hal_nl80211::channel_scan_trigger(int dwell_time_msec,
                                                const std::vector<unsigned int> &channel_pool)
{
    LOG(DEBUG) << "nl80211 Scan trigger: received on interface=" << m_radio_info.iface_name;

    // TODO: build background scan parameters (dwell_time ...)

    auto ret = nl80211_channel_scan_trigger(
        // Create the message
        [&](struct nl_msg *msg) -> bool {
            LOG(DEBUG) << "nl80211 Scan trigger: Create the nl message !";
            struct nlattr *freqs;

            freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
            if (freqs == NULL) {
                LOG(ERROR) << "nl80211 Scan trigger: nl nest start freq failed";
                return false;
            }
            int freq_index = 0;
            for (auto channel : channel_pool) {
                //channel validation
                LOG(DEBUG) << "nl80211 Scan trigger: validating pool channel=" << channel;
                if (son::wireless_utils::which_freq(m_radio_info.channel) !=
                    son::wireless_utils::which_freq(channel)) {
                    LOG(ERROR) << "nl80211 Scan trigger: cannot scan channel = " << channel
                               << " not on the same radio interface =  " << m_radio_info.iface_name;
                    return false;
                }

                auto freq = son::wireless_utils::channel_to_freq(int(channel));
                LOG(DEBUG) << "nl80211 Scan trigger: put scan frequency " << freq << "MHz";
                freq_index++;
                if (nla_put_u32(msg, freq_index, freq) != 0) {
                    LOG(ERROR) << "nl80211 Scan trigger: nla put failed";
                    return false;
                }
            }
            nla_nest_end(msg, freqs);
            return true;
        },
        // Handle the reponse
        [&](struct nl_msg *msg) -> bool {
            LOG(DEBUG) << "nl80211 Scan trigger: Handle the reponse !";
            if (!process_scan_nl_event(msg)) {
                LOG(ERROR) << "nl80211 Scan trigger: User's netlink handler function failed!";
                return false;
            }
            return true;
        });

    if (!ret) {
        LOG(ERROR) << "nl80211 Scan trigger: cmd failed";
        return false;
    }

    m_scan_was_triggered_internally = true;

    return true;
}

bool mon_wlan_hal_nl80211::channel_scan_dump_cached_results()
{
    m_nl_seq                        = 0;
    m_scan_was_triggered_internally = true;
    return channel_scan_dump_results();
}

bool mon_wlan_hal_nl80211::channel_scan_dump_results()
{
    LOG(DEBUG) << "nl80211 Scan dump results: received on interface=" << m_radio_info.iface_name;

    auto ret = nl80211_channel_scan_dump_results(
        // Handle the reponse
        [&](struct nl_msg *msg) -> bool {
            LOG(DEBUG) << "nl80211 Scan dump results: Handle the reponse !";
            if (!process_scan_nl_event(msg)) {
                LOG(ERROR) << "nl80211 Scan dump results: User's netlink handler function failed!";
                return false;
            }
            return true;
        });

    if (!ret) {
        LOG(ERROR) << "nl80211 Scan dump results: cmd failed";
        return false;
    }

    // If scan dump succeeded need to manually send the finished event
    LOG(DEBUG) << "nl80211 Scan dump results: Scan sequence: " << (int)m_nl_seq
               << " finished, sending Finish notification.";

    //reset scan indicators for next scan
    m_nl_seq                        = 0;
    m_scan_dump_in_progress         = false;
    m_scan_was_triggered_internally = false;

    event_queue_push(Event::Channel_Scan_Finished);

    return true;
}

bool mon_wlan_hal_nl80211::generate_connected_clients_events(
    bool &is_finished_all_clients, std::chrono::steady_clock::time_point max_iteration_timeout)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";
    is_finished_all_clients = true;

    // TODO: implement the API (PPM-1152)
    // currently returning true even though not implemented in order not to break
    // the flow if this HAL is used by any flow, since the API return value is checked by
    // a common flow in the monitor.
    return true;
}

bool mon_wlan_hal_nl80211::pre_generate_connected_clients_events()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED";

    // TODO: implement the API (PPM-1152)
    // currently returning true even though not implemented in order not to break
    // the flow if this HAL is used by any flow, since the API return value is checked by
    // a common flow in the monitor.
    return true;
}

bool mon_wlan_hal_nl80211::process_nl80211_event(parsed_obj_map_t &parsed_obj)
{
    // Filter out empty events
    std::string opcode;
    if (!(parsed_obj.find("_opcode") != parsed_obj.end() &&
          !(opcode = parsed_obj["_opcode"]).empty())) {
        return true;
    }

    auto event = wav_to_bwl_event(opcode);

    // Handle the event
    switch (event) {

    case Event::STA_Connected: {

        // TODO: Change to HAL objects
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_ASSOCIATED_NOTIFICATION));

        msg->vap_id = 0;
        msg->mac    = tlvf::mac_from_string(parsed_obj["_mac"]);

        // Add the message to the queue
        event_queue_push(Event::STA_Connected, msg_buff);

    } break;

    case Event::STA_Disconnected: {

        // TODO: Change to HAL objects
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_MONITOR_CLIENT_DISCONNECTED_NOTIFICATION));

        // Store the MAC address of the disconnected STA
        msg->mac = tlvf::mac_from_string(parsed_obj["_mac"]);

        // Add the message to the queue
        event_queue_push(Event::STA_Disconnected, msg_buff);

    } break;

    case Event::RRM_Beacon_Request_Status: {

        // Allocate response object
        auto resp_buff = ALLOC_SMART_BUFFER(sizeof(SBeaconRequestStatus11k));
        auto resp      = reinterpret_cast<SBeaconRequestStatus11k *>(resp_buff.get());
        LOG_IF(!resp, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(resp_buff.get(), 0, sizeof(SBeaconRequestStatus11k));

        // STA Mac Address
        tlvf::mac_from_string(resp->sta_mac.oct, parsed_obj["_mac"]);

        // Dialog token and ACK
        resp->dialog_token = beerocks::string_utils::stoi(parsed_obj["_arg0"]);
        resp->ack          = beerocks::string_utils::stoi(parsed_obj["ack"]);

        // Add the message to the queue
        event_queue_push(event, resp_buff);

    } break;

    case Event::RRM_Beacon_Response: {

        // Allocate response object
        auto resp_buff = ALLOC_SMART_BUFFER(sizeof(SBeaconResponse11k));
        auto resp      = reinterpret_cast<SBeaconResponse11k *>(resp_buff.get());
        LOG_IF(!resp, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(resp_buff.get(), 0, sizeof(SBeaconResponse11k));

        // STA Mac Address
        tlvf::mac_from_string(resp->sta_mac.oct, parsed_obj["_mac"]);

        // Dialog token and rep_mode
        resp->dialog_token = beerocks::string_utils::stoi(parsed_obj["_arg0"]);
        resp->rep_mode     = beerocks::string_utils::stoi(parsed_obj["_arg1"]);

        // Parse the report
        auto report = parsed_obj["_arg2"];
        if (report.length() < 52) {
            LOG(WARNING) << "Invalid 11k report length!";
            break;
        }

        // TODO: Check for argument validity and use a safer stoi version
        int idx = 0;

        // op_class
        resp->op_class = std::strtoul(report.substr(idx, 2).c_str(), 0, 16);
        idx += 2;

        // channel
        resp->channel = std::strtoul(report.substr(idx, 2).c_str(), 0, 16);
        idx += 2;

        // start_time
        resp->start_time = std::strtoull(report.substr(idx, 16).c_str(), 0, 16);
        resp->start_time = be64toh(resp->start_time);
        idx += 16;

        // measurement_duration
        resp->duration = std::strtoul(report.substr(idx, 4).c_str(), 0, 16);
        resp->duration = be16toh(resp->duration);
        idx += 4;

        // phy_type
        resp->phy_type = std::strtoul(report.substr(idx, 2).c_str(), 0, 16);
        idx += 2;

        // rcpi
        resp->rcpi = std::strtol(report.substr(idx, 2).c_str(), 0, 16);
        idx += 2;

        // rsni
        resp->rsni = std::strtol(report.substr(idx, 2).c_str(), 0, 16);
        idx += 2;

        // bssid
        resp->bssid.oct[0] = std::strtoul(report.substr(idx + 0, 2).c_str(), 0, 16);
        resp->bssid.oct[1] = std::strtoul(report.substr(idx + 2, 2).c_str(), 0, 16);
        resp->bssid.oct[2] = std::strtoul(report.substr(idx + 4, 2).c_str(), 0, 16);
        resp->bssid.oct[3] = std::strtoul(report.substr(idx + 6, 2).c_str(), 0, 16);
        resp->bssid.oct[4] = std::strtoul(report.substr(idx + 8, 2).c_str(), 0, 16);
        resp->bssid.oct[5] = std::strtoul(report.substr(idx + 10, 2).c_str(), 0, 16);
        idx += 12;

        // ant_id
        resp->ant_id = std::strtoul(report.substr(idx, 2).c_str(), 0, 16);
        idx += 2;

        // parent_tsf
        resp->parent_tsf = std::strtoull(report.substr(idx, 8).c_str(), 0, 16);
        idx += 8;

        // TODO: Ignore everything else?
        // WLAN_BEACON_REPORT_SUBELEM_FRAME_BODY == 01
        // frame_body.length = ??

        LOG(DEBUG) << "Beacon Response:" << std::endl
                   << "  op_class = " << int(resp->op_class) << std::endl
                   << "  channel = " << int(resp->channel) << std::endl
                   << "  start_time = " << int(resp->start_time) << std::endl
                   << "  duration = " << int(resp->duration) << std::endl
                   << "  phy_type = " << int(resp->phy_type) << std::endl
                   << "  rcpi = " << int(resp->rcpi) << std::endl
                   << "  rsni = " << int(resp->rsni) << std::endl
                   << "  bssid = " << resp->bssid.oct << std::endl
                   << "  ant_id = " << int(resp->ant_id) << std::endl
                   << "  parent_tfs = " << int(resp->parent_tsf);

        // Add the message to the queue
        event_queue_push(event, resp_buff);

    } break;

    // Gracefully ignore unhandled events
    // TODO: Probably should be changed to an error once WAV will stop
    //       sending empty or irrelevant events...
    default: {
        LOG(DEBUG) << "Unhandled event received: " << opcode;
        break;
    };
    }

    return true;
}

bool mon_wlan_hal_nl80211::process_scan_nl_event(struct nl_msg *msg)
{
    struct nlmsghdr *nlh    = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlh);
    std::string iface_name;

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX]) {
        auto index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
        iface_name = beerocks::net::network_utils::linux_get_iface_name(index);
    }

    auto event = scan_nl_to_bwl_event(gnlh->cmd);

    switch (event) {
    case Event::Channel_Scan_Triggered: {
        if (m_radio_info.iface_name != iface_name) {
            // ifname doesn't match current interface
            // meaning the event was received for a diffrent channel
            return true;
        }
        if (!m_scan_was_triggered_internally) {
            // Scan was not triggered internally, no need to handle the event
            return true;
        }
        LOG(DEBUG) << "nl80211 event channel scan triggered";

        //start new sequence of dump results
        m_nl_seq = 0;
        event_queue_push(event);
        break;
    }
    case Event::Channel_Scan_Dump_Result: {
        if (m_radio_info.iface_name != iface_name) {
            // ifname doesn't match current interface
            // meaning the event was received for a diffrent channel
            return true;
        }
        if (!m_scan_was_triggered_internally) {
            // Scan was not triggered internally, no need to handle the event
            return true;
        }

        if (m_nl_seq == 0) {
            if (nlh->nlmsg_seq == 0) {
                // First "empty" Channel_Scan_Dump_Result message
                LOG(DEBUG) << "Results dump are ready";
                event_queue_push(Event::Channel_Scan_New_Results_Ready);
                m_scan_dump_in_progress = true;
                channel_scan_dump_results();
                return true;
            } else {
                //2nd -> Nth Channel_Scan_Dump_Result
                LOG(DEBUG) << "Results dump new sequence:" << int(nlh->nlmsg_seq);
                m_nl_seq = nlh->nlmsg_seq;
            }
        }

        // Check if current Channel_Scan_Dump_Result is part of the dump sequence.
        if (m_nl_seq != nlh->nlmsg_seq) {
            LOG(ERROR) << "channel scan results dump received with unexpected seq number";
            return false;
        }

        LOG(DEBUG) << "nl80211 event channel scan results dump, seq = " << int(nlh->nlmsg_seq);

        auto results = std::make_shared<sCHANNEL_SCAN_RESULTS_NOTIFICATION>();

        if (!get_scan_results_from_nl_msg(results->channel_scan_results, msg)) {
            LOG(ERROR) << "read NL msg to monitor msg failed!";
            return false;
        }

        LOG(DEBUG) << "Processing results for BSSID:" << results->channel_scan_results.bssid
                   << " on Channel: " << results->channel_scan_results.channel;
        event_queue_push(event, results);
        break;
    }
    case Event::Channel_Scan_Aborted: {

        if (m_radio_info.iface_name != iface_name) {
            // ifname doesn't match current interface
            // meaning the event was recevied for a diffrent channel
            return true;
        }
        if (!m_scan_was_triggered_internally) {
            // Scan was not triggered internally, no need to handle the event
            return true;
        }
        LOG(DEBUG) << "802.11 NL event channel scan aborted";

        //reset scan indicators for next scan
        m_nl_seq                        = 0;
        m_scan_dump_in_progress         = false;
        m_scan_was_triggered_internally = false;
        event_queue_push(event);
        break;
    }
    case Event::Channel_Scan_Finished: {
        if (!m_scan_was_triggered_internally) {
            // Scan was not triggered internally, no need to handle the event
            return true;
        }
        // We are not in a dump sequence, ignoring the message
        if (!m_scan_dump_in_progress) {
            return true;
        }

        // ifname is invalid  for Channel_Scan_Finished event using nlh->nlmsg_seq instead.
        // In case there are no results first check if current sequence number was set.
        if (m_nl_seq != 0 && nlh->nlmsg_seq != m_nl_seq) {
            // Current event has a sequence number not matching the current sequence number
            // meaning the event was recevied for a diffrent channel
            return true;
        }

        LOG(DEBUG) << "nl80211 event channel scan results finished for sequence: "
                   << (int)nlh->nlmsg_seq;

        //reset scan indicators for next scan
        m_nl_seq                        = 0;
        m_scan_dump_in_progress         = false;
        m_scan_was_triggered_internally = false;
        event_queue_push(event);
        break;
    }
    // Gracefully ignore unhandled events
    default:
        LOG(ERROR) << "Unknown nl80211 NL event received: " << int(event);
        break;
    }
    return true;
}

bool mon_wlan_hal_nl80211::channel_scan_abort()
{
    if (!m_nl80211_client->channel_scan_abort(get_iface_name())) {
        LOG(ERROR) << "Channel scan abort failed";
        return false;
    }

    return true;
}

bool mon_wlan_hal_nl80211::set_estimated_service_parameters(uint8_t *esp_info_field)
{
    // TO DO: Implement with PPM-1499
    return true;
}

} // namespace nl80211

std::shared_ptr<mon_wlan_hal> mon_wlan_hal_create(const std::string &iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback,

                                                  const bwl::hal_conf_t &hal_conf)
{
    return std::make_shared<nl80211::mon_wlan_hal_nl80211>(iface_name, callback, hal_conf);
}

} // namespace bwl
