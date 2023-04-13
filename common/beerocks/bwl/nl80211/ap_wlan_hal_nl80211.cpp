/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "ap_wlan_hal_nl80211.h"
#include <bcl/beerocks_os_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_assoc_frame_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <bwl/key_value_parser.h>
#include <cmath>
#include <easylogging++.h>
#include <hostapd/configuration.h>
#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <type_traits>

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace bwl {
namespace nl80211 {

#define BUFFER_SIZE 4096
#define CSA_EVENT_FILTERING_TIMEOUT_MS 1000

// Temporary storage for station capabilities
struct SRadioCapabilitiesStrings {
    std::string supported_rates;
    std::string ht_cap;
    std::string ht_mcs;
    std::string vht_cap;
    std::string vht_mcs;
    std::string btm_supported;
    std::string nr_enabled;
    std::string non_pref_chan;
    std::string cell_capa;
};

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

static ap_wlan_hal::Event nl80211_to_bwl_event(const std::string &opcode)
{
    if (opcode == "AP-ENABLED") {
        return ap_wlan_hal::Event::AP_Enabled;
    } else if (opcode == "AP-DISABLED") {
        return ap_wlan_hal::Event::AP_Disabled;
    } else if (opcode == "AP-STA-CONNECTED") {
        return ap_wlan_hal::Event::STA_Connected;
    } else if (opcode == "AP-STA-DISCONNECTED") {
        return ap_wlan_hal::Event::STA_Disconnected;
    } else if (opcode == "INTERFACE-ENABLED") {
        return ap_wlan_hal::Event::Interface_Enabled;
    } else if (opcode == "INTERFACE-DISABLED") {
        return ap_wlan_hal::Event::Interface_Disabled;
    } else if (opcode == "ACS-STARTED") {
        return ap_wlan_hal::Event::ACS_Started;
    } else if (opcode == "ACS-COMPLETED") {
        return ap_wlan_hal::Event::ACS_Completed;
    } else if (opcode == "ACS-FAILED") {
        return ap_wlan_hal::Event::ACS_Failed;
    } else if (opcode == "AP-CSA-FINISHED") {
        return ap_wlan_hal::Event::CSA_Finished;
    } else if (opcode == "CTRL-EVENT-CHANNEL-SWITCH") {
        return ap_wlan_hal::Event::CTRL_Channel_Switch;
    } else if (opcode == "BSS-TM-QUERY") {
        return ap_wlan_hal::Event::BSS_TM_Query;
    } else if (opcode == "BSS-TM-RESP") {
        return ap_wlan_hal::Event::BSS_TM_Response;
    } else if (opcode == "DFS-CAC-COMPLETED") {
        return ap_wlan_hal::Event::DFS_CAC_Completed;
    } else if (opcode == "DFS-NOP-FINISHED") {
        return ap_wlan_hal::Event::DFS_NOP_Finished;
    } else if (opcode == "AP-MGMT-FRAME-RECEIVED") {
        return ap_wlan_hal::Event::AP_MGMT_FRAME_RECEIVED;
    } else if (opcode == "WPA_EVENT_EAP_FAILURE") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Failure;
    } else if (opcode == "WPA_EVENT_EAP_FAILURE2") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Failure2;
    } else if (opcode == "WPA_EVENT_EAP_TIMEOUT_FAILURE") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Timeout_Failure;
    } else if (opcode == "WPA_EVENT_EAP_TIMEOUT_FAILURE2") {
        return ap_wlan_hal::Event::WPA_Event_EAP_Timeout_Failure2;
    } else if (opcode == "WPS_EVENT_TIMEOUT") {
        return ap_wlan_hal::Event::WPS_Event_Timeout;
    } else if (opcode == "WPS_EVENT_FAIL") {
        return ap_wlan_hal::Event::WPS_Event_Fail;
    } else if (opcode == "WPA_EVENT_SAE_UNKNOWN_PASSWORD_IDENTIFIER") {
        return ap_wlan_hal::Event::WPA_Event_SAE_Unknown_Password_Identifier;
    } else if (opcode == "WPS_EVENT_CANCEL") {
        return ap_wlan_hal::Event::WPS_Event_Cancel;
    } else if (opcode == "AP-STA-POSSIBLE-PSK-MISMATCH") {
        return ap_wlan_hal::Event::AP_Sta_Possible_Psk_Mismatch;
    }

    return ap_wlan_hal::Event::Invalid;
}

static uint8_t wpa_bw_to_beerocks_bw(const std::string &chan_width)
{
    // 20 MHz (no HT)
    // 20 MHz
    // 40 MHz
    // 80 MHz
    // 80+80 MHz
    // 160 MHz

    return (chan_width == "80+80") ? 160 : beerocks::string_utils::stoi(chan_width);
}

/// @brief figures out hostapd config file name by the
//  interface name and loads its content
static prplmesh::hostapd::Configuration load_hostapd_config(const std::string &radio_iface_name)
{
    std::vector<std::string> hostapd_cfg_names = {
        "/tmp/run/hostapd-phy0.conf", "/tmp/run/hostapd-phy1.conf", "/var/run/hostapd-phy0.conf",
        "/var/run/hostapd-phy1.conf", "/var/run/hostapd-phy2.conf", "/var/run/hostapd-phy3.conf",
        "/nvram/hostapd0.conf",       "/nvram/hostapd1.conf",       "/nvram/hostapd2.conf",
        "/nvram/hostapd3.conf",       "/nvram/hostapd4.conf",       "/nvram/hostapd5.conf",
        "/nvram/hostapd6.conf",       "/nvram/hostapd7.conf"};

    for (const auto &try_fname : hostapd_cfg_names) {
        LOG(DEBUG) << "Trying to load " << try_fname << "...";

        if (!beerocks::os_utils::file_exists(try_fname)) {
            continue;
        }

        prplmesh::hostapd::Configuration hostapd_conf(try_fname);

        // try loading
        if (!hostapd_conf.load("interface=", "bss=")) {
            LOG(ERROR) << "Failed to load hostapd config file: " << hostapd_conf;
            continue;
        }

        // check if it is the right one:
        // we are looking for the line in the vap that declares this vap: interface=radio_iface_name
        // we could equaly ask hostapd_conf if it has this vap, but there is no such interface
        // to do this. it should be something like: hostapd_conf.is_vap_exists(radio_iface_name);
        if (hostapd_conf.get_vap_value(radio_iface_name, "interface") != radio_iface_name &&
            hostapd_conf.get_vap_value(radio_iface_name, "bss") != radio_iface_name) {
            LOG(DEBUG) << radio_iface_name << " does not exists in " << try_fname;
            continue;
        }

        // all is good, return the conf
        return hostapd_conf;
    }

    // return an empty one since we couldn't find the
    return prplmesh::hostapd::Configuration("file not found");
}

/**
* @brief Assign hostapd parameters based on authentication and
* encryption configuration.
*
* @param conf the hostapd configuration to save the parameters to.
* @param the VAP id of the BSS.
* @param authentication_type the authentication type.
* @param encryption_type the encryption type.
*
* @return true on success, false otherwise.
*/
static bool assign_auth_encr_parameters(prplmesh::hostapd::Configuration &conf,
                                        const std::string &vap_id,
                                        const son::wireless_utils::sBssInfoConf &bss)
{

    // Hostapd "wpa" field.
    // This field is a bit field that can be used to enable WPA (IEEE 802.11i/D3.0)
    // and/or WPA2 (full IEEE 802.11i/RSN):
    // bit0 = WPA
    // bit1 = IEEE 802.11i/RSN (WPA2) (dot11RSNAEnabled)
    int wpa = 0;

    // Set of accepted key management algorithms (WPA-PSK, WPA-EAP, or both). The
    // entries are separated with a space. WPA-PSK-SHA256 and WPA-EAP-SHA256 can be
    // added to enable SHA256-based stronger algorithms.
    // WPA-PSK = WPA-Personal / WPA2-Personal
    std::string wpa_key_mgmt; // default to empty -> delete from hostapd config

    // (dot11RSNAConfigPairwiseCiphersTable)
    // Pairwise cipher for WPA (v1) (default: TKIP)
    //  wpa_pairwise=TKIP CCMP
    // Pairwise cipher for RSN/WPA2 (default: use wpa_pairwise value)
    //  rsn_pairwise=CCMP
    std::string wpa_pairwise; // default to empty -> delete from hostapd config

    // WPA pre-shared keys for WPA-PSK. This can be either entered as a 256-bit
    // secret in hex format (64 hex digits), wpa_psk, or as an ASCII passphrase
    // (8..63 characters), wpa_passphrase.
    std::string wpa_passphrase;
    std::string wpa_psk;

    // ieee80211w: Whether management frame protection (MFP) is enabled
    // 0 = disabled (default)
    // 1 = optional
    // 2 = required
    std::string ieee80211w;

    // This parameter can be used to disable caching of PMKSA created through EAP
    // authentication. RSN preauthentication may still end up using PMKSA caching if
    // it is enabled (rsn_preauth=1).
    // 0 = PMKSA caching enabled (default)
    // 1 = PMKSA caching disabled
    std::string disable_pmksa_caching;

    // Opportunistic Key Caching (aka Proactive Key Caching)
    // Allow PMK cache to be shared opportunistically among configured interfaces
    // and BSSes (i.e., all configurations within a single hostapd process).
    // 0 = disabled (default)
    // 1 = enabled
    std::string okc;

    // This parameter can be used to disable retransmission of EAPOL-Key frames that
    // are used to install keys (EAPOL-Key message 3/4 and group message 1/2). This
    // is similar to setting wpa_group_update_count=1 and
    std::string wpa_disable_eapol_key_retries;

    // EasyMesh R1 only allows Open and WPA2 PSK auth&encryption methods.
    // Quote: A Multi-AP Controller shall set the Authentication Type attribute
    //        in M2 to indicate WPA2-Personal or Open System Authentication.
    // bss.authentication_type is a bitfield, but we are not going
    // to accept any combinations due to the above limitation.
    if (bss.authentication_type == WSC::eWscAuth::WSC_AUTH_OPEN) {
        wpa = 0x0;
        if (bss.encryption_type != WSC::eWscEncr::WSC_ENCR_NONE) {
            LOG(ERROR) << "Autoconfiguration: " << vap_id << " encryption set on open VAP";
            return false;
        }
        if (bss.network_key.length() > 0) {
            LOG(ERROR) << "Autoconfiguration: " << vap_id << " network key set for open VAP";
            return false;
        }
    } else if (bss.authentication_type == WSC::eWscAuth::WSC_AUTH_WPA2PSK) {
        wpa = 0x2;
        wpa_key_mgmt.assign("WPA-PSK");
        // Cipher must include AES for WPA2, TKIP is optional
        if ((static_cast<uint16_t>(bss.encryption_type) &
             static_cast<uint16_t>(WSC::eWscEncr::WSC_ENCR_AES)) == 0) {
            LOG(ERROR) << "Autoconfiguration:  " << vap_id << " CCMP(AES) is required for WPA2";
            return false;
        }
        if ((uint16_t(bss.encryption_type) & uint16_t(WSC::eWscEncr::WSC_ENCR_TKIP)) != 0) {
            wpa_pairwise.assign("TKIP CCMP");
        } else {
            wpa_pairwise.assign("CCMP");
        }
        if (bss.network_key.length() < 8 || bss.network_key.length() > 64) {
            LOG(ERROR) << "Autoconfiguration: " << vap_id << " invalid network key length "
                       << bss.network_key.length();
            return false;
        }
        if (bss.network_key.length() < 64) {
            wpa_passphrase.assign(bss.network_key);
        } else {
            wpa_psk.assign(bss.network_key);
        }
        ieee80211w.assign("0");
        disable_pmksa_caching.assign("1");
        okc.assign("0");
        wpa_disable_eapol_key_retries.assign("0");
    } else if (bss.authentication_type ==
               WSC::eWscAuth(WSC::eWscAuth::WSC_AUTH_WPA2PSK | WSC::eWscAuth::WSC_AUTH_SAE)) {
        wpa = 0x2;
        wpa_key_mgmt.assign("WPA-PSK SAE");

        if (bss.encryption_type != WSC::eWscEncr::WSC_ENCR_AES) {
            LOG(ERROR) << "Autoconfiguration:  " << vap_id << " CCMP(AES) is required for WPA3";
            return false;
        }
        wpa_pairwise.assign("CCMP");

        if (bss.network_key.length() < 8 || bss.network_key.length() > 64) {
            LOG(ERROR) << "Autoconfiguration: " << vap_id << " invalid network key length "
                       << bss.network_key.length();
            return false;
        }
        wpa_passphrase.assign(bss.network_key);

        ieee80211w.assign("2");
        disable_pmksa_caching.assign("1");
        okc.assign("1");
        wpa_disable_eapol_key_retries.assign("0");
    } else if (bss.authentication_type == WSC::eWscAuth::WSC_AUTH_SAE) {
        wpa = 0x2;
        wpa_key_mgmt.assign("SAE");

        if (bss.encryption_type != WSC::eWscEncr::WSC_ENCR_AES) {
            LOG(ERROR) << "Autoconfiguration:  " << vap_id << " CCMP(AES) is required for WPA3";
            return false;
        }
        wpa_pairwise.assign("CCMP");

        if (bss.network_key.length() < 8 || bss.network_key.length() > 64) {
            LOG(ERROR) << "Autoconfiguration: " << vap_id << " invalid network key length "
                       << bss.network_key.length();
            return false;
        }
        wpa_passphrase.assign(bss.network_key);

        ieee80211w.assign("2");
        disable_pmksa_caching.assign("1");
        okc.assign("1");
        wpa_disable_eapol_key_retries.assign("0");
    } else {
        LOG(ERROR) << "Autoconfiguration: " << vap_id << " invalid authentication type: "
                   << son::wireless_utils::wsc_to_bwl_authentication(bss.authentication_type);
        return false;
    }

    conf.set_create_value(vap_id, "wpa", wpa);
    conf.set_create_value(vap_id, "okc", okc);
    conf.set_create_value(vap_id, "wpa_key_mgmt", wpa_key_mgmt);
    conf.set_create_value(vap_id, "wpa_pairwise", wpa_pairwise);
    conf.set_create_value(vap_id, "wpa_psk", wpa_psk);
    conf.set_create_value(vap_id, "ieee80211w", ieee80211w);
    conf.set_create_value(vap_id, "wpa_passphrase", wpa_passphrase);
    conf.set_create_value(vap_id, "disable_pmksa_caching", disable_pmksa_caching);
    conf.set_create_value(vap_id, "wpa_disable_eapol_key_retries", wpa_disable_eapol_key_retries);
    return true;
}

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

// NOTE: Since *base_wlan_hal_nl80211* inherits *base_wlan_hal* virtually, we
//       need to explicitly call it's from any deriving class
ap_wlan_hal_nl80211::ap_wlan_hal_nl80211(const std::string &iface_name, hal_event_cb_t callback,
                                         const hal_conf_t &hal_conf)
    : base_wlan_hal(bwl::HALType::AccessPoint, iface_name, IfaceType::Intel, callback, hal_conf),
      base_wlan_hal_nl80211(bwl::HALType::AccessPoint, iface_name, callback, BUFFER_SIZE, hal_conf)
{
    m_filtered_events.insert({});
}

ap_wlan_hal_nl80211::~ap_wlan_hal_nl80211() {}

HALState ap_wlan_hal_nl80211::attach(bool block)
{
    auto state = base_wlan_hal_nl80211::attach(block);

    // On Operational send the AP_Attached event to the AP Manager
    if (state == HALState::Operational) {
        event_queue_push(Event::AP_Attached);
    }

    return state;
}

bool ap_wlan_hal_nl80211::set_cce_indication(uint16_t advertise_cce)
{
    LOG(DEBUG) << "ap_wlan_hal_nl80211: set_cce_indication, advertise_cce=" << advertise_cce;
    return true;
}

bool ap_wlan_hal_nl80211::refresh_radio_info()
{
    // Obtain radio information (frequency band, maximum supported bandwidth, capabilities and
    // supported channels) using NL80211.
    // Most of this data does not change during runtime. An exception is, for example, the DFS
    // state. So, to read the latest value, we need to refresh data on every call.

    nl80211_client::radio_info radio_info;
    if (!m_nl80211_client->get_radio_info(get_iface_name(), radio_info)) {
        LOG(ERROR) << "Unable to read radio info for interface " << m_radio_info.iface_name;
        return false;
    }

    if (radio_info.bands.empty()) {
        LOG(ERROR) << "Unable to read any band in radio for interface " << m_radio_info.iface_name;
        return false;
    }

    if (m_radio_info.frequency_band == beerocks::eFreqType::FREQ_UNKNOWN) {

        if (radio_info.bands.size() == 1) {
            // if there is only one band for this radio, then select it
            auto &supported_channels = radio_info.bands[0].supported_channels;
            if (supported_channels.empty()) {
                LOG(ERROR)
                    << "There must be at least 1 supported channel that is read from nl80211";
                return false;
            }

            // validate all the frequencies are of the same type
            auto freq_type = son::wireless_utils::which_freq_type(
                supported_channels.begin()->second.center_freq);
            if (freq_type == beerocks::eFreqType::FREQ_UNKNOWN) {
                LOG(ERROR) << "frequency " << supported_channels.begin()->second.center_freq
                           << " type is unknown";
                return false;
            }
            bool are_all_freq_same_type =
                std::all_of(supported_channels.begin(), supported_channels.end(),
                            [&](const std::pair<uint8_t, bwl::nl80211_client::channel_info>
                                    &supported_channel) {
                                return freq_type == son::wireless_utils::which_freq_type(
                                                        supported_channel.second.center_freq);
                            });
            if (!are_all_freq_same_type) {
                LOG(ERROR) << "All frequencies of the same band must be of the same band type";
                return false;
            }

            m_radio_info.frequency_band = freq_type;
        } else {
            // If there are multiple bands, then select the band which frequency matches the
            // operation mode read from hostapd.conf file.
            // For efficiency reasons, parse hostapd.conf only once, the first time this method is
            // called.

            // Load hostapd config for the radio
            prplmesh::hostapd::Configuration conf = load_hostapd_config(m_radio_info.iface_name);
            if (!conf) {
                LOG(ERROR) << "Unable to load hostapd config for interface "
                           << m_radio_info.iface_name;
                return false;
            }
            // The name "band" is OpenWRT common option name, taken from the following link:
            // https://openwrt.org/docs/guide-user/network/wifi/basic
            // Basically, there are two option names that determines
            // the band type: "band" and "hwmode", but "hwmode" is
            // deprecated, as stated in the link.
            auto band = conf.get_head_value("band");
            if (!band.empty()) {
                if (band == "2g") {
                    m_radio_info.frequency_band = beerocks::eFreqType::FREQ_24G;
                } else if (band == "5g") {
                    m_radio_info.frequency_band = beerocks::eFreqType::FREQ_5G;
                } else if (band == "6g") {
                    m_radio_info.frequency_band = beerocks::eFreqType::FREQ_6G;
                } else {
                    LOG(ERROR) << "Unknown operation mode for interface "
                               << m_radio_info.iface_name;
                    return false;
                }
            } else {
                // Compute frequency band out of parameter `hw_mode` in hostapd.conf
                auto hw_mode = conf.get_head_value("hw_mode");
                if (!hw_mode.empty()) {
                    // The mode used by hostapd (11b, 11g, 11n, 11ac, 11ax) is governed by several
                    // parameters in the configuration file. However, as explained in the comment below from
                    // hostapd.conf, the hw_mode parameter is sufficient to determine the band.
                    //
                    // # Operation mode (a = IEEE 802.11a (5 GHz), b = IEEE 802.11b (2.4 GHz),
                    // # g = IEEE 802.11g (2.4 GHz), ad = IEEE 802.11ad (60 GHz); a/g options are used
                    // # with IEEE 802.11n (HT), too, to specify band). For IEEE 802.11ac (VHT), this
                    // # needs to be set to hw_mode=a. For IEEE 802.11ax (HE) on 6 GHz this needs
                    // # to be set to hw_mode=a.
                    //
                    // Note that this will need to be revisited for 6GHz operation, which we don't support
                    // at the moment.
                    if ((hw_mode == "b") || (hw_mode == "g")) {
                        m_radio_info.frequency_band = beerocks::eFreqType::FREQ_24G;
                    } else if (hw_mode == "a") {
                        m_radio_info.frequency_band = beerocks::eFreqType::FREQ_5G;
                    } else {
                        LOG(ERROR)
                            << "Unknown operation mode for interface " << m_radio_info.iface_name;
                        return false;
                    }
                } else {
                    // when both "band" and "hw_mode" are not exist, then choose the
                    // highest frequency band
                    m_radio_info.frequency_band = radio_info.bands.begin()->get_frequency_band();
                    beerocks::eFreqType current_freq_type = beerocks::FREQ_UNKNOWN;
                    for (auto it = radio_info.bands.begin() + 1; it != radio_info.bands.end();
                         it++) {
                        current_freq_type = it->get_frequency_band();
                        if (current_freq_type == beerocks::eFreqType::FREQ_UNKNOWN) {
                            LOG(ERROR)
                                << "Unknown band type for interface " << m_radio_info.iface_name;
                            return false;
                        }
                        if (current_freq_type > m_radio_info.frequency_band) {
                            m_radio_info.frequency_band = current_freq_type;
                        }
                    }
                }
            }
        }
    }

    if (radio_info.bands.begin()->supported_channels.empty()) {
        LOG(ERROR) << "Supported channels map is empty";
        return false;
    }
    auto band_info_it =
        std::find_if(radio_info.bands.begin(), radio_info.bands.end(),
                     [&](const bwl::nl80211_client::band_info &b) {
                         return m_radio_info.frequency_band ==
                                son::wireless_utils::which_freq_type(
                                    b.supported_channels.begin()->second.center_freq);
                     });

    if (band_info_it != radio_info.bands.end()) {
        m_radio_info.max_bandwidth = band_info_it->get_max_bandwidth();
        m_radio_info.ht_supported  = band_info_it->ht_supported;
        m_radio_info.ht_capability = band_info_it->ht_capability;
        std::copy_n(band_info_it->ht_mcs_set, m_radio_info.ht_mcs_set.size(),
                    m_radio_info.ht_mcs_set.begin());
        m_radio_info.vht_supported  = band_info_it->vht_supported;
        m_radio_info.vht_capability = band_info_it->vht_capability;
        std::copy_n(band_info_it->vht_mcs_set, m_radio_info.vht_mcs_set.size(),
                    m_radio_info.vht_mcs_set.begin());
        m_radio_info.he_supported  = band_info_it->he_supported;
        m_radio_info.he_capability = band_info_it->he_capability;

        for (auto const &pair : band_info_it->supported_channels) {
            auto &supported_channel_info = pair.second;
            auto &channel_info        = m_radio_info.channels_list[supported_channel_info.number];
            channel_info.tx_power_dbm = supported_channel_info.tx_power;
            channel_info.dfs_state    = supported_channel_info.is_dfs
                                            ? supported_channel_info.dfs_state
                                            : beerocks::eDfsState::DFS_STATE_MAX;

            for (auto bw : supported_channel_info.supported_bandwidths) {
                // Since bwl nl8011 does not support ranking, set all ranking to highest rank (1).
                channel_info.bw_info_list[bw] = 1;
            }
        }
    } else {
        LOG(ERROR) << "Failed to find a band that matches the frequency band of the radio info";
        return false;
    }

    return base_wlan_hal_nl80211::refresh_radio_info();
} // namespace nl80211

bool ap_wlan_hal_nl80211::enable()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::disable()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::set_start_disabled(bool enable, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::set_channel(int chan, beerocks::eWiFiBandwidth bw, int center_channel)
{
    if (chan < 0) {
        LOG(ERROR) << "Invalid input: channel(" << chan << ") < 0";
        return false;
    }

    // ACS is triggered in BackhaulManager::send_slaves_enable() on radio which does not have BH link
    if (chan == 0) {
        LOG(INFO) << "ACS is not supported";

        // TODO: Returning false exits whole AP initialization (PPM-1928)
        return true;
    }

    // Load hostapd config for the radio
    prplmesh::hostapd::Configuration conf = load_hostapd_config(m_radio_info.iface_name);
    if (!conf) {
        LOG(ERROR) << "Unable to load hostapd config for interface " << m_radio_info.iface_name;
        return false;
    }

    std::string chan_string = std::to_string(chan);

    LOG(DEBUG) << "Set channel to " << chan_string << ", bw " << bw << ", center channel "
               << center_channel;

    if (!conf.set_create_head_value("channel", chan_string)) {
        LOG(ERROR) << "Failed setting channel";
        return false;
    }

    if (bw != beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN) {
        int wifi_bw = 0;
        // based on hostapd.conf @ https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
        // # 0 = 20 or 40 MHz operating Channel width
        // # 1 = 80 MHz channel width
        // # 2 = 160 MHz channel width
        // # 3 = 80+80 MHz channel width
        // #vht_oper_chwidth=1

        if (bw == beerocks::eWiFiBandwidth::BANDWIDTH_20 ||
            bw == beerocks::eWiFiBandwidth::BANDWIDTH_40) {
            wifi_bw = 0;
        } else if (bw == beerocks::eWiFiBandwidth::BANDWIDTH_80) {
            wifi_bw = 1;
        } else if (bw == beerocks::eWiFiBandwidth::BANDWIDTH_160) {
            wifi_bw = 2;
        } else if (bw == beerocks::eWiFiBandwidth::BANDWIDTH_80_80) {
            wifi_bw = 3;
        } else {
            LOG(ERROR) << "Unknown BW " << bw;
            return false;
        }

        if (!conf.set_create_head_value("vht_oper_chwidth", std::to_string(wifi_bw))) {
            LOG(ERROR) << "Failed setting vht_oper_chwidth";
            return false;
        }
    }

    if (center_channel > 0) {
        if (!conf.set_create_head_value("vht_oper_centr_freq_seg0_idx",
                                        std::to_string(center_channel))) {
            LOG(ERROR) << "Failed setting vht_oper_centr_freq_seg0_idx";
            return false;
        }
    }

    // store the result:
    if (!conf.store()) {
        LOG(ERROR) << "set_channel: cannot save hostapd config!";
        return false;
    }

    // make hostapd reload its configuration file:
    const std::string cmd{"UPDATE "};
    if (!wpa_ctrl_send_msg(cmd)) {
        LOG(ERROR) << "'" << cmd << "' command to hostapd failed";
        return false;
    }

    LOG(DEBUG) << "set_channel done";

    return true;
}

bool ap_wlan_hal_nl80211::sta_allow(const sMacAddr &mac, const sMacAddr &bssid)
{
    LOG(TRACE) << __func__ << " mac: " << mac << ", bssid: " << bssid;

    // Build command string
    // We use the DENY_ACL list only
    const std::string cmd = "DENY_ACL DEL_MAC " + tlvf::mac_to_string(mac);

    auto vap_id = get_vap_id_with_mac(tlvf::mac_to_string(bssid));
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }
    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << "sta_allow() failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::sta_deny(const sMacAddr &mac, const sMacAddr &bssid)
{
    LOG(TRACE) << __func__ << " mac: " << mac << ", bssid: " << bssid;

    // Build command string
    // We use the DENY_ACL list only
    const std::string cmd = "DENY_ACL ADD_MAC " + tlvf::mac_to_string(mac);

    auto vap_id = get_vap_id_with_mac(tlvf::mac_to_string(bssid));
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }
    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << "sta_deny() failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::sta_acceptlist_modify(const sMacAddr &mac, const sMacAddr &bssid,
                                                bwl::sta_acl_action action)
{
    const std::string cmd = "ACCEPT_ACL ";
    std::string action_cmd;

    switch (action) {
    case bwl::sta_acl_action::ADD: {
        action_cmd = "ADD_MAC " + tlvf::mac_to_string(mac);
        break;
    }

    case bwl::sta_acl_action::DEL: {
        action_cmd = "DEL_MAC " + tlvf::mac_to_string(mac);
        break;
    }
    default: {
        LOG(ERROR) << "Unknown action ";
        return false;
    }
    }

    LOG(TRACE) << __func__ << " mac: " << mac << ", bssid: " << bssid
               << " action cmd: " << action_cmd;

    auto vap_id = get_vap_id_with_mac(tlvf::mac_to_string(bssid));
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }
    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    // Send command
    if (!wpa_ctrl_send_msg(cmd + action_cmd, ifname)) {
        LOG(ERROR) << __func__ << " failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::set_macacl_type(const eMacACLType &acl_type, const sMacAddr &bssid)
{
    LOG(TRACE) << __func__ << " acl_type: " << int(acl_type) << ", bssid: " << bssid;

    std::string macaddr_acl = "0";

    switch (acl_type) {
    case eMacACLType::DENY_LIST: {
        macaddr_acl = "0";
        break;
    }
    case eMacACLType::ACCEPT_LIST: {
        macaddr_acl = "1";
        break;
    }
    }

    // Build command string
    const std::string cmd = "SET macaddr_acl " + macaddr_acl;

    auto vap_id = get_vap_id_with_mac(tlvf::mac_to_string(bssid));
    if (vap_id < 0) {
        LOG(ERROR) << "no vap has bssid " << bssid;
        return false;
    }
    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << __func__ << " failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::sta_disassoc(int8_t vap_id, const std::string &mac, uint32_t reason)
{
    LOG(TRACE) << __func__ << " mac: " << mac << " vap_id: " << vap_id;

    if (!check_vap_id(vap_id)) {
        LOG(ERROR) << "invalid vap_id " << vap_id;
        return false;
    }

    // Build command string
    const std::string cmd = "DISASSOCIATE " + mac + " reason=" + std::to_string(reason) + " tx=0";

    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << "sta_disassoc() failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::sta_deauth(int8_t vap_id, const std::string &mac, uint32_t reason)
{
    LOG(TRACE) << __func__ << " mac: " << mac << " vap_id: " << vap_id;

    if (!check_vap_id(vap_id)) {
        LOG(ERROR) << "invalid vap_id " << vap_id;
        return false;
    }

    // Build command string
    const std::string cmd = "DEAUTHENTICATE " + mac + " reason=" + std::to_string(reason) + " tx=0";

    std::string ifname = m_radio_info.available_vaps[vap_id].bss;

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << "sta_disassoc() failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::sta_bss_steer(int8_t vap_id, const std::string &mac,
                                        const std::string &bssid, int oper_class, int chan,
                                        int disassoc_timer_btt, int valid_int_btt, int reason)
{
    LOG(TRACE) << __func__ << " vap_id: " << vap_id << " mac: " << mac << ", BSS: " << bssid
               << ", oper_class: " << oper_class << ", channel: " << chan
               << ", disassoc: " << disassoc_timer_btt << ", valid_int: " << valid_int_btt
               << ", reason: " << reason;

    if (!check_vap_id(vap_id)) {
        LOG(ERROR) << "invalid source vap_id " << vap_id;
        return false;
    }

    // Build command string
    std::string cmd =
        // Set the STA MAC address
        "BSS_TM_REQ " +
        mac
        // Transition management parameters
        + " pref=" + "1" + " abridged=" + "1";

    // Add only valid (positive) reason codes
    // Upper layers may set the reason value to a (-1) value to mark that the reason is not present
    if (reason >= 0) {
        // mbo format is mbo=<reason>:<reassoc_delay>:<cell_pref>
        // since the <reassoc_delay>:<cell_pref> variables are not part of the Steering Request TLV, we hard code it.
        // See discussion here:
        // https://gitlab.com/prpl-foundation/prplmesh/prplMesh/-/merge_requests/1948#note_457733802
        cmd += " mbo=" + std::to_string(reason);

        // BTM request (MBO): Assoc retry delay is only valid in disassoc imminent mode
        if (disassoc_timer_btt) {
            cmd += ":100:0";
        } else {
            cmd += ":0:0";
        }
    }

    if (disassoc_timer_btt) {
        cmd += std::string() + " disassoc_imminent=" + "1" +
               " disassoc_timer=" + std::to_string(disassoc_timer_btt);
    }
    // " bss_term="  // Unused Param
    // " url="       // Unused Param

    if (valid_int_btt) {
        cmd += " valid_int=" + std::to_string(valid_int_btt);
    }

    // Target BSSID
    cmd += std::string() + " neighbor=" + bssid + ",0," + std::to_string(oper_class) + "," +
           std::to_string(chan) + ",0";

    // Send command
    if (!wpa_ctrl_send_msg(cmd, m_radio_info.available_vaps[vap_id].bss)) {
        LOG(ERROR) << "sta_bss_steer() failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::update_vap_credentials(
    std::list<son::wireless_utils::sBssInfoConf> &bss_info_conf_list,
    const std::string &backhaul_wps_ssid, const std::string &backhaul_wps_passphrase)
{
    // Load hostapd config for the radio
    prplmesh::hostapd::Configuration conf = load_hostapd_config(m_radio_info.iface_name);
    if (!conf) {
        LOG(ERROR) << "Autoconfiguration: no hostapd config to apply configuration!";
        return false;
    }

    // If a Multi-AP Agent receives an AP-Autoconfiguration WSC message containing one or
    // more M2, it shall validate each M2 (based on its 1905 AL MAC address) and configure
    // a BSS on the corresponding radio for each of the M2. If the Multi-AP Agent is currently
    // operating a BSS with operating parameters that do not completely match any of the M2 in
    // the received AP-Autoconfiguration WSC message, it shall tear down that BSS.

    // decalre a function for iterating over bss-conf and ap-vaps
    bool abort = false;
    for (const auto &bss_it : bss_info_conf_list) {
        const auto &vap_id = conf.get_vap_by_bssid(tlvf::mac_to_string(bss_it.bssid));
        if (vap_id.empty()) {
            LOG(ERROR) << "Could not find BSS " << bss_it.bssid;
            abort = true;
            break;
        }

        if (bss_it.teardown) {
            // BSS is flagged for teardown
            LOG(DEBUG) << "Disabling VAP " << vap_id;
            conf.disable_vap(vap_id);
            // Continue to the next BSS
            continue;
        }

        // escape I
        auto auth_type = son::wireless_utils::wsc_to_bwl_authentication(bss_it.authentication_type);
        if (auth_type == "INVALID") {
            LOG(ERROR) << "Autoconfiguration: auth type is 'INVALID'; number: "
                       << (uint16_t)bss_it.authentication_type;
            abort = true;
            break;
        }

        // escape II
        auto enc_type = son::wireless_utils::wsc_to_bwl_encryption(bss_it.encryption_type);
        if (enc_type == "INVALID") {
            LOG(ERROR) << "Autoconfiguration: enc_type is 'INVALID'; number: "
                       << int(bss_it.encryption_type);
            abort = true;
            break;
        }

        // escape III
        std::string bss   = conf.get_vap_value(vap_id, "bss"),
                    bssid = conf.get_vap_value(vap_id, "bssid");
        // check explicit bssid value only in case of Multiple BSSID support
        if ((!bss.empty()) && bssid.empty()) {
            LOG(ERROR) << "Failed to get BSSID for vap: " << vap_id;
            abort = true;
            break;
        }

        // escape IV
        const auto vap_iter =
            std::find_if(m_radio_info.available_vaps.begin(), m_radio_info.available_vaps.end(),
                         [&bssid](const std::pair<int, bwl::VAPElement> &elem) {
                             return (elem.second.mac == bssid);
                         });
        // check bssid exists in available vaps since bssids should not change.
        if (vap_iter == m_radio_info.available_vaps.end()) {
            LOG(ERROR) << "Vap is not found in existing vaps";
            abort = true;
            break;
        }

        if (!assign_auth_encr_parameters(conf, vap_id, bss_it)) {
            LOG(ERROR) << "Failed to set the authentication/encryption parameters!";
            abort = true;
            break;
        }

        LOG(DEBUG) << "Autoconfiguration for ssid: " << bss_it.ssid << " auth_type: " << auth_type
                   << " encr_type: " << enc_type << " network_key: " << bss_it.network_key
                   << " fronthaul: " << beerocks::string_utils::bool_str(bss_it.fronthaul)
                   << " backhaul: " << beerocks::string_utils::bool_str(bss_it.backhaul);

        conf.set_create_vap_value(vap_id, "ssid", bss_it.ssid);
        conf.set_create_vap_value(vap_id, "wps_state", bss_it.fronthaul ? "2" : "");
        conf.set_create_vap_value(vap_id, "wps_independent", "0");
        std::string multi_ap;
        if (bss_it.fronthaul) {
            if (bss_it.backhaul) {
                multi_ap = "3";
            } else {
                multi_ap = "2";
            }
        } else {
            if (bss_it.backhaul) {
                multi_ap = "1";
            } else {
                LOG(WARNING) << "BSS configured with fronthaul nor backhaul";
                multi_ap = "0";
            }
        }
        conf.set_create_vap_value(vap_id, "multi_ap", multi_ap);

        // oddly enough, multi_ap_backhaul_wpa_passphrase has to be
        // quoted, while wpa_passphrase does not...
        if (bss_it.fronthaul && !backhaul_wps_ssid.empty()) {
            conf.set_create_vap_value(vap_id, "multi_ap_backhaul_ssid",
                                      "\"" + backhaul_wps_ssid + "\"");
            conf.set_create_vap_value(vap_id, "multi_ap_backhaul_wpa_passphrase",
                                      backhaul_wps_passphrase);
        }

        // remove when not needed
        if (!bss_it.fronthaul && backhaul_wps_ssid.empty()) {
            conf.set_create_vap_value(vap_id, "multi_ap_backhaul_ssid", "");
            conf.set_create_vap_value(vap_id, "multi_ap_backhaul_wpa_passphrase", "");
        }

        // we always need to get the mgmt frames (assoc req) for capability reports:
        conf.set_create_vap_value(vap_id, "notify_mgmt_frames", "1");

        // finally enable the vap (remove any previously set start_disabled)
        conf.set_create_vap_value(vap_id, "start_disabled", "");

        auto &vap_info     = m_radio_info.available_vaps[vap_iter->first];
        vap_info.bss       = bss;
        vap_info.mac       = bssid;
        vap_info.fronthaul = bss_it.fronthaul;
        vap_info.backhaul  = bss_it.backhaul;
        if (vap_info.backhaul) {
            vap_info.ssid = backhaul_wps_ssid;
            vap_info.profile1_backhaul_sta_association_disallowed =
                bss_it.profile1_backhaul_sta_association_disallowed;
            vap_info.profile2_backhaul_sta_association_disallowed =
                bss_it.profile2_backhaul_sta_association_disallowed;
        } else {
            vap_info.ssid                                         = bss_it.ssid;
            vap_info.profile1_backhaul_sta_association_disallowed = false;
            vap_info.profile2_backhaul_sta_association_disallowed = false;
        }
    }

    if (abort) {
        return false;
    }

    if (conf.update_required()) {
        if (!conf.store()) {
            LOG(ERROR) << "Autoconfiguration: cannot save hostapd config!";
            return false;
        }

        const std::string cmd("UPDATE ");
        if (!wpa_ctrl_send_msg(cmd)) {
            LOG(ERROR) << "Autoconfiguration: \"" << cmd << "\" command to hostapd has failed";
            return false;
        }
    }

    LOG(DEBUG) << "Autoconfiguration: done:\n" << conf;
    return true;
}

bool ap_wlan_hal_nl80211::sta_unassoc_rssi_measurement(const std::string &mac, int chan, int bw,
                                                       int vht_center_frequency, int delay,
                                                       int window_size)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_nl80211::sta_softblock_add(
    const std::string &vap_name, const std::string &client_mac, uint8_t reject_error_code,
    uint8_t probe_snr_threshold_hi, uint8_t probe_snr_threshold_lo,
    uint8_t authetication_snr_threshold_hi, uint8_t authetication_snr_threshold_lo)
{
    // softblock is used to block stations at the probe request level
    // (instead of during the authentication or association).  It
    // doesn't seem to be part of nl80211, so it cannot be
    // implemented. In prplMesh, it is only used by BML commands which
    // are triggered by an external process.

    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_nl80211::sta_softblock_remove(const std::string &vap_name,
                                               const std::string &client_mac)
{
    return false;
}

bool ap_wlan_hal_nl80211::switch_channel(int chan, beerocks::eWiFiBandwidth bw,
                                         int vht_center_frequency, int csa_beacon_count)
{
    LOG(TRACE) << __func__ << " channel: " << chan << ", bw: " << bw
               << ", vht_center_frequency: " << vht_center_frequency;

    // CHAN_SWITCH cs_count freq [center_freq1] [center_freq2] [bandwidth] [sec_channel_offset]
    //             [ht] [vht] [blocktx]
    // cs_count - CSA_BCN_COUNT, beacon count before switch.
    std::string cmd = "CHAN_SWITCH ";

    // Add custom beacon count
    cmd += std::to_string(csa_beacon_count) + " ";

    if (chan == 0) {
        LOG(ERROR) << "ACS is not supported";
        return false;
    }

    auto freq_type       = son::wireless_utils::which_freq_type(vht_center_frequency);
    int freq             = son::wireless_utils::channel_to_freq(chan, freq_type);
    std::string freq_str = std::to_string(freq);
    std::string wave_vht_center_frequency = std::to_string(vht_center_frequency);

    // Center Freq
    cmd += freq_str; // CenterFrequency

    // Extension Channel
    if (bw != beerocks::BANDWIDTH_20) {
        if (freq < vht_center_frequency) {
            cmd += " sec_channel_offset=1";
        } else {
            cmd += " sec_channel_offset=-1";
        }
    }

    /*
    according to the P802.11ax_D7.0 standard, Section 9.4.2.249:
    On 6GHz band, center_frequency_1 shall be the center frequency of the primary 80MHz channel,
    and center_frequency_2 shall be the center frequency of the 160MHz channel
    */
    if (freq_type != beerocks::FREQ_6G) {
        if (bw == beerocks::BANDWIDTH_80 || bw == beerocks::BANDWIDTH_160) {
            cmd += " center_freq1=" + wave_vht_center_frequency;
        }
    } else {
        if (bw == beerocks::BANDWIDTH_160) {
            auto primary_80mhz_freq = (freq < vht_center_frequency) ? vht_center_frequency - 40
                                                                    : vht_center_frequency + 40;
            cmd += " center_freq1=" + std::to_string(primary_80mhz_freq);
            cmd += " center_freq2=" + wave_vht_center_frequency;
        } else {
            cmd += " center_freq1=" + wave_vht_center_frequency;
        }
    }

    cmd += " bandwidth=" +
           std::to_string(beerocks::utils::convert_bandwidth_to_int((beerocks::eWiFiBandwidth)bw));

    // Supported Standard n/ac
    if (freq_type == beerocks::FREQ_6G) {
        cmd += " he";
    } else if (bw == beerocks::BANDWIDTH_20 || bw == beerocks::BANDWIDTH_40) {
        cmd += " ht"; //n
    } else if (bw == beerocks::BANDWIDTH_80 || bw == beerocks::BANDWIDTH_160) {
        cmd += " vht"; // ac
    }

    // Send command
    if (!wpa_ctrl_send_msg(cmd)) {
        LOG(ERROR) << "wpa_ctrl_send_msg() failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::cancel_cac(int chan, beerocks::eWiFiBandwidth bw,
                                     int vht_center_frequency, int secondary_chan)
{
    // TODO: implement
    return false;
}

bool ap_wlan_hal_nl80211::failsafe_channel_set(int chan, int bw, int vht_center_frequency)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::failsafe_channel_get(int &chan, int &bw)
{
    LOG(TRACE) << __func__;

    // Build command string
    std::string cmd = "GET_FAILSAFE_CHAN";
    char *reply;

    // Send command
    if (!wpa_ctrl_send_msg(cmd, &reply)) {
        LOG(ERROR) << "failsafe_channel_get() failed!";
        return false;
    }

    // Custom reply parsing

    std::string reply_str(reply);
    if (reply_str.find("UNSPECIFIED", 0, 11) != std::string::npos) {
        chan = -1;
        bw   = -1;
    } else if (reply_str.find("ACS", 0, 3) != std::string::npos) {
        chan = bw = 0;

    } else {
        int freq;
        std::string tmp;
        std::stringstream ss(reply_str);
        // parsing string in form: "%d %*s %*s bandwidth=%d"
        ss >> freq >> tmp >> tmp >> tmp;
        auto tmp_vec = beerocks::string_utils::str_split(tmp, '=');
        if (tmp_vec.size() != 2 || tmp_vec[0] != std::string("bandwidth")) {
            return false;
        }
        bw   = beerocks::string_utils::stoi(tmp_vec[1]);
        chan = son::wireless_utils::freq_to_channel(freq);
    }

    return true;
}

bool ap_wlan_hal_nl80211::is_zwdfs_supported()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_nl80211::set_zwdfs_antenna(bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_nl80211::is_zwdfs_antenna_enabled()
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return false;
}

bool ap_wlan_hal_nl80211::hybrid_mode_supported() { return true; }

bool ap_wlan_hal_nl80211::restricted_channels_set(char *channel_list)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::restricted_channels_get(char *channel_list)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    memset(channel_list, 0, beerocks::message::RESTRICTED_CHANNEL_LENGTH);
    return true;
}

bool ap_wlan_hal_nl80211::read_acs_report()
{
    LOG(TRACE) << __func__ << " for interface: " << get_radio_info().iface_name;

    // We're not going to support ACS in the NL80211 flavor of BWL.
    // The channel selection will instead be done by making the agent send channel scan reports to
    // the controller and the controller will take a decision based on the report (as part of
    // EasyMesh R2).
    return true;
}

bool ap_wlan_hal_nl80211::set_tx_power_limit(int tx_pow_limit)
{
    return m_nl80211_client->set_tx_power_limit(m_radio_info.iface_name, tx_pow_limit);
}

bool ap_wlan_hal_nl80211::set_vap_enable(const std::string &iface_name, const bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::set_mbo_assoc_disallow(const std::string &bssid, bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::set_radio_mbo_assoc_disallow(bool enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::set_primary_vlan_id(uint16_t primary_vlan_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::get_vap_enable(const std::string &iface_name, bool &enable)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::generate_connected_clients_events(
    bool &is_finished_all_clients, std::chrono::steady_clock::time_point max_iteration_timeout)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    is_finished_all_clients = true;
    return true;
}

bool ap_wlan_hal_nl80211::pre_generate_connected_clients_events()
{

    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool ap_wlan_hal_nl80211::start_wps_pbc()
{
    LOG(DEBUG) << "Start WPS PBC on interface " << m_radio_info.iface_name;
    std::string cmd = "WPS_PBC";
    if (!wpa_ctrl_send_msg(cmd)) {
        LOG(ERROR) << "start_wps_pbc() failed!";
        return false;
    }
    return true;
}

bool ap_wlan_hal_nl80211::process_nl80211_event(parsed_obj_map_t &parsed_obj)
{
    // Filter out empty events
    std::string opcode;
    if (!(parsed_obj.find(bwl::EVENT_KEYLESS_PARAM_OPCODE) != parsed_obj.end() &&
          !(opcode = parsed_obj[bwl::EVENT_KEYLESS_PARAM_OPCODE]).empty())) {
        return true;
    }

    // LOG(TRACE) << __func__ << " - opcode: |" << opcode << "|";

    auto event = nl80211_to_bwl_event(opcode);

    std::string interface;
    if (parsed_obj.find(bwl::EVENT_KEYLESS_PARAM_IFACE) != parsed_obj.end()) {
        interface = parsed_obj.at(bwl::EVENT_KEYLESS_PARAM_IFACE);
    }
    if (interface.empty()) {
        LOG(DEBUG) << "Could not find interface name.";
    }

    auto vap_id    = get_vap_id_with_bss(interface);
    auto iface_ids = beerocks::utils::get_ids_from_iface_string(interface);
    if ((vap_id < 0) && (iface_ids.vap_id != beerocks::IFACE_RADIO_ID)) {
        LOG(DEBUG) << "Unknown vap_id " << vap_id;
    }

    switch (event) {

    case Event::AP_MGMT_FRAME_RECEIVED: {
        if (parsed_obj.find("buf") == parsed_obj.end() || parsed_obj["buf"].empty()) {
            LOG(ERROR) << "Management frame without data!";
            return false;
        }
        // Tunnel the Management request to the controller
        auto mgmt_frame = create_mgmt_frame_notification(parsed_obj["buf"].c_str());
        if (mgmt_frame) {
            event_queue_push(Event::MGMT_Frame, mgmt_frame);
            // only save association and re-association request frames:
            if ((mgmt_frame->type == eManagementFrameType::ASSOCIATION_REQUEST) ||
                (mgmt_frame->type == eManagementFrameType::REASSOCIATION_REQUEST)) {
                std::string src_mac           = tlvf::mac_to_string(mgmt_frame->mac);
                m_latest_assoc_frame[src_mac] = mgmt_frame;
                LOG(DEBUG) << "Saved assoc frame";
            }
        }

    } break;

    // STA Connected
    case Event::STA_Connected: {

        // TODO: Change to HAL objects
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));

        if (vap_id < 0) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return false;
        }

        std::string src_mac      = parsed_obj[bwl::EVENT_KEYLESS_PARAM_MAC];
        msg->params.vap_id       = vap_id;
        msg->params.mac          = tlvf::mac_from_string(src_mac);
        msg->params.capabilities = {};

        //init the freq band cap with the target radio freq band info
        msg->params.capabilities.band_5g_capable = m_radio_info.is_5ghz;
        msg->params.capabilities.band_2g_capable =
            (son::wireless_utils::which_freq_type(m_radio_info.vht_center_freq) ==
             beerocks::eFreqType::FREQ_24G);

        auto assoc_frame_type = assoc_frame::AssocReqFrame::UNKNOWN;

        if (m_latest_assoc_frame.find(src_mac) == m_latest_assoc_frame.end()) {
            LOG(WARNING) << "STA-CONNECTED without previously receiving a (re-)association frame!";
            msg->params.association_frame_length = 0;
        } else {
            // Add the latest association frame
            // PPM-1718: parse the association frame and make sure it belongs to the right MAC address.
            auto &frame_info  = m_latest_assoc_frame[src_mac];
            msg->params.bssid = frame_info->bssid;
            auto &frame_body  = frame_info->data;
            // Add the latest association frame
            std::copy(frame_body.begin(), frame_body.end(), msg->params.association_frame);
            msg->params.association_frame_length = frame_body.size();
            assoc_frame_type                     = assoc_frame::AssocReqFrame::ASSOCIATION_REQUEST;
            if (frame_info->type == eManagementFrameType::REASSOCIATION_REQUEST) {
                assoc_frame_type = assoc_frame::AssocReqFrame::REASSOCIATION_REQUEST;
            }
        }

        auto assoc_frame = assoc_frame::AssocReqFrame::parse(
            msg->params.association_frame, msg->params.association_frame_length, assoc_frame_type);

        auto res = son::assoc_frame_utils::get_station_capabilities_from_assoc_frame(
            assoc_frame, msg->params.capabilities);
        if (!res) {
            LOG(ERROR) << "Failed to get station capabilities.";
        } else {
            son::wireless_utils::print_station_capabilities(msg->params.capabilities);
        }

        // Add the message to the queue
        event_queue_push(Event::STA_Connected, msg_buff);

    } break;

    // STA Disconnected
    case Event::STA_Disconnected: {

        // TODO: Change to HAL objects
        auto msg_buff =
            ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION));
        auto msg =
            reinterpret_cast<sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION));

        if (vap_id < 0) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return false;
        }

        // Store the MAC address of the disconnected STA
        msg->params.vap_id = vap_id;
        msg->params.mac    = tlvf::mac_from_string(parsed_obj[bwl::EVENT_KEYLESS_PARAM_MAC]);

        // Add the message to the queue
        event_queue_push(Event::STA_Disconnected, msg_buff);

        m_latest_assoc_frame.erase(parsed_obj[bwl::EVENT_KEYLESS_PARAM_MAC]);

    } break;

    // BSS Transition Query (802.11v)
    case Event::BSS_TM_Query: {

        auto val_iter = parsed_obj.find(bwl::EVENT_KEYLESS_PARAM_MAC);
        if (val_iter == parsed_obj.end()) {
            LOG(ERROR) << "No STA mac found";
            return false;
        }
        const auto client_mac = val_iter->second;

        if (interface.empty()) {
            LOG(ERROR) << "No interface name found";
            return false;
        }
        const auto vap_name = interface;

        if (vap_id < 0) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return false;
        }
        std::string bssid = m_radio_info.available_vaps[vap_id].mac;

        auto op_class = son::wireless_utils::get_operating_class_by_channel(
            beerocks::WifiChannel(m_radio_info.channel, m_radio_info.vht_center_freq,
                                  static_cast<beerocks::eWiFiBandwidth>(m_radio_info.bandwidth),
                                  m_radio_info.channel_ext_above > 0 ? true : false));
        // According to easymesh R2 specification when STA sends BSS_TM_QUERY
        // AP should respond with BSS_TM_REQ with at least one neighbor AP.
        // This commit adds the answer to the BSS_TM_QUERY. The answer adds only
        // one neighbor to the BSS_TM_REQ - the current VAP that the STA is
        // connected to, which in turn makes the STA to stay on the current VAP.
        // Since it's not an "active" transition and it makes the STA stay on the
        // current VAP, there is no need to notify the upper layer.
        // disassoc_timer_btt = 0 valid_int_btt=2 (200ms) reason=0 (not specified)
        sta_bss_steer(vap_id, client_mac, bssid, op_class, m_radio_info.channel, 0, 2, 0);
        break;
    }

    // BSS Transition (802.11v)
    case Event::BSS_TM_Response: {

        // TODO: Change to HAL objects
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE));
        auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        // Initialize the message
        memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE));

        // Client params
        msg->params.mac         = tlvf::mac_from_string(parsed_obj[bwl::EVENT_KEYLESS_PARAM_MAC]);
        msg->params.status_code = beerocks::string_utils::stoi(parsed_obj["status_code"]);

        // Open source hostapd does not contain bssid where client connected
        // BSSID should be retrieved from Agent database, for simplify logic in the
        // Agent need to fill up BSSID here with ZERO_MAC.
        msg->params.source_bssid = beerocks::net::network_utils::ZERO_MAC;

        if (msg->params.status_code == 0) {
            if (parsed_obj.find("target_bssid") != parsed_obj.end()) {
                msg->params.target_bssid = tlvf::mac_from_string(parsed_obj.at("target_bssid"));
            } else {
                LOG(ERROR) << "BTM Response : status ACCEPT but no target bssid";
            }
        }

        // Add the message to the queue
        event_queue_push(Event::BSS_TM_Response, msg_buff);

    } break;

    case Event::CTRL_Channel_Switch: {
        std::string bandwidth = parsed_obj["ch_width"];
        if (bandwidth.empty()) {
            LOG(ERROR) << "Invalid bandwidth";
            return false;
        }
        m_radio_info.channel =
            son::wireless_utils::freq_to_channel(beerocks::string_utils::stoi(parsed_obj["freq"]));
        m_radio_info.bandwidth          = wpa_bw_to_beerocks_bw(bandwidth);
        m_radio_info.channel_ext_above  = beerocks::string_utils::stoi(parsed_obj["ch_offset"]);
        m_radio_info.vht_center_freq    = beerocks::string_utils::stoi(parsed_obj["cf1"]);
        m_radio_info.is_dfs_channel     = beerocks::string_utils::stoi(parsed_obj["dfs"]);
        m_radio_info.last_csa_sw_reason = ChanSwReason::Unknown;
        if (son::wireless_utils::which_freq_type(m_radio_info.vht_center_freq) ==
            beerocks::eFreqType::FREQ_5G) {
            m_radio_info.is_5ghz = true;
        }
    } break;
    // ACS/CSA Completed
    case Event::ACS_Completed:
    case Event::CSA_Finished:
        event_queue_push(event);
        break;
    case Event::Interface_Disabled:
    case Event::ACS_Failed: {
        // Forward to the AP manager
        event_queue_push(event);
    } break;

    case Event::AP_Disabled: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_DISABLED_NOTIFICATION));
        auto msg      = reinterpret_cast<sHOSTAP_DISABLED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        memset(msg_buff.get(), 0, sizeof(sHOSTAP_DISABLED_NOTIFICATION));

        if (interface.empty()) {
            LOG(ERROR) << "Could not find interface name.";
            return false;
        }

        // Case of boards where main VAP and radio have same name
        if (vap_id == 0 && iface_ids.vap_id == beerocks::IFACE_RADIO_ID) {
            vap_id = beerocks::IFACE_RADIO_ID;
        }
        if (vap_id == beerocks::IFACE_ID_INVALID) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return false;
        }
        msg->vap_id = vap_id;

        event_queue_push(Event::AP_Disabled, msg_buff); // send message to the AP manager

    } break;
    case Event::AP_Enabled: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_ENABLED_NOTIFICATION));
        auto msg      = reinterpret_cast<sHOSTAP_ENABLED_NOTIFICATION *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        memset(msg_buff.get(), 0, sizeof(sHOSTAP_ENABLED_NOTIFICATION));

        // Case of boards where main VAP and radio have same name
        if (vap_id == 0 && iface_ids.vap_id == beerocks::IFACE_RADIO_ID) {
            vap_id = beerocks::IFACE_RADIO_ID;
        }
        if (vap_id == beerocks::IFACE_ID_INVALID) {
            LOG(ERROR) << "Invalid vap_id " << vap_id;
            return false;
        }
        msg->vap_id = vap_id;

        // same as in dwpal: AP enabling is done per vap
        if (msg->vap_id == beerocks::IFACE_RADIO_ID) {
            // Ignore AP-ENABLED on radio
            return true;
        }

        event_queue_push(Event::AP_Enabled, msg_buff);
    } break;
    case Event::WPA_Event_EAP_Failure:
    case Event::WPA_Event_EAP_Failure2:
    case Event::WPA_Event_EAP_Timeout_Failure:
    case Event::WPA_Event_EAP_Timeout_Failure2:
    case Event::WPS_Event_Timeout:
    case Event::WPS_Event_Fail:
    case Event::WPA_Event_SAE_Unknown_Password_Identifier:
    case Event::WPS_Event_Cancel:
    case Event::AP_Sta_Possible_Psk_Mismatch: {

        LOG(DEBUG) << "Sta Connection Failure";
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sStaConnectionFail));
        auto msg      = reinterpret_cast<sStaConnectionFail *>(msg_buff.get());
        LOG_IF(!msg, FATAL) << "Memory allocation failed!";

        memset(msg_buff.get(), 0, sizeof(sStaConnectionFail));

        msg->sta_mac = tlvf::mac_from_string(parsed_obj[bwl::EVENT_KEYLESS_PARAM_MAC]);
        LOG(DEBUG) << "STA connection failure: offending Sta MAC: " << msg->sta_mac;

        msg->bssid = tlvf::mac_from_string(m_radio_info.available_vaps[vap_id].mac);
        LOG(DEBUG) << "STA connection failure: interface BSSID: " << msg->bssid;

        event_queue_push(event, msg_buff);
        break;
    }

    // Gracefully ignore unhandled events
    // TODO: Probably should be changed to an error once WAV will stop
    //       sending empty or irrelevant events...
    default: {
        LOG(DEBUG) << "Unhandled event received: " << opcode;
    } break;
    }

    return true;
}

int ap_wlan_hal_nl80211::add_bss(std::string &ifname, son::wireless_utils::sBssInfoConf &bss_conf,
                                 std::string &bridge, bool vbss)
{
    std::string conf_path =
        std::string(bwl::nl80211::base_ctrl_path) + "hostapd-" + ifname + ".conf";
    std::stringstream cmd;

    // TODO: PPM-2347: check that the radio still has room for one more BSS.

    prplmesh::hostapd::Configuration conf(conf_path);
    conf.set_create_head_value("interface", ifname);
    conf.set_create_head_value("bssid", tlvf::mac_to_string(bss_conf.bssid));
    conf.set_create_head_value("ssid", bss_conf.ssid);
    conf.set_create_head_value("notify_mgmt_frames", "1");
    conf.set_create_head_value("ctrl_interface",
                               std::string(bwl::nl80211::base_ctrl_path) + "/hostapd");

    assign_auth_encr_parameters(conf, "", bss_conf);
    if (!bridge.empty()) {
        conf.set_create_head_value("bridge", bridge);
    }
    if (vbss) {
        conf.set_create_head_value("broadcast_deauth", "0");
        conf.set_create_head_value("no_deauth_unknown_sta", "1");
    }
    if (!conf.store()) {
        LOG(ERROR) << "Failed to store the hostapd configuration!";
        return false;
    }

    LOG(DEBUG) << "Adding new BSS on phy " << get_iface_name() << std::endl
               << "BSS configuration: " << conf;

    cmd << "ADD bss_config=" << get_iface_name() << ":" << conf_path;
    if (!wpa_ctrl_send_msg(cmd.str(), global_iface)) {
        LOG(ERROR) << "Failed to create the new BSS!";
        return false;
    }

    int fd = base_wlan_hal_nl80211::add_interface(ifname);
    if (fd < 0) {
        LOG(DEBUG) << "Failed to register and connect the new BSS interface!";
    }

    return fd;
}

bool ap_wlan_hal_nl80211::remove_bss(std::string &ifname)
{
    LOG(DEBUG) << "Removing BSS with ifname: '" << ifname << "'.";
    std::stringstream cmd;
    cmd << "REMOVE " << ifname;
    if (!wpa_ctrl_send_msg(cmd.str(), global_iface)) {
        LOG(ERROR) << "Failed to remove the BSS!";
        return false;
    }
    return base_wlan_hal_nl80211::remove_interface(ifname);
}

bool ap_wlan_hal_nl80211::add_key(const std::string &ifname, const sKeyInfo &key_info)
{
    return m_nl80211_client->add_key(ifname, key_info);
}

bool ap_wlan_hal_nl80211::add_station(const std::string &ifname, const sMacAddr &mac,
                                      std::vector<uint8_t> &raw_assoc_req)
{
    // TODO: PPM-2358: the AIDs are managed by hostapd. We currently
    // have no way to know what AIDs hostapd already assigned. As a
    // temporary measure, choose AIDs starting from the end to avoid
    // colliding with the ones assigned by hostapd. In the future the
    // station should be added through hostapd, which would avoid this
    // problem entirely.
    uint16_t aid = m_aid--;

    if (aid < 1) {
        LOG(ERROR) << "No more AIDs available!";
        return false;
    }

    if (raw_assoc_req.empty()) {
        LOG(ERROR) << "Could not add station '" << mac << "' to interface '" << ifname
                   << "', empty association frame.";
        return false;
    }
    auto assoc_req = assoc_frame::AssocReqFrame::parse(raw_assoc_req.data(), raw_assoc_req.size());
    if (!assoc_req) {
        LOG(ERROR) << "Could not add station '" << mac << "' to interface '" << ifname
                   << "', could not parse association frame!";
        return false;
    }
    if (!m_nl80211_client->add_station(ifname, mac, *assoc_req, aid)) {
        LOG(ERROR) << "Could not add station";
        return false;
    }
    auto vap_id = get_vap_id_with_bss(ifname);
    if (vap_id < 0) {
        LOG(ERROR) << "Failed to find vap id from BSS '" << ifname << "'";
        return false;
    }
    auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));
    auto msg = reinterpret_cast<sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION *>(msg_buff.get());
    LOG_IF(!msg, FATAL) << "Memory allocation failed!";

    // Initialize the message
    memset(msg_buff.get(), 0, sizeof(sACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION));

    msg->params.mac    = mac;
    msg->params.vap_id = vap_id;
    std::copy_n(raw_assoc_req.begin(), raw_assoc_req.size(), msg->params.association_frame);
    msg->params.association_frame_length = raw_assoc_req.size();
    son::assoc_frame_utils::get_station_capabilities_from_assoc_frame(assoc_req,
                                                                      msg->params.capabilities);
    event_queue_push(Event::STA_Connected, msg_buff);
    return true;
}

bool ap_wlan_hal_nl80211::get_key(const std::string &ifname, sKeyInfo &key_info)
{
    return m_nl80211_client->get_key(ifname, key_info);
}

bool ap_wlan_hal_nl80211::send_delba(const std::string &ifname, const sMacAddr &dst,
                                     const sMacAddr &src, const sMacAddr &bssid)
{
    return m_nl80211_client->send_delba(ifname, dst, src, bssid);
}

bool ap_wlan_hal_nl80211::set_no_deauth_unknown_sta(const std::string &ifname, bool value)
{
    LOG(TRACE) << __func__ << " ifname: " << ifname << " value: " << value;

    std::string set_value = value ? "1" : "0";
    const std::string cmd = "SET no_deauth_unknown_sta " + set_value;

    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << __func__ << " failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::set_beacon_da(const std::string &ifname, const sMacAddr &mac)
{
    LOG(TRACE) << __func__ << " ifname: " << ifname << ", mac: " << mac;

    // Build command string
    const std::string cmd = "SET beacon_da " + tlvf::mac_to_string(mac);

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << __func__ << " failed!";
        return false;
    }

    return true;
}

bool ap_wlan_hal_nl80211::update_beacon(const std::string &ifname)
{
    LOG(TRACE) << __func__ << " ifname: " << ifname;

    // Build command string
    const std::string cmd = "UPDATE_BEACON";

    // Send command
    if (!wpa_ctrl_send_msg(cmd, ifname)) {
        LOG(ERROR) << __func__ << " failed!";
        return false;
    }

    return true;
}

} // namespace nl80211

std::shared_ptr<ap_wlan_hal> ap_wlan_hal_create(std::string iface_name, hal_conf_t hal_conf,
                                                base_wlan_hal::hal_event_cb_t callback)
{
    return std::make_shared<nl80211::ap_wlan_hal_nl80211>(iface_name, callback, hal_conf);
}

} // namespace bwl
