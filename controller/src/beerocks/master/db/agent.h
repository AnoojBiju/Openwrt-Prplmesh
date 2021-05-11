/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AGENT_H
#define AGENT_H

#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_mac_map.h>
#include <beerocks/tlvf/beerocks_message.h>
#include <memory>
#include <string>
#include <tlvf/common/sMacAddr.h>
#include <tlvf/tlvftypes.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>

struct sWifiChannelRadarStats {
    uint8_t channel;
    uint8_t bandwidth;
    int8_t channel_ext_above_secondary;
    std::chrono::steady_clock::time_point csa_exit_timestamp;
    std::chrono::steady_clock::time_point csa_enter_timestamp;
};

typedef struct {
    std::string mac;
    std::string ssid;
    bool backhaul_vap;
} sVapElement;

// Forward declaration of son::node
namespace son {
class node;
}

namespace prplmesh {
namespace controller {
namespace db {

class Station;

/** All information about an agent in the controller database. */
struct sAgent {
public:
    sAgent()               = delete;
    sAgent(const sAgent &) = delete;
    explicit sAgent(const sMacAddr &al_mac_) : al_mac(al_mac_) {}

    /** AL-MAC address of the agent. */
    const sMacAddr al_mac;

    struct sRadio {
        sRadio()               = delete;
        sRadio(const sRadio &) = delete;
        explicit sRadio(const sMacAddr &radio_uid_) : radio_uid(radio_uid_) {}

        /** Radio UID. */
        const sMacAddr radio_uid;

        bool active              = false;
        bool is_backhaul_manager = false;
        bool is_acs_enabled      = false;
        std::string iface_name;
        beerocks::eIfaceType iface_type;
        std::string driver_version;
        std::vector<beerocks::message::sWifiChannel> supported_channels;
        uint8_t operating_class = 0;
        int ant_gain            = 0;
        int tx_power            = 0;
        std::string ssid;
        beerocks::eRadioBandCapability capability = beerocks::SUBBAND_CAPABILITY_UNKNOWN;
        uint16_t vht_center_frequency             = 0;
        int8_t channel_ext_above_primary          = 1;
        bool is_dfs                               = false;
        bool cac_completed                        = false;
        bool on_dfs_reentry                       = false;
        std::set<std::string> dfs_reentry_clients;
        beerocks::eApActiveMode ap_activity_mode = beerocks::AP_ACTIVE_MODE;

        std::list<sWifiChannelRadarStats> Radar_stats;
        std::vector<uint8_t> conf_restricted_channels;

        class ap_stats_params {
        public:
            int active_sta_count                 = 0;
            uint32_t rx_packets                  = 0;
            uint32_t tx_packets                  = 0;
            uint32_t rx_bytes                    = 0;
            uint32_t tx_bytes                    = 0;
            uint32_t errors_sent                 = 0;
            uint32_t errors_received             = 0;
            uint32_t retrans_count               = 0;
            int8_t noise                         = 0;
            uint8_t channel_load_percent         = 0;
            uint8_t total_client_tx_load_percent = 0;
            uint8_t total_client_rx_load_percent = 0;
            uint16_t stats_delta_ms              = 0;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::shared_ptr<ap_stats_params> stats_info = std::make_shared<ap_stats_params>();
        std::unordered_map<int8_t, sVapElement> vaps_info;

        class channel_scan_capabilities {
        public:
            // 1: True (Agent can only perform scan on boot), 0: False (Agent can perform Requested scans)
            uint8_t on_boot_only = 1;

            // 0x00: No impact (independent radio is available for scanning that is not used for Fronthaul or backhaul)
            // 0x01: Reduced number of spatial streams
            // 0x02: Time slicing impairment (Radio may go off channel for a series of short intervals)
            // 0x03: Radio unavailable for >= 2 seconds)
            uint8_t scan_impact = 0x02;

            // The minimum interval in seconds between the start of two consecutive channel scans on this radio
            uint32_t minimum_scan_interval = 0;

            // An unordered-map of operating classes the radio can scan on
            // Key: operating-class id, Value: operating
            std::unordered_map<uint8_t, std::vector<beerocks::message::sWifiChannel>>
                operating_classes;
        };
        channel_scan_capabilities scan_capabilities;

        class channel_scan_report {
        public:
            typedef std::pair<uint8_t, uint8_t> channel_scan_report_key;
            struct channel_scan_report_hash {
                std::size_t operator()(const std::pair<uint8_t, uint8_t> &pair) const
                {
                    return std::hash<uint8_t>()(pair.first) ^ std::hash<uint8_t>()(pair.second);
                }
            };
            std::vector<wfa_map::cNeighbors> neighbors;
            uint8_t noise;
            uint8_t utilization;
        };

        std::unordered_map<channel_scan_report::channel_scan_report_key, channel_scan_report,
                           channel_scan_report::channel_scan_report_hash>
            scan_report;

        struct channel_scan_config {
            bool is_enabled = false;
            std::unordered_set<uint8_t> channel_pool; // default value: empty list
            int interval_sec    = -1;                 //-1 (invalid)
            int dwell_time_msec = -1;                 //-1 (invalid)
        };

        struct channel_scan_status {
            // The scan is pending flag will be used to indicate when a single scan was requested
            bool scan_is_pending  = false;
            bool scan_in_progress = false;
            beerocks::eChannelScanStatusCode last_scan_error_code =
                beerocks::eChannelScanStatusCode::SUCCESS;
        };

        /**
         * These members are part of the continuous channel scan.
         * The contiuous scan runs every interval_sec.
         */
        channel_scan_config continuous_scan_config; /**< continues scan configuration */
        channel_scan_status continuous_scan_status; /**< continues scan status        */
        std::list<beerocks_message::sChannelScanResults>
            continuous_scan_results; /**< continues scan results list  */

        /**
         * These members are part of the single channel scan.
         * The single scan triggered once.
         */
        channel_scan_config single_scan_config; /**< single scan configuration */
        channel_scan_status single_scan_status; /**< single scan status        */
        std::list<beerocks_message::sChannelScanResults>
            single_scan_results; /**< single scan results list  */

        std::string dm_path; /**< data model path */

        struct sBss {
            sBss()             = delete;
            sBss(const sBss &) = delete;
            explicit sBss(const sMacAddr &bssid_,
                          int vap_id_ = beerocks::eBeeRocksIfaceIds::IFACE_ID_INVALID)
                : bssid(bssid_), vap_id(vap_id_)
            {
            }

            /** BSSID of the BSS. */
            const sMacAddr bssid;

            /**
             * @brief VAP ID.
             *
             * Only exists on prplmesh devices. -1 if not set.
             */
            const int vap_id;

            /** SSID of the BSS - empty if unconfigured. */
            std::string ssid;

            /** True if this is a backhaul bss. */
            bool backhaul = false;

            /** Stations (backhaul or fronthaul) connected to this BSS. */
            beerocks::mac_map<Station> connected_stations;
        };

        /** BSSes configured/reported on this radio. */
        beerocks::mac_map<sBss> bsses;
    };

    /** Radios reported on this agent. */
    beerocks::mac_map<sRadio> radios;
};

std::ostream &operator<<(std::ostream &os, const sAgent::sRadio &radio);

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // AGENT_H
