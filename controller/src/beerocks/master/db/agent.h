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
#include <bcl/beerocks_message_structs.h>
#include <memory>
#include <string>
#include <tlvf/common/sMacAddr.h>
#include <tlvf/tlvftypes.h>
#include <tlvf/wfa_map/tlvChannelScanCapabilities.h>
#include <tlvf/wfa_map/tlvProfile2ApCapability.h>
#include <tlvf/wfa_map/tlvProfile2MultiApProfile.h>
#include <tlvf/wfa_map/tlvServicePrioritizationRule.h>
#include <tlvf/wfa_map/tlvSteeringPolicy.h>

// Forward declaration of son::node
namespace son {
class node;
class db;
} // namespace son

namespace prplmesh {
namespace controller {
namespace db {

class Station;

/** All information about an agent in the controller database. */
class Agent {
public:
    Agent()              = delete;
    Agent(const Agent &) = delete;
    explicit Agent(const sMacAddr &al_mac_) : al_mac(al_mac_) {}

    /** AL-MAC address of the agent. */
    const sMacAddr al_mac;

    std::string dm_path; /**< data model path */

    /**
     * @brief Agents supported profile information.
     *
     * Default is MULTIAP_PROFILE_1.
     *
     * This parameter is reported with Profile-2 Multi AP Profile TLV.
     */
    wfa_map::tlvProfile2MultiApProfile::eMultiApProfile profile =
        wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::MULTIAP_PROFILE_1;

    // The maximum total number of service prioritization rules supported by the Multi-AP Agent
    uint8_t max_prioritization_rules;

    /**
     * @brief Byte counters unit types related TLVs.
     *
     * Multi-AP Agent onboards to a Controller created with Profile-1 settings and
     * byte counters unit is set to BYTES.
     *
     * This affects counters in AP Extended Metrics and Associated STA Traffic Stats TLV.
     *
     * This parameter is reported with Profile-2 AP Capability TLV.
     */
    wfa_map::tlvProfile2ApCapability::eByteCounterUnits byte_counter_units =
        wfa_map::tlvProfile2ApCapability::eByteCounterUnits::BYTES;

    // 802.1Q C-TAG Service Prioritization support
    bool prioritization_support;

    // DPP Onboarding procedure support
    bool dpp_onboarding_support;

    // 802.1Q C-TAG Traffic Separation support
    bool traffic_separation_support;

    /**
     * @brief Max Total Number of unique VLAN identifiers the Multi-AP Agent supports.
     *
     * This parameter is reported with Profile-2 AP Capability TLV.
     * For Profile-1, it is initialized as zero due to not supporting the TLV.
     */
    uint8_t max_total_number_of_vids = 0;

    bool is_gateway = false;

    bool does_support_vbss = false;

    struct sDeviceInfo {
        std::string manufacturer;
        std::string manufacturer_model;
        std::string serial_number;
        std::string software_version;
        std::string execution_env;
        std::string country_code;
    } device_info;

    // True: Report unsuccessful association attempts, False: Don't report
    bool unsuccessful_assoc_report_policy;

    // Maximum rate for reporting unsuccessful association attempts (in attempts per minute)
    uint8_t unsuccessful_assoc_max_reporting_rate;

    beerocks::eNodeState state = beerocks::STATE_CONNECTED;

    /** Stations for which local steering is disallowed */
    beerocks::mac_map<Station> disallowed_local_steering_stations;
    /** Stations for which BTM steering is disallowed */
    beerocks::mac_map<Station> disallowed_btm_steering_stations;

    struct sServicePrioritization {
        // Key: rule ID
        std::unordered_map<uint32_t,
                           wfa_map::tlvServicePrioritizationRule::sServicePrioritizationRule>
            rules;

        // List of 64 PCP values corresponding to the DSCP markings (0x00 to 0x3F)
        // Each value: 0x00 – 0x07
        std::array<uint8_t, beerocks::message::DSCP_MAPPING_LIST_LENGTH> dscp_mapping_table;
    } service_prioritization;

    struct sRadio {
        sRadio()               = delete;
        sRadio(const sRadio &) = delete;
        explicit sRadio(const sMacAddr &radio_uid_) : radio_uid(radio_uid_) {}

        /** Radio UID. */
        const sMacAddr radio_uid;

        std::string dm_path; /**< data model path */

        /** MAC of the Backhaul STA */
        sMacAddr backhaul_station_mac;

        bool is_acs_enabled = false;

        /** Name of the Wi-Fi chip vendor of this radio */
        std::string chipset_vendor;

        class s_ap_stats_params {
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
        std::shared_ptr<s_ap_stats_params> stats_info;

        class channel_scan_capabilities {
        public:
            // True: Agent can only perform scan on boot, False: Agent can perform Requested scans
            bool on_boot_only = true;

            // 0x00: No impact (independent radio is available for scanning that is not used for Fronthaul or backhaul)
            // 0x01: Reduced number of spatial streams
            // 0x02: Time slicing impairment (Radio may go off channel for a series of short intervals)
            // 0x03: Radio unavailable for >= 2 seconds)
            uint8_t scan_impact = wfa_map::cRadiosWithScanCapabilities::eScanImpact::
                SCAN_IMPACT_TIME_SLICING_IMPAIRMENT;

            // The minimum interval in seconds between the start of two consecutive channel scans on this radio
            uint32_t minimum_scan_interval = 0;

            // An unordered-map of operating classes the radio can scan on
            // Key: operating-class id, Value: vector with channels
            std::unordered_map<uint8_t, std::vector<beerocks::message::sWifiChannel>>
                operating_classes;
        };
        channel_scan_capabilities scan_capabilities;

        struct sAdvancedCapabilities {
            // Indicates traffic separation on combined fronthaul and Profile-1 backhaul support
            bool traffic_separation_combined_fronthaul;
            // Indicates traffic separation on combined Profile-1 backhaul and Profile-2 backhaul support
            bool traffic_separation_combined_backhaul;
            // Support for MSCS and EasyMesh configuration of extensions to MSCS
            bool mscs;
            // Support for SCS and EasyMesh configuration of extensions to SCS
            bool scs;
            // Support for DSCP-to-UP mapping
            bool dscp_to_up_mapping;
            // Support for sending DSCP Policy Requests to associated STAs
            // and EasyMesh configuration of such policies
            bool dscp_policy;
        } advanced_capabilities;

        struct sMetricReportingPolicies {
            // 0: Do not report STA Metrics based on RCPI threshold
            // 1–220: RCPI threshold (encoded per [Table 9-176/802.11-2020])
            uint8_t sta_reporting_rcpi_threshold;
            // 0: Use Agent's implementation-specific default RCPI Hysteresis margin
            // >0: RCPI hysteresis margin value. This field is coded as an unsigned integer in units of decibels (dB)
            uint8_t sta_reporting_rcpi_hyst_margin_override_threshold;
            // 0: Do not report AP Metrics based on Channel utilization threshold
            // >0: AP Metrics Channel Utilization Reporting Threshold (similar to channel utilization measurement in [Section 9.4.2.27/802.11-2020])
            uint8_t ap_reporting_channel_utilization_threshold;

            // True: Include Associated STA Traffic Stats TLV in AP Metrics Response, False: Don't include
            bool assoc_sta_traffic_stats_inclusion_policy;
            // True: Include Associated STA Link Metrics TLV in AP Metrics Response, False: Don't include
            bool assoc_sta_link_metrics_inclusion_policy;
            // True: Include Associated Wi-Fi 6 STA Status Report TLV in AP Metrics Response, False: Don't include
            bool assoc_wifi6_sta_status_report_inclusion_policy;
        } metric_reporting_policies;

        struct sSteeringPolicies {
            // 0x00: Agent Initiated Steering Disallowed
            // 0x01: Agent Initiated RCPI-based Steering Mandated
            // 0x02: Agent Initiated RCPI-based Steering Allowed
            wfa_map::tlvSteeringPolicy::eSteeringPolicy steering_policy;
            // Defined per BSS Load element [Section 9.4.2.27/802.11-2020]
            uint8_t channel_utilization_threshold;
            // Encoded per [Table 9-176/802.11-2020]
            uint8_t rcpi_steering_threshold;
        } steering_policies;

        struct sBss {
            sBss()             = delete;
            sBss(const sBss &) = delete;
            explicit sBss(const sMacAddr &bssid_, sRadio &radio_,
                          int vap_id_ = beerocks::eBeeRocksIfaceIds::IFACE_ID_INVALID)
                : bssid(bssid_), radio(radio_), vap_id(vap_id_)
            {
            }

            /** BSSID of the BSS. */
            const sMacAddr bssid;
            sRadio &radio;
            std::string dm_path; /**< data model path */

            /** SSID of the BSS - empty if unconfigured. */
            std::string ssid;

            /** True if the BSS supports Fronthaul connections */
            bool fronthaul = false;

            /** True if the BSS supports Backhaul connections */
            bool backhaul = false;

            /** True if the BSS is operational. */
            bool enabled = false;

            /** True if this BSS was created virtually for use by a single station */
            bool is_vbss = false;

            /**
             * @brief Byte Counter Units.
             *
             * The units used for byte counters when the Multi-AP Agent
             * reports traffic statistics.
             *
             * BYTES = 0x0
             * KIBIBYTES = 0x1
             * MEBIBYTES = 0x2
             */
            uint32_t byte_counter_units = 0x0;

            /** Stations (backhaul or fronthaul) connected to this BSS. */
            beerocks::mac_map<Station> connected_stations;

            /**
             * @brief Updates vap_id with valid value, if is was undefined
             * @param[in] vap_id_ : new vap_id value, only applied when valid
             *                      and that current one is still undefined
             * @return current/updated vap_id.
             */
            int update_vap_id(int vap_id_) const
            {
                if ((vap_id == beerocks::eBeeRocksIfaceIds::IFACE_ID_INVALID) &&
                    (vap_id_ >= beerocks::eBeeRocksIfaceIds::IFACE_VAP_ID_MIN)) {
                    vap_id = vap_id_;
                }
                return vap_id;
            }

            /**
             * @brief Returns current BSS vap_id value
             */
            int get_vap_id() const { return vap_id; }

            /**
             * @brief VAP ID.
             *
             * Only exists on prplmesh devices. -1 if not set.
             */
        private:
            mutable int vap_id;
        };

        /** BSSes configured/reported on this radio. */
        beerocks::mac_map<sBss> bsses;
    };

    struct sBackhaul {

        // In case of a wireless connection, backhaul station mac (bSTA) that connects to an AP interface (BSS).
        // In case of a wired connection, ethernet port that connects to a LAN interface.
        sMacAddr backhaul_interface;

        //TODO: Implement diffrent iface types (PPM-1656)
        beerocks::eIfaceType backhaul_iface_type;

        // Local radio the backhaul station use. If `nullptr` the backhaul is wired.
        std::shared_ptr<Agent::sRadio> wireless_backhaul_radio;

        // In case of a wireless connection, the BSSID to which the backhaul station is connected.
        // In case of a wired connection, the LAN port that the interface is connected to.
        sMacAddr parent_interface;

        // The Agent node that the backhaul station is connected to.
        std::weak_ptr<Agent> parent_agent;
    } backhaul;

    /** Radios reported on this agent. */
    beerocks::mac_map<sRadio> radios;

    friend class ::son::db;

private:
    /**
     * @brief The last time that the Agent was contacted via the Multi-AP control protocol.
     */
    std::chrono::system_clock::time_point last_contact_time;
};

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // AGENT_H
