/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _NODE_H_
#define _NODE_H_

#include "../tasks/task.h"
#include "interface.h"
#include <bcl/network/network_utils.h>
#include <tlvf/common/sMacAddr.h>
#include <tlvf/ieee_1905_1/tlvReceiverLinkMetric.h>
#include <tlvf/ieee_1905_1/tlvTransmitterLinkMetric.h>
#include <tlvf/wfa_map/tlvApMetrics.h>
#include <tlvf/wfa_map/tlvChannelScanCapabilities.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>

#include <list>
#include <map>
#include <unordered_set>

namespace son {
typedef struct {
    uint8_t channel;
    uint8_t bandwidth;
    int8_t channel_ext_above_secondary;
    std::chrono::steady_clock::time_point csa_exit_timestamp;
    std::chrono::steady_clock::time_point csa_enter_timestamp;
} sWifiChannelRadarStats;

typedef struct {
    std::string mac;
    std::string ssid;
    bool backhaul_vap;
} sVapElement;

/**
 * @brief Extended boolean parameter to support "not configured" value for configuration.
 * For persistent data, it is important to differ between configured (true/false) to unconfigured value.
 */
enum class eTriStateBool : int8_t { NOT_CONFIGURED = -1, FALSE = 0, TRUE = 1 };

std::ostream &operator<<(std::ostream &os, eTriStateBool value);

class node {
public:
    node(beerocks::eType type_, const std::string &mac_);
    bool get_beacon_measurement(const std::string &ap_mac_, int8_t &rcpi, uint8_t &rsni);
    void set_beacon_measurement(const std::string &ap_mac_, int8_t rcpi, uint8_t rsni);
    bool get_cross_rx_rssi(const std::string &ap_mac_, int8_t &rssi, int8_t &rx_packets);
    void set_cross_rx_rssi(const std::string &ap_mac_, int8_t rssi, int8_t rx_packets);
    void clear_cross_rssi();
    void clear_node_stats_info();
    void clear_hostap_stats_info();

    beerocks::eType get_type() const;
    bool set_type(beerocks::eType type_);

    int8_t vap_id = beerocks::IFACE_ID_INVALID;
    const std::string mac;           // client
    std::string parent_mac;          // hostap
    std::string dm_path;             // data model path
    std::string previous_parent_mac; //hostap
    std::string radio_identifier;

    std::string ipv4;
    std::string manufacturer;
    int channel = 0;
    std::string name;
    int hierarchy = -1; //redundant but more efficient
    beerocks::message::sRadioCapabilities &capabilities;
    beerocks::message::sRadioCapabilities m_sta_5ghz_capabilities;
    beerocks::message::sRadioCapabilities m_sta_24ghz_capabilities;

    beerocks::eWiFiBandwidth bandwidth = beerocks::BANDWIDTH_160;
    bool channel_ext_above_secondary   = true;

    beerocks::eNodeState state = beerocks::STATE_DISCONNECTED;
    bool handoff               = false;
    bool confined              = false;

    /// Clear this flag when channel switch is not in progress and channel is optimal path.
    /// And run optimal path for clients.
    bool cs_op = false;

    /// Clear this flag when channel switch is not in progress and cs_in_prog_optimal_path flag
    /// is clear too. Run load balancer algo.
    bool cs_lb = false;

    bool supports_5ghz            = true;
    int failed_5ghz_steer_attemps = 0;

    bool supports_24ghz            = true;
    int failed_24ghz_steer_attemps = 0;
    beerocks::eBeaconMeasurementSupportLevel supports_beacon_measurement =
        beerocks::BEACON_MEAS_UNSUPPORTED;
    bool supports_11v            = true;
    int failed_11v_request_count = 0;
    bool operational_state       = false;

    //Used by channel-selection to block the clients from connecting to a hostap
    std::vector<std::string> blocked_hostaps;

    std::chrono::steady_clock::time_point last_state_change;

    int association_handling_task_id             = -1;
    int steering_task_id                         = -1;
    int roaming_task_id                          = -1;
    int load_balancer_task_id                    = -1;
    int client_locating_task_id_new_connection   = -1;
    int client_locating_task_id_exist_connection = -1;
    int dynamic_channel_selection_task_id        = -1;

    std::chrono::steady_clock::time_point measurement_sent_timestamp;
    int measurement_recv_delta  = 0;
    int measurement_delay       = 0;
    int measurement_window_size = 60;

    class sta_stats_params {
    public:
        uint32_t rx_packets                             = 0;
        uint32_t tx_packets                             = 0;
        uint32_t rx_bytes                               = 0;
        uint32_t tx_bytes                               = 0;
        uint32_t retrans_count                          = 0;
        uint8_t tx_load_percent                         = 0;
        uint8_t rx_load_percent                         = 0;
        uint16_t rx_phy_rate_100kb                      = 0;
        uint16_t tx_phy_rate_100kb                      = 0;
        int8_t rx_rssi                                  = beerocks::RSSI_INVALID;
        uint16_t stats_delta_ms                         = 0;
        std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
    };
    std::shared_ptr<sta_stats_params> stats_info;

    uint16_t max_supported_phy_rate_100kb = 0;

    uint16_t cross_rx_phy_rate_100kb   = 0;
    uint16_t cross_tx_phy_rate_100kb   = 0;
    double cross_estimated_rx_phy_rate = 0.0;
    double cross_estimated_tx_phy_rate = 0.0;

    int ire_4addr_mode_transition_task_id = 0;
    bool transition_to_4addr_mode         = false;
    bool ire_handoff                      = false;

    class radio {
    public:
        int8_t iface_id           = beerocks::IFACE_ID_INVALID;
        bool active               = false;
        bool is_backhaul_manager  = false;
        bool is_acs_enabled       = false;
        bool enable_repeater_mode = false;
        std::string iface_name;
        beerocks::eIfaceType iface_type;
        std::string driver_version;
        std::vector<beerocks::message::sWifiChannel> supported_channels;
        uint8_t operating_class    = 0;
        int ant_gain               = 0;
        int tx_power               = 0;
        bool exclude_from_steering = false;
        std::string ssid;
        beerocks::eRadioBandCapability capability = beerocks::SUBBAND_CAPABILITY_UNKNOWN;
        uint16_t vht_center_frequency             = 0;
        int8_t channel_ext_above_primary          = 1;
        bool is_dfs                               = false;
        bool cac_completed                        = false;
        bool on_fail_safe_channel                 = false;
        bool on_sub_band_channel                  = false;
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
        std::shared_ptr<ap_stats_params> stats_info;
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
    };
    std::shared_ptr<radio> hostap;

    class link_metrics_data {
    public:
        link_metrics_data(){};
        ~link_metrics_data(){};

        std::vector<ieee1905_1::tlvTransmitterLinkMetric::sInterfacePairInfo>
            transmitterLinkMetrics;
        std::vector<ieee1905_1::tlvReceiverLinkMetric::sInterfacePairInfo> receiverLinkMetrics;

        bool add_transmitter_link_metric(
            std::shared_ptr<ieee1905_1::tlvTransmitterLinkMetric> TxLinkMetricData);
        bool add_receiver_link_metric(
            std::shared_ptr<ieee1905_1::tlvReceiverLinkMetric> RxLinkMetricData);
    };

    class ap_metrics_data {
    public:
        ap_metrics_data(){};
        ~ap_metrics_data(){};

        sMacAddr bssid                               = beerocks::net::network_utils::ZERO_MAC;
        uint8_t channel_utilization                  = 0;
        uint16_t number_of_stas_currently_associated = 0;
        std::vector<uint8_t> estimated_service_info_fields;
        bool include_ac_vo = false;
        bool include_ac_bk = false;
        bool include_ac_vi = false;

        bool add_ap_metric_data(std::shared_ptr<wfa_map::tlvApMetrics> ApMetricData);
    };

    bool is_prplmesh                = false;
    beerocks::eBandType band_type   = beerocks::eBandType::INVALID_BAND;
    beerocks::eIfaceType iface_type = beerocks::IFACE_TYPE_ETHERNET;
    std::chrono::steady_clock::time_point last_seen;

    friend std::ostream &operator<<(std::ostream &os, const node &node);
    friend std::ostream &operator<<(std::ostream &os, const node *node);

    /*
     * Persistent configurations - start
     * Client persistent configuration aging is refreshed on persistent configurations set
     * persistent configuration of aged clients removed from the persistent-db and cleared in the runtime-db
     */

    // Indicates when client parameters were last updated (even if not updated yet to persistent-db)
    // minimal value is used as invalid value.
    std::chrono::system_clock::time_point client_parameters_last_edit =
        std::chrono::system_clock::time_point::min();

    // Optional - if configured the client has its own configured timelife delay.
    std::chrono::minutes client_time_life_delay_minutes =
        std::chrono::minutes(beerocks::PARAMETER_NOT_CONFIGURED);

    // If enabled, the client will be steered to the initial radio it connected to - save at client_initial_radio.
    eTriStateBool client_stay_on_initial_radio = eTriStateBool::NOT_CONFIGURED;

    // The client_initial_radio mac must be set, default value is network_utils::ZERO_MAC.
    sMacAddr client_initial_radio;

    // The selected bands that the client should be steered to.
    // Default value is PARAMETER_NOT_CONFIGURED - which means no limitation on bands.
    // Possible values are bitwise options of eClientSelectedBands.
    int8_t client_selected_bands = beerocks::PARAMETER_NOT_CONFIGURED;

    // The unfriendly status indicates how we interact with the client.
    // If the unfriendly status is not configured, the client is assumed friendly unless proven otherwise.
    // The friendliness status affects how we handle the aging mechanism.
    eTriStateBool client_is_unfriendly = eTriStateBool::NOT_CONFIGURED;

    /*
     * Persistent configurations - end
     */

    /**
     * @brief Returns active interface mac addresses via loop through interface objects.
     *
     * @return active interface mac's returned as vector of sMacAddr
     */
    std::vector<sMacAddr> get_interfaces_mac();

    /**
     * @brief Get Interface with the given MAC, create it if necessary.
     *
     * @param mac interface MAC address
     * @return shared pointer of Interface Object
     */
    std::shared_ptr<prplmesh::controller::db::Interface> add_interface(const sMacAddr &mac);

    /**
     * @brief Get Interface with the given MAC, if there is one. Else returns nullptr.
     *
     * @param mac interface MAC address
     * @return shared pointer of Interface Object on success, nullptr otherwise.
     */
    std::shared_ptr<prplmesh::controller::db::Interface> get_interface(const sMacAddr &mac);

    /**
     * @brief Remove the Interface with the given MAC Address.
     */
    void remove_interface(const sMacAddr &mac);

    /**
     * @brief Get all Interfaces
     */
    const std::vector<std::shared_ptr<prplmesh::controller::db::Interface>> &get_interfaces()
    {
        return m_interfaces;
    }

    /**
     * @brief Returns unused interface mac addresses
     *
     * @param new_interfaces vector of active interface macs from topology message
     * @return unused interface mac's returned as vector of sMacAddr
     */
    std::vector<sMacAddr> get_unused_interfaces(const std::vector<sMacAddr> &new_interfaces);

    /**
     * @brief Get Neighbor with the given MAC, create it if necessary within Interface.
     *
     * @param interface_mac interface MAC address
     * @param neighbor_mac neighbor MAC address
     * @param flag_ieee1905 is IEEE1905 Flag
     * @return shared pointer of Neighbor Object
     */
    std::shared_ptr<prplmesh::controller::db::Interface::sNeighbor>
    add_neighbor(const sMacAddr &interface_mac, const sMacAddr &neighbor_mac, bool flag_ieee1905);

private:
    class rssi_measurement {
    public:
        rssi_measurement(const std::string &ap_mac_, int8_t rssi_, int8_t packets_)
            : ap_mac(ap_mac_)
        {
            rssi      = rssi_;
            packets   = packets_;
            timestamp = std::chrono::steady_clock::now();
        }
        const std::string ap_mac;
        int8_t rssi = beerocks::RSSI_INVALID;
        int8_t packets;
        std::chrono::steady_clock::time_point timestamp;
    };

    class beacon_measurement {
    public:
        beacon_measurement(const std::string &ap_mac_, int8_t rcpi_, uint8_t rsni_)
            : ap_mac(ap_mac_)
        {
            rcpi      = rcpi_; // received channel power indication (like rssi)
            rsni      = rsni_; // received signal noise indication (SNR)
            timestamp = std::chrono::steady_clock::now();
        }
        const std::string ap_mac;
        int8_t rcpi  = beerocks::RSSI_INVALID;
        uint8_t rsni = 0;
        std::chrono::steady_clock::time_point timestamp;
    };

    beerocks::eType type;
    std::unordered_map<std::string, std::shared_ptr<beacon_measurement>> beacon_measurements;
    std::unordered_map<std::string, std::shared_ptr<rssi_measurement>> cross_rx_rssi;

    /**
     * @brief Interfaces configured on this node.
     *
     * The Interface objects are kept alive by this list. Only active interfaces should be on this list.
     *
     */
    std::vector<std::shared_ptr<prplmesh::controller::db::Interface>> m_interfaces;

    virtual void print_node(std::ostream &os) const;
};

class node_gw: public node {
public:
    node_gw(const std::string &mac): node(beerocks::eType::TYPE_GW, mac) {};
};

class node_ire: public node {
public:
    node_ire(const std::string &mac): node(beerocks::eType::TYPE_IRE, mac) {};
};

class node_ire_backhaul: public node {
public:
    node_ire_backhaul(const std::string &mac): node(beerocks::eType::TYPE_IRE_BACKHAUL, mac) {};
};

class node_slave: public node {
public:
    node_slave(const std::string &mac): node(beerocks::eType::TYPE_SLAVE, mac) {};
};

class node_client: public node {
public:
    node_client(const std::string &mac): node(beerocks::eType::TYPE_CLIENT, mac) {};
};

class node_eth_switch: public node {
public:
    node_eth_switch(const std::string &mac): node(beerocks::eType::TYPE_ETH_SWITCH, mac) {};
};

class node_any: public node {
public:
    node_any(const std::string &mac): node(beerocks::eType::TYPE_ANY, mac) {};
};

std::shared_ptr<node> create_node(beerocks::eType type_, const std::string &mac);

} // namespace son
#endif
