/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef STATION_H
#define STATION_H

#include <bcl/beerocks_defines.h>
#include <bcl/network/network_utils.h>
#include <chrono>
#include <memory>
#include <string>
#include <tlvf/AssociationRequestFrame/AssocReqFrame.h>
#include <tlvf/common/sMacAddr.h>
#include <unordered_map>

#include "agent.h"
#include "node.h"

namespace son {
class db;

/**
 * @brief Extended boolean parameter to support "not configured" value for configuration.
 * For persistent data, it is important to differ between configured (true/false) to unconfigured value.
 */
enum class eTriStateBool : int8_t { NOT_CONFIGURED = -1, FALSE = 0, TRUE = 1 };

std::ostream &operator<<(std::ostream &os, eTriStateBool value);
} // namespace son

namespace prplmesh {
namespace controller {
namespace db {

/**
 * @brief Station struct.
 *
 * Struct representing a station. It can be a client or a backhaul station.
 */
class Station {
public:
    Station()                = delete;
    Station(const Station &) = delete;
    explicit Station(const sMacAddr &mac_) : mac(mac_)
    {
        m_sta_6ghz_capabilities.valid  = false;
        m_sta_5ghz_capabilities.valid  = false;
        m_sta_24ghz_capabilities.valid = false;
    }

    const sMacAddr mac;
    std::string name;
    uint8_t operating_class = 0;

    std::string dm_path; /**< data model path */
    std::string ipv4;
    std::string ipv6;
    int8_t vap_id              = beerocks::IFACE_ID_INVALID;
    beerocks::eNodeState state = beerocks::STATE_DISCONNECTED;

    int association_handling_task_id = -1;
    int steering_task_id             = -1;
    int roaming_task_id              = -1;
    int btm_request_task_id          = -1;

    bool confined = false;

    uint16_t cross_rx_phy_rate_100kb   = 0;
    uint16_t cross_tx_phy_rate_100kb   = 0;
    double cross_estimated_rx_phy_rate = 0.0;
    double cross_estimated_tx_phy_rate = 0.0;
    bool supports_24ghz                = true;
    bool supports_5ghz                 = true;
    bool supports_6ghz                 = true;
    beerocks::WifiChannel wifi_channel;
    std::chrono::steady_clock::time_point last_seen;

    /*
     * Persistent configurations - start
     * Client persistent configuration aging is refreshed on persistent configurations set
     * persistent configuration of aged clients removed from the persistent-db and cleared in the runtime-db
     */

    // Indicates when client parameters were last updated (even if not updated yet to persistent-db)
    // minimal value is used as invalid value.
    std::chrono::system_clock::time_point parameters_last_edit =
        std::chrono::system_clock::time_point::min();

    // Optional - if configured the client has its own configured timelife delay.
    std::chrono::minutes time_life_delay_minutes =
        std::chrono::minutes(beerocks::PARAMETER_NOT_CONFIGURED);

    sMacAddr initial_radio = beerocks::net::network_utils::ZERO_MAC;

    // If enabled, the client will be steered to the initial radio it connected to - save at initial_radio.
    son::eTriStateBool stay_on_initial_radio = son::eTriStateBool::NOT_CONFIGURED;

    // The selected bands that the client should be steered to.
    // Default value is PARAMETER_NOT_CONFIGURED - which means no limitation on bands.
    // Possible values are bitwise options of eClientSelectedBands.
    int8_t selected_bands = beerocks::PARAMETER_NOT_CONFIGURED;

    // The unfriendly status indicates how we interact with the client.
    // If the unfriendly status is not configured, the client is assumed friendly unless proven otherwise.
    // The friendliness status affects how we handle the aging mechanism.
    son::eTriStateBool is_unfriendly = son::eTriStateBool::NOT_CONFIGURED;

    /*
     * Persistent configurations - end
     */

    struct sSteeringSummaryStats {
        uint64_t blacklist_attempts  = 0;
        uint64_t blacklist_successes = 0;
        uint64_t blacklist_failures  = 0;
        uint64_t btm_attempts        = 0;
        uint64_t btm_successes       = 0;
        uint64_t btm_failures        = 0;
        uint64_t btm_query_responses = 0;
        uint32_t last_steer_time     = 0;
    } steering_summary_stats;

    class steering_attempt {
    public:
        int failed_6ghz_steer_attempts  = 0;
        int failed_5ghz_steer_attempts  = 0;
        int failed_24ghz_steer_attempts = 0;
    };

    std::shared_ptr<steering_attempt> steer_attempts = std::make_shared<steering_attempt>();

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

    std::shared_ptr<sta_stats_params> stats_info = std::make_shared<sta_stats_params>();
    beerocks::message::sRadioCapabilities *capabilities;
    beerocks::message::sRadioCapabilities m_sta_6ghz_capabilities;
    beerocks::message::sRadioCapabilities m_sta_5ghz_capabilities;
    beerocks::message::sRadioCapabilities m_sta_24ghz_capabilities;

    std::string assoc_timestamp;

    std::string assoc_event_path; /**< assoc event data model path */

    void assign_client_locating_task_id(int new_task_id, bool new_connection);
    int get_client_locating_task_id(bool new_connection);

    bool get_beacon_measurement(const std::string &ap_mac_, uint8_t &rcpi, uint8_t &rsni);
    void set_beacon_measurement(const std::string &ap_mac_, uint8_t rcpi, uint8_t rsni);
    bool get_cross_rx_rssi(const std::string &ap_mac_, int8_t &rssi, int8_t &rx_packets);
    void set_cross_rx_rssi(const std::string &ap_mac_, int8_t rssi, int8_t rx_packets);
    void clear_cross_rssi();
    void set_bss(std::shared_ptr<Agent::sRadio::sBss> bss);
    std::shared_ptr<Agent::sRadio::sBss> get_bss();
    void clear_sta_stats_info();
    bool is_bSta();
    void set_bSta(bool bSta);

    friend class ::son::db;

    beerocks::eBeaconMeasurementSupportLevel supports_beacon_measurement =
        beerocks::BEACON_MEAS_UNSUPPORTED;

private:
    int m_client_locating_task_id_new_connection   = -1;
    int m_client_locating_task_id_exist_connection = -1;

    bool m_supports_11v            = true;
    int m_failed_11v_request_count = 0;
    bool m_is_bSta                 = false;

    bool m_handoff = false;
    std::chrono::steady_clock::time_point last_state_change;

    class beacon_measurement;
    std::unordered_map<std::string, std::shared_ptr<beacon_measurement>> m_beacon_measurements;

    class rssi_measurement;
    std::unordered_map<std::string, std::shared_ptr<rssi_measurement>> m_cross_rx_rssi;
    std::weak_ptr<Agent::sRadio::sBss> m_bss;
    std::vector<uint8_t> m_assoc_frame;
};

} // namespace db
} // namespace controller
} // namespace prplmesh

#endif // STATION_H
