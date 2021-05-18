#include "agent.h"
#include "node.h"

#include <bcl/beerocks_utils.h>

namespace prplmesh {
namespace controller {
namespace db {

std::ostream &operator<<(std::ostream &os, const sAgent::sRadio &radio)
{
    std::chrono::steady_clock::time_point tCurrTime_steady = std::chrono::steady_clock::now();

    os << " IfaceType: " << beerocks::utils::get_iface_type_string(radio.iface_type) << std::endl
       << " Active: " << bool(radio.active) << std::endl
       << " Is backhual manager: " << radio.is_backhaul_manager << std::endl
       << " cac_completed: " << bool(radio.cac_completed) << std::endl
       << " on_dfs_reentry: " << bool(radio.on_dfs_reentry) << std::endl
       << " ap_activity_mode: "
       << ((uint8_t(radio.ap_activity_mode)) ? "AP_ACTIVE_MODE" : "AP_IDLE_MODE") << std::endl;

    for (auto val : radio.supported_channels) {
        if (val.channel > 0) {
            os << " ch=" << int(val.channel) << " | dfs=" << int(val.is_dfs_channel)
               << " | tx_pow=" << int(val.tx_pow) << " | noise=" << int(val.noise)
               << " [dbm] | bss_overlap=" << int(val.bss_overlap) << std::endl;
        }
    }

    os << " AntGain: " << int(radio.ant_gain) << std::endl
       << " AntNum: " << int(radio.ant_num) << std::endl
       << " ConductedPower: " << int(radio.tx_power) << std::endl
       << " Statistics:" << std::endl
       << "   LastUpdate: "
       << float((std::chrono::duration_cast<std::chrono::duration<double>>(
                     tCurrTime_steady - radio.stats_info->timestamp))
                    .count())
       << "[sec]" << std::endl
       << "   StatsDelta: " << float(radio.stats_info->stats_delta_ms) / 1000.0 << "[sec]"
       << std::endl
       << "   ActiveStaCount: " << int(radio.stats_info->active_sta_count) << std::endl
       << "   Packets (RX|TX): " << int(radio.stats_info->rx_packets) << " | "
       << int(radio.stats_info->tx_packets) << std::endl
       << "   Bytes (RX|TX): " << int(radio.stats_info->rx_bytes) << " | "
       << int(radio.stats_info->tx_bytes) << std::endl
       << "   ChannelLoad: " << int(radio.stats_info->channel_load_percent) << " [%]" << std::endl
       << "   TotalStaLoad (RX|TX): " << int(radio.stats_info->total_client_rx_load_percent)
       << " | " << int(radio.stats_info->total_client_tx_load_percent) << " [%] " << std::endl
       << "**radar statistics**" << std::endl;

    for_each(
        begin(radio.Radar_stats), end(radio.Radar_stats), [&](sWifiChannelRadarStats radar_stat) {
            //for(auto radar_stat : radio.Radar_stats) {
            auto delta_radar = std::chrono::duration_cast<std::chrono::seconds>(
                                   radar_stat.csa_exit_timestamp - radar_stat.csa_enter_timestamp)
                                   .count();
            // if(delta// _radar)
            os << "channel = " << int(radar_stat.channel) << " bw = " << int(radar_stat.bandwidth)
               << " time_in_channel = " << int(delta_radar) << std::endl;
            //}
        });
    os << "   RX Load: [";

    for (int i = 0; i < 10; ++i) {
        if (i < radio.stats_info->total_client_rx_load_percent / 10) {
            os << "#";
        } else {
            os << "_";
        }
    }

    os << "] | TX Load: [";

    for (int i = 0; i < 10; ++i) {
        if (i < radio.stats_info->total_client_tx_load_percent / 10) {
            os << "#";
        } else {
            os << "_";
        }
    }

    os << "]";

    return os;
}

} // namespace db
} // namespace controller
} // namespace prplmesh
