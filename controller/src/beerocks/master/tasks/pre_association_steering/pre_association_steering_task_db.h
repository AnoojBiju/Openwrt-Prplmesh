/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_string_utils.h>
#include <beerocks/tlvf/beerocks_message_common.h>
#include <memory>
#include <unordered_map>

namespace son {
class pre_association_steering_task_db {
public:
    class ClientConfig {
    public:
        ClientConfig(const std::string &mac_,
                     const beerocks_message::sSteeringClientConfig &config_)
            : m_mac(mac_)
        {
            m_snr_probe_req_hwm       = config_.snrProbeHWM;
            m_snr_probe_req_lwm       = config_.snrProbeLWM;
            m_snr_auth_frame_hwm      = config_.snrAuthHWM;
            m_snr_auth_frame_lwm      = config_.snrAuthLWM;
            m_snr_inactivity_crossing = config_.snrInactXing;
            m_snr_high_crossing       = config_.snrHighXing;
            m_snr_low_crossing        = config_.snrLowXing;
            m_auth_reject_reason      = config_.authRejectReason;
        }

        std::shared_ptr<beerocks_message::sSteeringClientConfig> get_client_config() const
        {
            auto config              = std::make_shared<beerocks_message::sSteeringClientConfig>();
            config->snrProbeHWM      = m_snr_probe_req_hwm;
            config->snrProbeLWM      = m_snr_probe_req_lwm;
            config->snrAuthHWM       = m_snr_auth_frame_hwm;
            config->snrAuthLWM       = m_snr_auth_frame_lwm;
            config->snrInactXing     = m_snr_inactivity_crossing;
            config->snrHighXing      = m_snr_high_crossing;
            config->snrLowXing       = m_snr_low_crossing;
            config->authRejectReason = m_auth_reject_reason;
            return config;
        }

    private:
        std::string m_mac;
        unsigned int m_snr_probe_req_hwm;
        unsigned int m_snr_probe_req_lwm;
        unsigned int m_snr_auth_frame_hwm;
        unsigned int m_snr_auth_frame_lwm;
        unsigned int m_snr_inactivity_crossing;
        unsigned int m_snr_high_crossing;
        unsigned int m_snr_low_crossing;
        unsigned int m_auth_reject_reason;
    };

    class ApConfig {
    public:
        explicit ApConfig(const beerocks_message::sSteeringApConfig &config_)
        {
            m_bssid                          = tlvf::mac_to_string(config_.bssid);
            m_util_check_interval_sec        = config_.utilCheckIntervalSec;
            m_util_avg_count                 = config_.utilAvgCount;
            m_inactivity_check_interval_sec  = config_.inactCheckIntervalSec;
            m_inactivity_check_threshold_sec = config_.inactCheckThresholdSec;
        }

        beerocks_message::sSteeringApConfig get_ap_config() const
        {
            beerocks_message::sSteeringApConfig config;
            config.bssid                  = tlvf::mac_from_string(m_bssid);
            config.utilCheckIntervalSec   = m_util_check_interval_sec;
            config.utilAvgCount           = m_util_avg_count;
            config.inactCheckIntervalSec  = m_inactivity_check_interval_sec;
            config.inactCheckThresholdSec = m_inactivity_check_threshold_sec;
            return config;
        }

        ApConfig operator=(const beerocks_message::sSteeringApConfig &config_)
        {
            this->m_bssid                          = tlvf::mac_to_string(config_.bssid);
            this->m_util_check_interval_sec        = config_.utilCheckIntervalSec;
            this->m_util_avg_count                 = config_.utilAvgCount;
            this->m_inactivity_check_interval_sec  = config_.inactCheckIntervalSec;
            this->m_inactivity_check_threshold_sec = config_.inactCheckThresholdSec;
            return *this;
        }

        std::unordered_map<std::string, std::shared_ptr<ClientConfig>> &get_client_config_list()
        {
            return m_client_config_list;
        }

        const std::string &get_bssid() const { return m_bssid; }

    private:
        std::unordered_map<std::string, std::shared_ptr<ClientConfig>> m_client_config_list;
        std::string m_bssid;
        unsigned int m_util_check_interval_sec;
        unsigned int m_util_avg_count;
        unsigned int m_inactivity_check_interval_sec;
        unsigned int m_inactivity_check_threshold_sec;
    };

    class SteeringGroupConfig {
    public:
        SteeringGroupConfig(int index_, const beerocks_message::sSteeringApConfig &config_2ghz_,
                            const beerocks_message::sSteeringApConfig &config_5ghz_)
            : m_index(index_), m_config_2ghz(config_2ghz_), m_config_5ghz(config_5ghz_)
        {
        }

        std::shared_ptr<beerocks_message::sSteeringApConfig>
        get_ap_config(const std::string &bssid);
        bool get_client_config(const std::string &mac, const std::string &bssid,
                               std::shared_ptr<beerocks_message::sSteeringClientConfig> &config);
        bool set_client_config(const std::string &mac, const std::string &bssid,
                               const beerocks_message::sSteeringClientConfig &config);
        bool clear_client_config(const std::string &mac, const std::string &bssid);
        bool update_group_config(const beerocks_message::sSteeringApConfig &config_2ghz,
                                 const beerocks_message::sSteeringApConfig &config_5ghz);
        ApConfig &get_config_2ghz() { return m_config_2ghz; }
        ApConfig &get_config_5ghz() { return m_config_5ghz; }

    private:
        const int m_index;
        ApConfig m_config_2ghz;
        ApConfig m_config_5ghz;
    };

    std::unordered_map<int, std::shared_ptr<SteeringGroupConfig>> m_steering_group_list;

    bool get_client_config(const std::string &mac, const std::string &bssid,
                           const int steering_group_index,
                           std::shared_ptr<beerocks_message::sSteeringClientConfig> &config);

    bool set_client_config(const std::string &mac, const std::string &bssid,
                           int steering_group_index,
                           const beerocks_message::sSteeringClientConfig &config);

    bool clear_client_config(const std::string &mac, const std::string &bssid,
                             int steering_group_index);

    bool set_steering_group_config(int index,
                                   const beerocks_message::sSteeringApConfig &config_2ghz,
                                   const beerocks_message::sSteeringApConfig &config_5ghz);

    bool clear_steering_group_config(int index);

    std::pair<bool, beerocks_message::sSteeringApConfig> get_ap_config(const std::string &bssid);

    std::unordered_map<std::string, std::shared_ptr<beerocks_message::sSteeringClientConfig>>
    get_client_config_list(const std::string &bssid);

    const std::unordered_map<int, std::shared_ptr<SteeringGroupConfig>> &get_steering_group_list()
    {
        return m_steering_group_list;
    }

    int32_t get_group_index(const std::string &client_mac, const std::string &bssid);

    void print_db();
};
} // namespace son
