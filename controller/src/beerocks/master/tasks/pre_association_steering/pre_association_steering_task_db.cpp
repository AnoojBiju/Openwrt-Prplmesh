/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "pre_association_steering_task_db.h"
#include <algorithm>
#include <easylogging++.h>

using namespace beerocks;
using namespace son;

bool pre_association_steering_task_db::SteeringGroupConfig::get_client_config(
    const std::string &mac, const std::string &bssid,
    std::shared_ptr<beerocks_message::sSteeringClientConfig> &config)
{
    bool is_bssid_found = false;
    for (auto &ap_cfg : m_ap_cfgs) {
        if (ap_cfg.get_bssid() == bssid) {
            auto it = ap_cfg.get_client_config_list().find(mac);
            if (it == ap_cfg.get_client_config_list().end()) {
                return false;
            }
            config         = it->second->get_client_config();
            is_bssid_found = true;
        }
    }
    if (!is_bssid_found) {
        LOG(ERROR) << "no bssid=" << bssid << " for steering_group_index=" << m_index;
        return false;
    }
    return true;
}

bool pre_association_steering_task_db::get_client_config(
    const std::string &mac, const std::string &bssid, const int steering_group_index,
    std::shared_ptr<beerocks_message::sSteeringClientConfig> &config)
{
    auto it = m_steering_group_list.find(steering_group_index);
    if (it == m_steering_group_list.end()) {
        LOG(ERROR) << "can't find steering group " << steering_group_index;
        return false;
    }

    auto steering_group = it->second;
    return steering_group->get_client_config(mac, bssid, config);
}

bool pre_association_steering_task_db::SteeringGroupConfig::set_client_config(
    const std::string &mac, const std::string &bssid,
    const beerocks_message::sSteeringClientConfig &config)
{
    auto new_entry = std::make_shared<ClientConfig>(mac, config);

    bool is_bssid_found = false;
    for (auto &ap_cfg : m_ap_cfgs) {
        if (ap_cfg.get_bssid() == bssid) {
            ap_cfg.get_client_config_list()[mac] = new_entry;
            is_bssid_found                       = true;
            break;
        }
    }
    if (!is_bssid_found) {
        LOG(ERROR) << "set_client_config: no bssid=" << bssid
                   << " for steering_group_index=" << m_index;
        return false;
    }
    return true;
}

bool pre_association_steering_task_db::SteeringGroupConfig::clear_client_config(
    const std::string &mac, const std::string &bssid)
{
    bool is_bssid_found = false;

    for (auto &ap_cfg : m_ap_cfgs) {
        if (ap_cfg.get_bssid() == bssid) {
            ap_cfg.get_client_config_list().erase(mac);
            is_bssid_found = true;
        }
    }

    if (!is_bssid_found) {
        LOG(ERROR) << "clear_client_config: no bssid=" << bssid
                   << " for steering_group_index=" << m_index;
        return false;
    }
    return true;
}

bool pre_association_steering_task_db::SteeringGroupConfig::update_group_config(
    const std::vector<beerocks_message::sSteeringApConfig> &ap_cfgs_)
{
    for (auto &ap_cfg_ : ap_cfgs_) {
        auto bssid_ = tlvf::mac_to_string(ap_cfg_.bssid);
        auto ap_cfg_it =
            std::find_if(m_ap_cfgs.begin(), m_ap_cfgs.end(),
                         [&](const pre_association_steering_task_db::ApConfig &ap_cfg) {
                             return bssid_ == ap_cfg.get_bssid();
                         });
        if (ap_cfg_it == m_ap_cfgs.end()) {
            LOG(ERROR) << "update_group_config: Can't change bssid for" << bssid_
                       << "in an existing steeringGroup";
            return false;
        } else {
            *ap_cfg_it = ap_cfg_;
        }
    }
    return true;
}

bool pre_association_steering_task_db::set_client_config(
    const std::string &mac, const std::string &bssid, int steering_group_index,
    const beerocks_message::sSteeringClientConfig &config)
{
    auto it = m_steering_group_list.find(steering_group_index);
    if (it == m_steering_group_list.end()) {
        LOG(ERROR) << "can't find steering group " << steering_group_index;
        return false;
    }

    auto steering_group = it->second;
    return steering_group->set_client_config(mac, bssid, config);
}

bool pre_association_steering_task_db::clear_client_config(const std::string &mac,
                                                           const std::string &bssid,
                                                           int steering_group_index)
{
    auto it = m_steering_group_list.find(steering_group_index);
    if (it == m_steering_group_list.end()) {
        LOG(ERROR) << "can't find steering group " << steering_group_index;
        return false;
    }

    auto steering_group = it->second;
    return steering_group->clear_client_config(mac, bssid);
}

bool pre_association_steering_task_db::set_steering_group_config(
    int index, const std::vector<beerocks_message::sSteeringApConfig> &ap_cfgs)
{
    auto it = m_steering_group_list.find(index);
    if (it == m_steering_group_list.end()) {
        auto new_entry               = std::make_shared<SteeringGroupConfig>(index, ap_cfgs);
        m_steering_group_list[index] = new_entry;
    } else {
        //otherwise update the parameters but don't overwrite the client config list
        auto steering_group = it->second;
        steering_group->update_group_config(ap_cfgs);
    }
    return true;
}

bool pre_association_steering_task_db::clear_steering_group_config(int index)
{
    auto it = m_steering_group_list.find(index);
    if (it == m_steering_group_list.end()) {
        LOG(ERROR) << "can't find steering group index=" << index;
        return false;
    } else {
        it = m_steering_group_list.erase(it);
        return true;
    }
}

std::pair<bool, beerocks_message::sSteeringApConfig>
pre_association_steering_task_db::get_ap_config(const std::string &bssid)
{
    for (auto group_entry : m_steering_group_list) {
        auto steering_group = group_entry.second;
        for (auto &ap_cfg : steering_group->get_ap_configs()) {
            if (ap_cfg.get_bssid() == bssid) {
                return std::make_pair(true, ap_cfg.get_ap_config());
            }
        }
    }
    LOG(ERROR) << "can't find entry for bssid=" << bssid;
    return {};
}

std::unordered_map<std::string, std::shared_ptr<beerocks_message::sSteeringClientConfig>>
pre_association_steering_task_db::get_client_config_list(const std::string &bssid)
{
    std::unordered_map<std::string, std::shared_ptr<beerocks_message::sSteeringClientConfig>>
        result;
    for (auto group_entry : m_steering_group_list) {
        auto steering_group = group_entry.second;
        for (auto &ap_cfg : steering_group->get_ap_configs()) {
            if (ap_cfg.get_bssid() == bssid) {
                auto &client_config_list = ap_cfg.get_client_config_list();
                for (auto client_config_entry : client_config_list) {
                    result[client_config_entry.first] =
                        client_config_entry.second->get_client_config();
                }
                break;
            }
        }
    }
    return result;
}

int32_t pre_association_steering_task_db::get_group_index(const std::string &client_mac,
                                                          const std::string &bssid)
{
    //notification common data: group index
    for (auto group_entry : m_steering_group_list) {
        auto steering_group = group_entry.second;
        for (auto &ap_cfg : steering_group->get_ap_configs()) {
            auto &client_config_map = ap_cfg.get_client_config_list();
            auto client_config_it   = client_config_map.find(client_mac);
            if (client_config_it != client_config_map.end() && ap_cfg.get_bssid() == bssid) {
                return group_entry.first;
            }
        }
    }
    return -1;
}

void pre_association_steering_task_db::print_db()
{
    std::unordered_map<std::string,
                       std::shared_ptr<son::pre_association_steering_task_db::ClientConfig>>
        clients_list;
    //notification common data: group index
    std::for_each(
        m_steering_group_list.begin(), m_steering_group_list.end(),
        [&](std::pair<int, std::shared_ptr<SteeringGroupConfig>> const &group_entry) {
            LOG(DEBUG) << "***********************PRE_ASSOCIATION_STEERING_DATABASE****************"
                          "*******";
            for (auto &ap_cfg : group_entry.second->get_ap_configs()) {
                LOG(DEBUG) << "group_index = " << group_entry.first;
                LOG(DEBUG) << "ap config***** ";
                LOG(DEBUG) << "     bssid " << ap_cfg.get_bssid();
                LOG(DEBUG) << "     utilCheckIntervalSec "
                           << int(ap_cfg.get_ap_config().utilCheckIntervalSec);
                LOG(DEBUG) << "     utilAvgCount " << int(ap_cfg.get_ap_config().utilAvgCount);
                LOG(DEBUG) << "     inactCheckIntervalSec "
                           << ap_cfg.get_ap_config().inactCheckIntervalSec;
                LOG(DEBUG) << "     inactCheckThresholdSec "
                           << ap_cfg.get_ap_config().inactCheckThresholdSec;
                LOG(DEBUG) << "*********client_list********* ";
                clients_list = ap_cfg.get_client_config_list();
            }

            std::for_each(
                clients_list.begin(), clients_list.end(),
                [&](std::pair<std::string, std::shared_ptr<ClientConfig>> const &client_entry) {
                    LOG(DEBUG) << "             client_mac " << client_entry.first;
                    LOG(DEBUG) << "                 snrProbeHWM "
                               << int(client_entry.second->get_client_config()->snrProbeHWM);
                    LOG(DEBUG) << "                 snrProbeLWM "
                               << int(client_entry.second->get_client_config()->snrProbeLWM);
                    LOG(DEBUG) << "                 snrAuthHWM "
                               << int(client_entry.second->get_client_config()->snrAuthHWM);
                    LOG(DEBUG) << "                 snrAuthLWM "
                               << int(client_entry.second->get_client_config()->snrAuthLWM);
                    LOG(DEBUG) << "                 snrInactXing "
                               << int(client_entry.second->get_client_config()->snrInactXing);
                    LOG(DEBUG) << "                 snrHighXing "
                               << int(client_entry.second->get_client_config()->snrHighXing);
                    LOG(DEBUG) << "                 snrLowXing "
                               << int(client_entry.second->get_client_config()->snrLowXing);
                    LOG(DEBUG) << "                 authRejectReason "
                               << int(client_entry.second->get_client_config()->authRejectReason);
                });
        });
}
