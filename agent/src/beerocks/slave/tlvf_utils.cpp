/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "tlvf_utils.h"

#include "agent_db.h"
#include <bcl/beerocks_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <easylogging++.h>

#include <tlvf/wfa_map/tlvApRadioBasicCapabilities.h>
#include <tlvf/wfa_map/tlvOperatingChannelReport.h>
#include <tlvf/wfa_map/tlvSpatialReuseReport.h>

using namespace beerocks;

/**
 * @brief Get the maximum transmit power of operating class.
 *
 * @param channels_list List of supported channels.
 * @param operating_class Operating class to find max tx for.
 * @return Max tx power for requested operating class.
 */
static int8_t get_operating_class_max_tx_power(
    const std::unordered_map<uint8_t, beerocks::AgentDB::sRadio::sChannelInfo> &channels_list,
    uint8_t operating_class)
{
    int8_t max_tx_power = 0;
    auto oper_class_it  = son::wireless_utils::operating_classes_list.find(operating_class);
    if (oper_class_it == son::wireless_utils::operating_classes_list.end()) {
        LOG(ERROR) << "Operating class does not exist: " << operating_class;
        return beerocks::eGlobals::RSSI_INVALID;
    }

    const auto &oper_class = oper_class_it->second;

    for (const auto &channel_info_element : channels_list) {
        auto channel       = channel_info_element.first;
        auto &channel_info = channel_info_element.second;
        for (const auto &bw_info : channel_info.supported_bw_list) {
            if (son::wireless_utils::has_operating_class_5g_channel(oper_class, channel,
                                                                    bw_info.bandwidth)) {
                max_tx_power = std::max(max_tx_power, channel_info.tx_power_dbm);
            }
        }
    }
    return max_tx_power;
}

/**
 * @brief Get a list of permanent non operable channels for operating class.
 *
 * @param channels_list List of supported channels.
 * @param operating_class Operating class to find non operable channels on.
 * @return std::vector<uint8_t> A vector of non operable channels.
 */
std::vector<uint8_t> get_operating_class_non_oper_channels(
    const std::unordered_map<uint8_t, beerocks::AgentDB::sRadio::sChannelInfo> &channels_list,
    uint8_t operating_class)
{
    std::vector<uint8_t> non_oper_channels;
    auto oper_class_it = son::wireless_utils::operating_classes_list.find(operating_class);
    if (oper_class_it == son::wireless_utils::operating_classes_list.end()) {
        LOG(ERROR) << "Operating class does not exist: " << operating_class;
        return {};
    }

    const auto &oper_class = oper_class_it->second;

    for (const auto &op_class_channel : oper_class.channels) {
        bool found = false;
        for (const auto &channel_info_element : channels_list) {
            auto &channel_info = channel_info_element.second;
            for (const auto &bw_info : channel_info.supported_bw_list) {
                auto channel = channel_info_element.first;
                if (oper_class.band != bw_info.bandwidth) {
                    continue;
                }
                if (son::wireless_utils::is_operating_class_using_central_channel(
                        operating_class)) {
                    channel = son::wireless_utils::get_center_channel(
                        channel, son::wireless_utils::which_freq_op_cls(operating_class),
                        bw_info.bandwidth);
                }
                if (op_class_channel == channel) {
                    found = true;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            non_oper_channels.push_back(op_class_channel);
        }
    }
    return non_oper_channels;
}

bool tlvf_utils::add_ap_radio_basic_capabilities(ieee1905_1::CmduMessageTx &cmdu_tx,
                                                 const sMacAddr &ruid)
{
    std::vector<uint8_t> operating_classes;

    auto radio_basic_caps = cmdu_tx.addClass<wfa_map::tlvApRadioBasicCapabilities>();
    if (!radio_basic_caps) {
        LOG(ERROR) << "Error creating TLV_AP_RADIO_BASIC_CAPABILITIES";
        return false;
    }
    radio_basic_caps->radio_uid() = ruid;

    auto db    = AgentDB::get();
    auto radio = db->get_radio_by_mac(ruid);
    if (!radio) {
        LOG(ERROR) << "ruid not found: " << ruid;
        return false;
    }

    int num_bsses = std::count_if(radio->front.bssids.begin(), radio->front.bssids.end(),
                                  [](beerocks::AgentDB::sRadio::sFront::sBssid b) {
                                      return b.mac != net::network_utils::ZERO_MAC;
                                  });
    LOG(DEBUG) << "Radio reports " << num_bsses << " BSSes.";

    radio_basic_caps->maximum_number_of_bsss_supported() = num_bsses;
    LOG(DEBUG) << "Filling Supported operating classes on radio " << radio->front.iface_name
               << " (band type: "
               << beerocks::utils::convert_frequency_type_to_string(
                      radio->wifi_channel.get_freq_type())
               << "):";
    operating_classes = son::wireless_utils::get_operating_classes_of_freq_type(
        radio->wifi_channel.get_freq_type());

    for (auto op_class : operating_classes) {
        auto operationClassesInfo = radio_basic_caps->create_operating_classes_info_list();
        if (!operationClassesInfo) {
            LOG(ERROR) << "Failed creating operating classes info list";
            return false;
        }

        operationClassesInfo->operating_class() = op_class;
        operationClassesInfo->maximum_transmit_power_dbm() =
            get_operating_class_max_tx_power(radio->channels_list, op_class);

        auto non_oper_channels =
            get_operating_class_non_oper_channels(radio->channels_list, op_class);
        if (!non_oper_channels.empty()) {
            // Create list of statically non-oper channels

            operationClassesInfo->alloc_statically_non_operable_channels_list(
                non_oper_channels.size());
            uint8_t idx = 0;
            for (auto non_oper : non_oper_channels) {
                *operationClassesInfo->statically_non_operable_channels_list(idx) = non_oper;
                idx++;
            }
        }

        LOG(DEBUG) << "OpClass=" << op_class
                   << ", max_tx_dbm=" << operationClassesInfo->maximum_transmit_power_dbm()
                   << ", non_operable_channels=" << [&]() {
                          if (non_oper_channels.empty()) {
                              return std::string{"None"};
                          }
                          std::string out;
                          for (auto non_oper_ch : non_oper_channels) {
                              out.append(std::to_string(non_oper_ch)).append(",");
                          }
                          out.pop_back();
                          return out;
                      }();

        if (!radio_basic_caps->add_operating_classes_info_list(operationClassesInfo)) {
            LOG(ERROR) << "add_operating_classes_info_list failed";
            return false;
        }
    }

    return true;
}

bool tlvf_utils::create_operating_channel_report(ieee1905_1::CmduMessageTx &cmdu_tx,
                                                 const sMacAddr &radio_mac)
{
    auto radio = AgentDB::get()->get_radio_by_mac(radio_mac);
    if (!radio) {
        LOG(ERROR) << "Radio " << radio_mac << " does not exist on the db";
        return false;
    }

    auto operating_channel_report_tlv = cmdu_tx.addClass<wfa_map::tlvOperatingChannelReport>();
    if (!operating_channel_report_tlv) {
        LOG(ERROR) << "addClass ieee1905_1::operating_channel_report_tlv has failed";
        return false;
    }
    operating_channel_report_tlv->radio_uid() = radio_mac;

    auto op_classes_list = operating_channel_report_tlv->alloc_operating_classes_list();
    if (!op_classes_list) {
        LOG(ERROR) << "alloc_operating_classes_list() has failed!";
        return false;
    }

    auto operating_class_entry_tuple = operating_channel_report_tlv->operating_classes_list(0);
    if (!std::get<0>(operating_class_entry_tuple)) {
        LOG(ERROR) << "getting operating class entry has failed!";
        return false;
    }

    auto &operating_class_entry = std::get<1>(operating_class_entry_tuple);
    auto operating_class = son::wireless_utils::get_operating_class_by_channel(radio->wifi_channel);

    auto center_channel =
        son::wireless_utils::freq_to_channel(radio->wifi_channel.get_center_frequency());
    operating_class_entry.operating_class = operating_class;
    // operating classes 128,129,130 use center channel **unlike the other classes** (See Table
    // E-4 in 802.11 spec)
    operating_class_entry.channel_number =
        son::wireless_utils::is_operating_class_using_central_channel(operating_class)
            ? center_channel
            : radio->wifi_channel.get_channel();
    operating_channel_report_tlv->current_transmit_power() = radio->tx_power_dB;

    auto wifi6_caps =
        reinterpret_cast<beerocks::net::sWIFI6Capabilities *>(&radio->wifi6_capability);

    // Missing wifi6_caps->spatial_reuse. PPM-2602.
    if (!wifi6_caps->spatial_reuse) {
        LOG(WARNING) << "Missing spatial_reuse in WiFi 6 capabilities";
        wifi6_caps->spatial_reuse = true;
    }

    if (wifi6_caps->spatial_reuse) {
        auto spatial_reuse_report_tlv = cmdu_tx.addClass<wfa_map::tlvSpatialReuseReport>();
        if (!spatial_reuse_report_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvSpatialReuseReport has failed";
            return false;
        }

        LOG(DEBUG) << "Adding spatial reuse params to operating channel report for radio : "
                   << radio_mac;

        spatial_reuse_report_tlv->radio_uid() = radio_mac;

        spatial_reuse_report_tlv->flags1().bss_color = radio->spatial_reuse_params.bss_color;
        spatial_reuse_report_tlv->flags1().partial_bss_color =
            radio->spatial_reuse_params.partial_bss_color;
        spatial_reuse_report_tlv->flags2().hesiga_spatial_reuse_value15_allowed =
            (radio->spatial_reuse_params.hesiga_spatial_reuse_value15_allowed ? 1 : 0);
        spatial_reuse_report_tlv->flags2().srg_information_valid =
            (radio->spatial_reuse_params.srg_information_valid ? 1 : 0);
        spatial_reuse_report_tlv->flags2().non_srg_offset_valid =
            (radio->spatial_reuse_params.non_srg_offset_valid ? 1 : 0);
        spatial_reuse_report_tlv->flags2().psr_disallowed =
            (radio->spatial_reuse_params.psr_disallowed ? 1 : 0);
        spatial_reuse_report_tlv->non_srg_obsspd_max_offset() =
            radio->spatial_reuse_params.non_srg_obsspd_max_offset;
        spatial_reuse_report_tlv->srg_obsspd_min_offset() =
            radio->spatial_reuse_params.srg_obsspd_min_offset;
        spatial_reuse_report_tlv->srg_obsspd_max_offset() =
            radio->spatial_reuse_params.srg_obsspd_max_offset;
        spatial_reuse_report_tlv->srg_bss_color_bitmap() =
            radio->spatial_reuse_params.srg_bss_color_bitmap;
        spatial_reuse_report_tlv->srg_partial_bssid_bitmap() =
            radio->spatial_reuse_params.srg_partial_bssid_bitmap;
        spatial_reuse_report_tlv->neighbor_bss_color_in_use_bitmap() =
            radio->spatial_reuse_params.neighbor_bss_color_in_use_bitmap;
    }

    LOG(DEBUG) << "Created Operating Channel Report TLV";
    return true;
}
