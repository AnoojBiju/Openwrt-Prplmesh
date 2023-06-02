/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "bwl/uslm_utils.h"
#include "bcl/son/son_wireless_utils.h"
#include "bwl/uslm_messages.h"
#include "tlvf/tlvftypes.h"
#include <sys/socket.h>

static enum beerocks::eWiFiBandwidth uslm_bw_to_beerocks_bw(const uint16_t bw)
{
    if (bw == 20)
        return beerocks::eWiFiBandwidth::BANDWIDTH_20;
    else if (bw == 40)
        return beerocks::eWiFiBandwidth::BANDWIDTH_40;
    else if (bw == 80)
        return beerocks::eWiFiBandwidth::BANDWIDTH_80;
    else if (bw == 161)
        return beerocks::eWiFiBandwidth::BANDWIDTH_80_80;
    else if (bw == 160)
        return beerocks::eWiFiBandwidth::BANDWIDTH_160;
    else
        return beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN;
}

static enum beerocks::eFreqType uslm_freq_to_beerocks_freq(const uint16_t freq)
{
    if (freq >= 2412 && freq <= 2472)
        return beerocks::eFreqType::FREQ_24G;
    else if (freq >= 5170 && freq <= 5825)
        return beerocks::eFreqType::FREQ_5G;
    else
        return beerocks::eFreqType::FREQ_UNKNOWN;
}

static uint16_t frequency_from_channel_number(uint16_t chan)
{
    uint16_t freq = 0;
    if ((chan >= 1) && (chan <= 13)) {
        freq = (((chan - 1) * 5) + 2412);
    } else if ((chan >= 36) && (chan <= 64)) {
        freq = (((chan - 34) * 5) + 5170);
    } else if ((chan >= 100) && (chan <= 144)) {
        freq = (((chan - 100) * 5) + 5500);
    } else if ((chan >= 149) && (chan <= 161)) {
        freq = (((chan - 149) * 5) + 5745);
    } else if (chan == 165) {
        freq = 5825;
    }
    return (freq);
}

bool uslm_utils::send_message(const std::string &sta_mac, int fd, message_type_t message_type)
{
    if (fd == -1)
        return false;
    const auto mac           = tlvf::mac_from_string(sta_mac);
    unsigned char tx_buf[16] = {};
    size_t msg_builder_idx   = 0;
    tx_buf[msg_builder_idx]  = (unsigned char)message_type;
    msg_builder_idx += sizeof(message_type);
    for (int i = 0; i < 6; i++) {
        tx_buf[msg_builder_idx++] = mac.oct[i];
    }
    if (send(fd, tx_buf, sizeof(tx_buf), 0) < 0) {
        LOG(ERROR) << " Failed to send() message, message_type=" << static_cast<int>(message_type);
        return false;
    }
    return true;
}

bool uslm_utils::send_register_sta_message(const std::string &sta_mac, int fd)
{
    return send_message(sta_mac, fd, message_type_t::MSG_REGISTER_STA);
}

bool uslm_utils::send_sta_link_metrics_request_message(const std::string &sta_mac, int fd)
{
    return send_message(sta_mac, fd, message_type_t::MSG_GET_STA_STATS);
}

bool uslm_utils::send_unregister_sta_message(const std::string &sta_mac, int fd)
{
    return send_message(sta_mac, fd, message_type_t::MSG_UNREGISTER_STA);
}

bool uslm_utils::send_sta_disassoc_query(const std::string &sta_mac, int fd)
{
    return send_message(sta_mac, fd, message_type_t::MSG_STA_DISASSOC_QUERY);
}

error_code_t uslm_utils::get_response_error_code(const response &resp)
{
    return resp.response.error_code;
}

bool uslm_utils::parse_station_stats_from_buf(const uint8_t *buf, size_t buflen,
                                              bwl::sUnassociatedStationStats &stats_out)
{
    if (buflen == 0 || !buf || buflen < sizeof(sta_lm))
        return false;
    sta_lm *station_link_metrics      = (sta_lm *)buf;
    const error_code_t response_error = get_response_error_code(*station_link_metrics);
    if (response_error != error_code_t::ERROR_OK) {
        LOG(ERROR) << "Error code in STA LM response, cannot parse STA link metrics, error="
                   << (int)response_error;
        return false;
    } else {
        stats_out.signal_strength =
            son::wireless_utils::convert_rcpi_from_rssi(station_link_metrics->rssi);
        stats_out.channel = station_link_metrics->channel_number;
        auto freq_type    = uslm_freq_to_beerocks_freq(
            frequency_from_channel_number(station_link_metrics->channel_number));
        if (beerocks::eFreqType::FREQ_UNKNOWN == freq_type) {
            LOG(ERROR) << "Could not determine frequency type from USLM response!";
            return false;
        }
        auto bw_type = uslm_bw_to_beerocks_bw(station_link_metrics->bandwidth);
        beerocks::WifiChannel wifi_channel(station_link_metrics->channel_number, freq_type,
                                           bw_type);
        auto opclass = son::wireless_utils::get_operating_class_by_channel(wifi_channel);
        if (0 == opclass) {
            LOG(ERROR) << "Could not deduce operating class from wifi channel! freq=" << freq_type
                       << ", bandwidth=" << bw_type
                       << ", channel number=" << station_link_metrics->channel_number;
            return false;
        }
        stats_out.operating_class = opclass;
    }
    return true;
}
