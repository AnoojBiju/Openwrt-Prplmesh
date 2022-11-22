#include "uslm_utils.h"
#include "uslm_messages.h"
#include "bcl/son/son_wireless_utils.h"
#include "tlvf/tlvftypes.h"
#include <sys/socket.h>

bool uslm_utils::send_message(const std::string &sta_mac, int fd, message_type_t message_type)
{
    if (fd == -1)
        return false;
    const auto mac           = tlvf::mac_from_string(sta_mac);
    unsigned char tx_buf[16] = {0};
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

error_code_t uslm_utils::get_response_error_code(const response& resp)
{
    return resp.response.error_code;
}

bool uslm_utils::parse_station_stats_from_buf(const uint8_t *buf, size_t buflen,
                                              bwl::sUnassociatedStationStats &stats_out)
{
    if (buflen == 0 || !buf || buflen < sizeof(sta_lm))
        return false;
    sta_lm *station_link_metrics = (sta_lm *)buf;
    const error_code_t response_error = get_response_error_code(*station_link_metrics);
    if (response_error != error_code_t::ERROR_OK) {
        LOG(ERROR) << "Error code in STA LM response, cannot parse STA link metrics, error=" << (int)response_error;
        return false;
    } else {
        stats_out.signal_strength = son::wireless_utils::convert_rcpi_from_rssi(station_link_metrics->rssi);
        stats_out.time_stamp      = station_link_metrics->timestamp;
    }
    return true;
}
