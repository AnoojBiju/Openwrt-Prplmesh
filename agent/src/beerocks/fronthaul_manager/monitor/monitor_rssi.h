/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef MONITOR_RSSI_H
#define MONITOR_RSSI_H

#include "monitor_db.h"

#include <bcl/beerocks_cmdu_client.h>
#include <bcl/beerocks_message_structs.h>
#include <bcl/network/socket.h>

#include <tlvf/CmduMessageTx.h>

const unsigned DEFAULT_IDLE_UNIT_TX_THRESHOLD = 50000;
const unsigned DEFAULT_IDLE_UNIT_RX_THRESHOLD = 50000;
const unsigned DEFAULT_IDLE_UNIT_TIME_MS      = 1000;

namespace son {
class monitor_rssi {

public:
    explicit monitor_rssi(ieee1905_1::CmduMessageTx &cmdu_tx_);
    ~monitor_rssi() {}
    bool start(monitor_db *mon_db_, std::shared_ptr<beerocks::CmduClient> slave_client);
    void stop();
    Socket *get_arp_socket();

    void process();
    void arp_recv();

    int conf_rx_rssi_notification_delta_db      = 8;
    int conf_rx_rssi_notification_threshold_dbm = -60;
    bool conf_disable_initiative_arp            = false;
    beerocks::eFreqType freq_type               = beerocks::eFreqType::FREQ_UNKNOWN;

private:
    void send_rssi_measurement_response(const std::string &sta_mac, monitor_sta_node *sta_node);
    void monitor_idle_station(const std::string &sta_mac, monitor_sta_node *sta_node);

    monitor_db *mon_db = nullptr;

    /**
     * CMDU client to send messages to the CMDU server running in slave.
     */
    std::shared_ptr<beerocks::CmduClient> m_slave_client;

    int arp_socket;
    Socket *arp_socket_class;

    unsigned m_idle_unit_tx_threshold;
    unsigned m_idle_unit_rx_threshold;
    unsigned m_idle_unit_time_ms;

    ieee1905_1::CmduMessageTx &cmdu_tx;
};

} //namespace son

#endif // MONITOR_RSSI_H
