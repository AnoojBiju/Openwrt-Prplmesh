/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _ON_BOOT_SCAN_TASK_H_
#define _ON_BOOT_SCAN_TASK_H_

#include "../agent_db.h"
#include "scan_task.h"
#include "task.h"
#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanRequest.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>
#include <tlvf/wfa_map/tlvTimestamp.h>
#include <vector>

namespace beerocks {

// Forward declaration for BackhaulManager context saving
class BackhaulManager;

class OnBootScanTask : public ScanTask, public Task {
public:
    OnBootScanTask(BackhaulManager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~OnBootScanTask() {}

    void work() override;

    struct sScanRequestEvent {
    };

    enum eEvent : uint8_t { INDEPENDENT_SCAN_REQUEST };

    void handle_event(uint8_t event_enum_value, const void *event_obj) override;

    /**
     * @brief Handles incoming messages.
     *
     * @param[in] cmdu_rx Received CMDU.
     * @param[in] iface_index Interface index.
     * @param[in] dst_mac MAC address of the message receiver.
     * @param[in] src_mac MAC address of the message sender.
     * @param[in] fd File descriptor of the socket connection with the slave that sent the message.
     * @param[in] beerocks_header Shared pointer to beerocks header.
     * @return true, if the message has been handled, otherwise false.
     */
    bool handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                     std::shared_ptr<beerocks_header> beerocks_header) override;

    /**
     * @brief Handles Vendor Specific messages.
     *
     * @param[in] cmdu_rx Received CMDU.
     * @param[in] src_mac MAC address of the message sender.
     * @param[in] fd File descriptor of the socket connection with the slave that sent the message.
     * @param[in] beerocks_header Shared pointer to beerocks header.
     * @return true, if the message has been handled, otherwise false.
     */
    bool handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac, int fd,
                                std::shared_ptr<beerocks_header> beerocks_header);

    /* Scan helper functions */

    /**
     * @brief Check if given request has finished all its radio scans.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if all Radio Scans are finished, otherwise false.
     */
    bool is_scan_request_finished(const std::shared_ptr<sScanRequest> request) override;

    /**
     * @brief Abort the unfinished Radio Scans for the given request.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if the Abort Scan requests were sent successfully.
     */
    bool abort_scan_request(const std::shared_ptr<sScanRequest> request) override;

    /**
     * @brief Find the next pending Radio Scan and send a Trigger Scan request to the monitor.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if a Trigger Scan request was sent, otherwise false.
     */
    bool trigger_next_radio_scan(const std::shared_ptr<sScanRequest> request) override;

    /**
     * @brief Sets the status for the individual channels within a given scan.
     * 
     * @param radio_scan_info A shared pointer to the radio scan info.
     * @param status The new scan status that needs to be set.
     * 
     * @return True if the operation was successful, false otherwise.
     */
    bool set_radio_scan_status(const std::shared_ptr<sRadioScan> radio_scan_info,
                               const eScanStatus status) override;

    /**
     * @brief Send a Trigger Scan Request CMDU to the monitor.
     * 
     * @param radio_iface  Iface name of the radio to which we want to send the CMDU.
     * @param radio_scan_info A shared pointer to the radio scan info.
     *
     * @return True if a Trigger Scan request was sent, otherwise false.
     */
    bool trigger_radio_scan(const std::string &radio_iface,
                            const std::shared_ptr<sRadioScan> radio_scan_info) override;

    /**
     * @brief Store the given result in the agent DB.
     * 
     * @param request A shared pointer to the request info.
     * @param radio_mac MAC address of the radio from which we received the result.
     * @param results A Channel Scan result received from the monitor.
     *
     * @return True if the result was successfully stored in the DB.
     */
    bool store_radio_scan_result(const std::shared_ptr<sScanRequest> request,
                                 const sMacAddr &radio_mac,
                                 beerocks_message::sChannelScanResults results) override;

    /**
     * @brief Send 1905 CHANNEL_SCAN_REPORT message back to the sender.
     * 
     * @param[in] request request object
     *
     * @return True on success, otherwise false.
     */
    bool
    send_channel_scan_report_to_controller(const std::shared_ptr<sScanRequest> request) override;

    /**
     * @brief Get all stored results for the given request
     * 
     * @param[in] request request object
     * 
     * @return Stored Result vector containing all stored results for the given request
     */
    std::shared_ptr<StoredResultsVector>
    get_scan_results_for_request(const std::shared_ptr<sScanRequest> request) override;

private:
    BackhaulManager &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;
    std::shared_ptr<sScanRequest> new_request;
    std::shared_ptr<sRadioScan> new_radio_scan;

    struct sCurrentScan {
        bool is_scan_currently_running             = false;
        std::shared_ptr<sScanRequest> scan_request = nullptr;
        std::shared_ptr<sRadioScan> radio_scan     = nullptr;
    } m_current_scan_info;

    /**
     * Map containing previous successful scans
     * Key: Operating Class
     * Value: Channel List
     */
    std::unordered_map<uint8_t, std::unordered_set<uint8_t>> m_previous_scans;
    std::deque<std::shared_ptr<sScanRequest>> m_pending_requests;

    /**
    * @brief Handles On Boot scan request message.
    * 
    * @param[in] cmdu_rx Received CMDU.
    * @param[in] src_mac MAC address of the message sender.
    * @param[in] radio_mac Perform scan on this radio
    * @param[in] send_results
    *
    * @return True on success, otherwise false.
    */
    bool handle_on_boot_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac,
                                     const sMacAddr &radio_mac, const bool &send_results = false);
};

} // namespace beerocks

#endif // _ON_BOOT_SCAN_TASK_H_
