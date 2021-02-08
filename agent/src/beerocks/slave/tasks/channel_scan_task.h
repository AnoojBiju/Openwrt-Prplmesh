/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _CHANNEL_SCAN_TASK_H_
#define _CHANNEL_SCAN_TASK_H_

#include "task.h"
#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanRequest.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>
#include <tlvf/wfa_map/tlvTimestamp.h>
#include <vector>

namespace beerocks {

// Forward declaration for BackhaulManager context saving
class BackhaulManager;

class ChannelScanTask : public Task {
public:
    ChannelScanTask(BackhaulManager &btl_ctx, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~ChannelScanTask() {}

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

private:
    /* Class members */

    /**
     * @brief channel scan Task states.
     * 
     */
    enum eState : uint8_t {
        PENDING_TRIGGER,
        WAIT_FOR_SCAN_TRIGGERED,
        WAIT_FOR_RESULTS_READY,
        WAIT_FOR_RESULTS_DUMP,
        SCAN_DONE,
        SCAN_ABORTED,
        SCAN_FAILED,
    };

    // clang-format off
    const std::unordered_map<eState, std::string, std::hash<int>> m_states_string = {
      { eState::PENDING_TRIGGER,         "PENDING_TRIGGER"          }, // Waiting for for the current Scan to complete.
      { eState::WAIT_FOR_SCAN_TRIGGERED, "WAIT_FOR_SCAN_TRIGGERED"  }, // Pending on "Scan Triggered" event.
      { eState::WAIT_FOR_RESULTS_READY,  "WAIT_FOR_RESULTS_READY"   }, // Pending on "Results Ready" event.
      { eState::WAIT_FOR_RESULTS_DUMP,   "WAIT_FOR_RESULTS_DUMP"    }, // Pending on "Results Dump" event.
      { eState::SCAN_DONE,               "SCAN_DONE"                }, // Scan finished Results Sequence.
      { eState::SCAN_ABORTED,            "SCAN_ABORTED"             }, // Scan was aborted.
      { eState::SCAN_FAILED,             "SCAN_FAILED"              }  // Scan failed for some reason.
    };
    // clang-format on

    struct sOperationalClass {
        uint8_t operating_class;
        uint8_t channel_list[10];
        uint8_t channel_list_length;
        sOperationalClass(uint8_t _operating_class, uint8_t *_channel_list,
                          uint8_t _channel_list_length)
            : operating_class(_operating_class), channel_list_length(_channel_list_length)
        {
            if (_channel_list) {
                std::copy_n(_channel_list, _channel_list_length, channel_list);
            }
        }
    };
    struct sRadioScan {
        sMacAddr radio_mac;
        std::vector<sOperationalClass> operating_classes;
        wfa_map::tlvProfile2ChannelScanResult::eScanStatus scan_status;
        eState current_state;
        std::chrono::system_clock::time_point timeout;
        int dwell_time;
    };
    struct sRequestInfo {
        enum eScanRequestType {
            ControllerRequested,
            AgentRequested,
        };
        wfa_map::tlvProfile2ChannelScanRequest::ePerformFreshScan perform_fresh_scan;
        eScanRequestType request_type;
        explicit sRequestInfo(eScanRequestType _request_type) : request_type(_request_type) {}
    };
    struct sControllerRequestInfo : sRequestInfo {
        int mid;
        sMacAddr src_mac;
        sControllerRequestInfo() : sRequestInfo(eScanRequestType::ControllerRequested) {}
    };
    struct sScanRequest {
        std::shared_ptr<sRequestInfo> request_info;
        std::chrono::system_clock::time_point scan_start_timestamp;
        std::unordered_map<std::string, std::shared_ptr<sRadioScan>> radio_scans;
        bool ready_to_send_report;
    };
    std::deque<std::shared_ptr<sScanRequest>> m_pending_requests;

    /**
     * Currently only one Channel Scan per radio is supported.
     * When PPM-711 is resolved we need to rework the trigger mechanism to support multiple
     * simultaneous radio scans.
     * https://jira.prplfoundation.org/browse/PPM-711
     */
    struct sCurrentScan {
        bool is_scan_currently_running             = false;
        std::shared_ptr<sScanRequest> scan_request = nullptr;
        std::shared_ptr<sRadioScan> radio_scan     = nullptr;
    } m_current_scan_info;

    BackhaulManager &m_btl_ctx;
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    /* Request handling helper functions */

    /**
     * @brief Check if given request has finished all its radio scans.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if all Radio Scans are finished, otherwise false.
     */
    bool is_scan_request_finished(const std::shared_ptr<sScanRequest> request);

    /**
     * @brief Abort the unfinished Radio Scans for the given request.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if the Abort Scan requests were sent successfully.
     */
    bool abort_scan_request(const std::shared_ptr<sScanRequest> request);

    /**
     * @brief Find the next pending Radio Scan and send a Trigger Scan request to the monitor.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if a Trigger Scan request was sent, otherwise false.
     */
    bool trigger_next_radio_scan(const std::shared_ptr<sScanRequest> request);

    /* Radio Scan handling helper functions */

    /**
     * @brief Send a Trigger Scan Request CMDU to the monitor.
     * 
     * @param radio_iface  Iface name of the radio to which we want to send the CMDU.
     * @param radio_scan_info A shared pointer to the radio scan info.
     *
     * @return True if a Trigger Scan request was sent, otherwise false.
     */
    bool trigger_radio_scan(const std::string &radio_iface,
                            const std::shared_ptr<sRadioScan> radio_scan_info);

    /* Scan result handling helper functions */

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
                                 beerocks_message::sChannelScanResults results);

    /* 1905.1 message handlers: */

    /**
    * @brief Handles 1905 channel scan request message.
    * 
    * @param[in] cmdu_rx Received CMDU.
    * @param[in] src_mac MAC address of the message sender.
    *
    * @return True on success, otherwise false.
    */
    bool handle_channel_scan_request(ieee1905_1::CmduMessageRx &cmdu_rx, const sMacAddr &src_mac);

    /* 1905.1 message responses: */

    /**
    * @brief Sends channel scan report back to the requester.
    * 
    * @param[in] request request object
    *
    * @return True on success, otherwise false.
    */
    bool send_channel_scan_report(const std::shared_ptr<sScanRequest> request);

    /**
     * @brief Send 1905 CHANNEL_SCAN_REPORT message back to the sender.
     * 
     * @param[in] request request object
     *
     * @return True on success, otherwise false.
     */
    bool send_channel_scan_report_to_controller(const std::shared_ptr<sScanRequest> request);
};

} // namespace beerocks

#endif // _CHANNEL_SCAN_TASK_H_
