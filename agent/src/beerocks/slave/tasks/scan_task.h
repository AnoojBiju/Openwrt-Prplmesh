/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _SCAN_TASK_H_
#define _SCAN_TASK_H_

#include "../agent_db.h"
#include <tlvf/CmduMessageTx.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanRequest.h>
#include <tlvf/wfa_map/tlvProfile2ChannelScanResult.h>
#include <tlvf/wfa_map/tlvTimestamp.h>
#include <vector>

namespace beerocks {
struct sScanRequestEvent {
};

enum eEvent : uint8_t { INDEPENDENT_SCAN_REQUEST };

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

// Adding a type alias for eScanStatus to use instead of the long descriptor.
using eScanStatus = wfa_map::tlvProfile2ChannelScanResult::eScanStatus;
struct sChannel {
    uint8_t channel_number;
    eScanStatus scan_status;
    explicit sChannel(const uint8_t _channel_number,
                      const eScanStatus _scan_status = eScanStatus::SUCCESS)
        : channel_number(_channel_number), scan_status(_scan_status)
    {
    }
};
struct sOperatingClass {
    uint8_t operating_class;
    beerocks::eWiFiBandwidth bw;
    std::vector<sChannel> channel_list;
    explicit sOperatingClass(const uint8_t _operating_class, const beerocks::eWiFiBandwidth _bw,
                             const std::vector<sChannel> &_channel_list)
        : operating_class(_operating_class), bw(_bw),
          channel_list(_channel_list.begin(), _channel_list.end())
    {
    }
};
struct sRadioScan {
    sMacAddr radio_mac;
    std::vector<sOperatingClass> operating_classes;
    eState current_state;
    std::chrono::system_clock::time_point timeout;
    int dwell_time;
    std::map<uint8_t, std::vector<beerocks_message::sChannelScanResults>> cached_results;
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
    sMacAddr src_mac;
    sControllerRequestInfo() : sRequestInfo(eScanRequestType::ControllerRequested) {}
};
struct sAgentRequestedInfo : sRequestInfo {
    sMacAddr src_mac;
    sAgentRequestedInfo() : sRequestInfo(eScanRequestType::AgentRequested) {}
};
struct sScanRequest {
    std::shared_ptr<sRequestInfo> request_info;
    std::chrono::system_clock::time_point scan_start_timestamp;
    std::unordered_map<std::string, std::shared_ptr<sRadioScan>> radio_scans;
    bool ready_to_send_report;
};

struct sStoredScanResults {
    sMacAddr ruid;
    uint8_t operating_class;
    uint8_t channel;
    eScanStatus status;
    std::chrono::system_clock::time_point timestamp;
    std::vector<beerocks_message::sChannelScanResults> results;
    explicit sStoredScanResults(sMacAddr _ruid, uint8_t _operating_class, uint8_t _channel,
                                eScanStatus _status,
                                std::chrono::system_clock::time_point _timestamp,
                                const std::vector<beerocks_message::sChannelScanResults> &_results)
        : ruid(_ruid), operating_class(_operating_class), channel(_channel), status(_status),
          timestamp(_timestamp), results(_results)
    {
    }
};
typedef std::vector<sStoredScanResults> StoredResultsVector;

class ScanTask {
public:
    /* Request handling helper functions */

    /**
     * @brief Check if given request has finished all its radio scans.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if all Radio Scans are finished, otherwise false.
     */
    virtual bool is_scan_request_finished(const std::shared_ptr<sScanRequest> request)
    {
        return false;
    };

    /**
     * @brief Abort the unfinished Radio Scans for the given request.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if the Abort Scan requests were sent successfully.
     */
    virtual bool abort_scan_request(const std::shared_ptr<sScanRequest> request) { return false; };

    /**
     * @brief Find the next pending Radio Scan and send a Trigger Scan request to the monitor.
     * 
     * @param request A shared pointer to the request info.
     *
     * @return True if a Trigger Scan request was sent, otherwise false.
     */
    virtual bool trigger_next_radio_scan(const std::shared_ptr<sScanRequest> request)
    {
        return false;
    };

    /* Radio Scan handling helper functions */

    /**
     * @brief Sets the status for the individual channels within a given scan.
     * 
     * @param radio_scan_info A shared pointer to the radio scan info.
     * @param status The new scan status that needs to be set.
     * 
     * @return True if the operation was successful, false otherwise.
     */
    virtual bool set_radio_scan_status(const std::shared_ptr<sRadioScan> radio_scan_info,
                                       const eScanStatus status)
    {
        return false;
    };

    /**
     * @brief Send a Trigger Scan Request CMDU to the monitor.
     * 
     * @param radio_iface  Iface name of the radio to which we want to send the CMDU.
     * @param radio_scan_info A shared pointer to the radio scan info.
     *
     * @return True if a Trigger Scan request was sent, otherwise false.
     */
    virtual bool trigger_radio_scan(const std::string &radio_iface,
                                    const std::shared_ptr<sRadioScan> radio_scan_info)
    {
        return false;
    };

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
    virtual bool store_radio_scan_result(const std::shared_ptr<sScanRequest> request,
                                         const sMacAddr &radio_mac,
                                         beerocks_message::sChannelScanResults results)
    {
        return false;
    };

    /* 1905.1 message responses: */

    /**
     * @brief Send 1905 CHANNEL_SCAN_REPORT message back to the sender.
     * 
     * @param[in] request request object
     *
     * @return True on success, otherwise false.
     */
    virtual bool send_channel_scan_report_to_controller(const std::shared_ptr<sScanRequest> request)
    {
        return false;
    };

    /**
     * @brief Get all stored results for the given request
     * 
     * @param[in] request request object
     * 
     * @return Stored Result vector containing all stored results for the given request
     */
    virtual std::shared_ptr<StoredResultsVector>
    get_scan_results_for_request(const std::shared_ptr<sScanRequest> request)
    {
        return nullptr;
    };
};

} // namespace beerocks

#endif // _CHANNEL_SCAN_TASK_H_
