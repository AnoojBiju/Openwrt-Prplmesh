/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bwl/base_wlan_hal.h>

#include <bcl/beerocks_string_utils.h>

#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <easylogging++.h>

namespace bwl {

base_wlan_hal::base_wlan_hal(HALType type, std::string iface_name, IfaceType iface_type,
                             hal_event_cb_t callback, hal_conf_t hal_conf)
    : m_hal_conf(hal_conf), m_type(type), m_iface_name(iface_name), m_iface_type(iface_type),
      m_int_event_cb(callback)
{
    // Initialize radio info structure
    m_radio_info.iface_name = iface_name;
    m_radio_info.iface_type = iface_type;

    // Create an eventfd for internal events
    if ((m_fd_int_events = eventfd(0, EFD_SEMAPHORE)) < 0) {
        LOG(FATAL) << "Failed creating eventfd: " << strerror(errno);
    }
}

base_wlan_hal::~base_wlan_hal()
{
    // Close the eventfd used for internal events
    if (m_fd_int_events != -1) {
        close(m_fd_int_events);
        m_fd_int_events = -1;
    }
}

bool base_wlan_hal::event_queue_push(int event, std::shared_ptr<void> data)
{
    // Create a new shared pointer of the event and the payload
    auto event_ptr = std::make_shared<hal_event_t>(hal_event_t(event, data));

    // Push the event into the queue
    // push with block (default true) can't return false
    m_queue_events.push(event_ptr);

    // Increment the eventfd counter by 1
    uint64_t counter = 1;
    if (write(m_fd_int_events, &counter, sizeof(counter)) < 0) {
        LOG(ERROR) << "Failed updating eventfd counter: " << strerror(errno);
        return false;
    }

    return true;
}

std::shared_ptr<sMGMT_FRAME_NOTIFICATION>
base_wlan_hal::create_mgmt_frame_notification(const char *mgmt_frame_hex)
{
    auto mgmt_frame = std::make_shared<sMGMT_FRAME_NOTIFICATION>();
    LOG_IF(!mgmt_frame, FATAL) << "Failed allocating management frame notification structure!";

    // Store the received data as a hex string
    std::string hex_data(mgmt_frame_hex);

    // Validate the length of the received event
    // The length is divided by 2, since it's received in hex string representation
    if (hex_data.length() / 2 < sizeof(s80211MgmtFrame::sHeader)) {
        LOG(WARNING) << "Received event data too small: " << hex_data.length() / 2;
        return nullptr; // Just a warning, do not fail
    }

    // Convert the frame data from hex string to a vector (of mgmt_frame->data type)
    auto raw_frame = beerocks::string_utils::hex_to_bytes<decltype(mgmt_frame->data)>(hex_data);

    // Check the type of the received event
    s80211MgmtFrame *mgmt_frame_header = reinterpret_cast<s80211MgmtFrame *>(raw_frame.data());

    // Ignore non-management frames
    if (mgmt_frame_header->header.frame_control.bits.type != 0) {
        LOG(DEBUG) << "Received non-Management frame. Ignoring.";
        return nullptr;
    }

    // Store the STA MAC address
    mgmt_frame->mac = mgmt_frame_header->header.sa;

    // Check the frame subtype and update the frame type accordingly
    auto mgmt_frame_subtype =
        s80211MgmtFrame::eType(mgmt_frame_header->header.frame_control.bits.subtype);

    switch (mgmt_frame_subtype) {
    case s80211MgmtFrame::eType::ASSOC_REQ: {
        mgmt_frame->type = eManagementFrameType::ASSOCIATION_REQUEST;
    } break;
    case s80211MgmtFrame::eType::REASSOC_REQ: {
        mgmt_frame->type = eManagementFrameType::REASSOCIATION_REQUEST;
    } break;
    case s80211MgmtFrame::eType::ACTION: {
        // Re-validate the size of the data to make sure it also contains the
        // action frame header
        if (raw_frame.size() <
            sizeof(s80211MgmtFrame::sHeader) + sizeof(s80211MgmtFrame::uBody::sAction)) {
            LOG(WARNING) << "Action frame too small: " << mgmt_frame->data.size();
            return nullptr;
        }

        using eActionCategory = s80211MgmtFrame::uBody::sAction::eCategory;
        using eActionCode     = s80211MgmtFrame::uBody::sAction::eCode;

        const auto &action_category = eActionCategory(mgmt_frame_header->body.action.category);
        const auto &action_code     = eActionCode(mgmt_frame_header->body.action.code);

        // Check category and code for supported frames
        if (action_category == eActionCategory::WNM &&
            action_code == eActionCode::WNM_NOTIFICATION_REQ) {
            mgmt_frame->type = eManagementFrameType::WNM_REQUEST;
        } else if (action_category == eActionCategory::WNM &&
                   action_code == eActionCode::WNM_BSS_TRANS_MGMT_QUERY) {
            mgmt_frame->type = eManagementFrameType::BTM_QUERY;
        } else if ((action_category == eActionCategory::PUBLIC ||
                    action_category == eActionCategory::PROTECTED_DUAL) &&
                   action_code == eActionCode::ANQP_REQ) {
            mgmt_frame->type = eManagementFrameType::ANQP_REQUEST;
        } else {
            LOG(DEBUG) << "Received unhandled management action frame (category: "
                       << int(action_category) << ", code: " << int(action_code) << "). Ignoring.";
            return nullptr;
        }

    } break;
    default: {
        LOG(DEBUG) << "Received unhandled management frame (" << int(mgmt_frame_subtype)
                   << "). Ignoring.";
        return nullptr;
    }
    }

    // Copy the frame body (omitting control and header)
    mgmt_frame->data.insert(mgmt_frame->data.begin(),
                            raw_frame.begin() + sizeof(s80211MgmtFrame::sHeader), raw_frame.end());

    return mgmt_frame;
}

bool base_wlan_hal::process_int_events()
{
    // Read the counter value of the eventfd
    uint64_t counter = 0;
    if (read(m_fd_int_events, &counter, sizeof(counter)) < 0) {
        LOG(ERROR) << "Failed reading eventfd counter: " << strerror(errno);
        return false;
    }

    // Pop an event from the queue
    auto event = m_queue_events.pop(false);

    if (!event || !counter) {
        LOG(WARNING) << "process_int_events() called by the event queue pointer is " << event
                     << " and/or eventfd counter = " << counter;

        return false;
    }

    // Call the callback for handling the event
    if (!m_int_event_cb) {
        LOG(ERROR) << "Event callback not registered!";
        return false;
    }

    return m_int_event_cb(event);
}

void base_wlan_hal::calc_curr_traffic(uint64_t val, uint64_t &total, uint32_t &curr)
{
    if (val >= total) {
        curr = val - total;
    } else {
        curr = val;
    }
    total = val;
}

} // namespace bwl
