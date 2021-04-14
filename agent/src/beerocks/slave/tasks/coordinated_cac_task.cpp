/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "coordinated_cac_task.h"
#include "../backhaul_manager/backhaul_manager.h"
#include "task_pool_interface.h"
#include <bcl/beerocks_defines.h>
#include <bcl/beerocks_utils.h>

namespace beerocks {
namespace coordinated_cac {

/////////////
// cac fsm //
/////////////

std::ostream &operator<<(std::ostream &out, const fsm_state &value)
{
    switch (value) {
    case fsm_state::IDLE:
        out << "IDLE";
        break;
    case fsm_state::WAIT_FOR_CHANNEL_LIST_READY:
        out << "WAIT_FOR_CHANNEL_LIST_READY";
        break;
    case fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I:
        out << "WAIT_FOR_SWITCH_CHANNEL_REPORT_I";
        break;
    case fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II:
        out << "WAIT_FOR_SWITCH_CHANNEL_REPORT_II";
        break;
    case fsm_state::WAIT_FOR_CAC_TERMINATION:
        out << "WAIT_FOR_CAC_TERMINATION";
        break;
    case fsm_state::ERROR:
        out << "ERROR";
        break;
    }
    return out;
}

std::ostream &operator<<(std::ostream &out, const fsm_event &value)
{
    switch (value) {
    case fsm_event::CAC_REQUEST:
        out << "CAC_REQUEST";
        break;
    case fsm_event::CAC_TERMINATION_REQUEST:
        out << "CAC_TERMINATION_REQUEST";
        break;
    case fsm_event::CAC_TERMINATION_RESPONSE:
        out << "CAC_TERMINATION_RESPONSE";
        break;
    case fsm_event::CHANNEL_LIST_READY:
        out << "CHANNEL_LIST_READY";
        break;
    case fsm_event::SWITCH_CHANNEL_REPORT:
        out << "SWITCH_CHANNEL_REPORT";
        break;
    case fsm_event::SWITCH_CHANNEL_DURATION_TIME:
        out << "SWITCH_CHANNEL_DURATION_TIME";
        break;
    case fsm_event::CAC_STARTED_NOTIFICATION:
        out << "CAC_STARTED_NOTIFICATION";
        break;
    case fsm_event::CAC_COMPLETED_NOTIFICATION:
        out << "CAC_COMPLETED_NOTIFICATION";
        break;
    case fsm_event::PERIODIC:
        out << "PERIODIC";
        break;
    }
    return out;
}

CacFsm::CacFsm(TaskPoolInterface &task_pool, BackhaulManager &backhaul_manager,
               ieee1905_1::CmduMessageTx &cmdu_tx)
    : beerocks_fsm(fsm_state::IDLE), m_task_pool(task_pool), m_backhaul_manager(backhaul_manager),
      m_cmdu_tx(cmdu_tx)
{
    config_fsm();
}

void CacFsm::reset()
{
    m_cac_request.reset();
    m_first_switch_channel_request.reset();
    m_second_switch_channel_request.reset();

    m_original_channel                  = 0;
    m_original_bandwidth                = eWiFiBandwidth::BANDWIDTH_UNKNOWN;
    m_original_center_frequency         = 0;
    m_original_secondary_channel_offset = 0;

    m_max_wait_for_switch_channel = DEFAULT_MAX_WAIT_FOR_SWITCH_CHANNEL;
    m_max_wait_for_channel_list   = DEFAULT_MAX_WAIT_FOR_CHANNEL_LIST;

    m_cac_termination.reset();
}

void CacFsm::config_fsm()
{
    config()

        /////////////
        //// IDLE ///
        /////////////
        .state(fsm_state::IDLE)

        .entry([&](const void *args) -> bool {
            reset();
            return true;
        })

        .on(fsm_event::CAC_REQUEST,
            {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I, fsm_state::WAIT_FOR_CHANNEL_LIST_READY,
             fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                if (m_cac_request) {
                    LOG(ERROR) << "another cac request in progress, ignoring.";
                    // TODO: send preference report with an error
                    // https://jira.prplfoundation.org/browse/PPM-1090
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                m_cac_request =
                    *(reinterpret_cast<std::shared_ptr<wfa_map::tlvProfile2CacRequest> *>(
                        const_cast<void *>(args)));

                if (!m_cac_request) {
                    LOG(ERROR) << "Received CAC request without data";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // escape on currently non supported
                if (m_cac_request->number_of_cac_radios() != 1) {
                    LOG(ERROR) << "Only one radio is supported for cac request";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                std::tuple<bool, wfa_map::tlvProfile2CacRequest::sCacRequestRadio &> request_radio =
                    m_cac_request->cac_radios(0);
                if (!std::get<0>(request_radio)) {
                    LOG(ERROR) << "Coudn't find the one (and only) expected sCacRequestRadio in "
                                  "the request";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                m_cac_request_radio = std::get<1>(request_radio);
                if (m_cac_request_radio.cac_method_bit_field.cac_method !=
                    0x000) { // 000 is continues-cac
                    LOG(ERROR) << "Only continues-cac is supported";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // prepare for switch channel
                std::shared_ptr<BackhaulManager::sRadioInfo> backhaul_radio =
                    m_backhaul_manager.get_radio(m_cac_request_radio.radio_uid);
                if (!backhaul_radio) {
                    LOG(ERROR) << "Can't find " << m_cac_request_radio.radio_uid
                               << " radio in the backhaul manager";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                m_ifname      = backhaul_radio->hostap_iface;
                auto db       = AgentDB::get();
                auto db_radio = db->radio(m_ifname);
                if (!db_radio) {
                    LOG(ERROR) << "Failed to find database record for interface: " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                if (db_radio->channels_list.empty()) {
                    // since the channel list is empty
                    // we send a request for populating it
                    auto request = message_com::create_vs_message<
                        beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_REQUEST>(m_cmdu_tx);
                    if (!request) {
                        LOG(ERROR) << "Failed to build channel-list-request message.";
                        transition.change_destination(fsm_state::ERROR);
                        return true;
                    }

                    auto fronthaul_sd = m_backhaul_manager.front_iface_name_to_socket(m_ifname);
                    if (fronthaul_sd == beerocks::net::FileDescriptor::invalid_descriptor) {
                        LOG(DEBUG) << "Failed to find fronthaul socket for interface: " << m_ifname;
                        transition.change_destination(fsm_state::ERROR);
                        return true;
                    }

                    m_backhaul_manager.send_cmdu(fronthaul_sd, m_cmdu_tx);

                    // start the time count
                    m_channel_list_start_time_point = std::chrono::steady_clock::now();

                    transition.change_destination(fsm_state::WAIT_FOR_CHANNEL_LIST_READY);
                    return true;
                }

                auto channel_info = db_radio->channels_list.find(m_cac_request_radio.channel);
                if (channel_info == db_radio->channels_list.end()) {
                    LOG(ERROR) << "the channel " << m_cac_request_radio.channel
                               << " is not supported for " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // find the bandwidth based on the operating class in the request
                beerocks::eWiFiBandwidth bandwidth =
                    son::wireless_utils::operating_class_to_bandwidth(
                        m_cac_request_radio.operating_class);

                // save current channel - to know where to switch back if needed
                m_original_channel          = db_radio->channel;
                m_original_bandwidth        = db_radio->bandwidth;
                m_original_center_frequency = db_radio->vht_center_frequency;
                if (m_original_bandwidth == eWiFiBandwidth::BANDWIDTH_20) {
                    m_original_secondary_channel_offset = 0;
                } else {
                    m_original_secondary_channel_offset =
                        db_radio->channel_ext_above_primary ? 1 : -1;
                }

                // save the time point we started the switch channel
                m_switch_channel_start_time_point = std::chrono::steady_clock::now();

                // sending switch channel request (I)
                m_first_switch_channel_request =
                    send_switch_channel_request(m_cac_request_radio.channel, bandwidth);
                if (!m_first_switch_channel_request) {
                    LOG(ERROR) << "Failed to send switch channel request.";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // store the request in the database
                db_radio->last_swich_channel_request = m_first_switch_channel_request;

                // moving to next state: WAIT_FOR_SWITCH_CHANNEL_REPORT_I
                return true;
            })

        // it is ok to receive this event, we just stay in the same state
        .on(fsm_event::PERIODIC, fsm_state::IDLE)

        // it is ok to receive this event, we just stay in the same state
        .on(fsm_event::CHANNEL_LIST_READY, fsm_state::IDLE)

        // nothing to terminate
        .on(fsm_event::CAC_TERMINATION_REQUEST, fsm_state::IDLE)

        /////////////////////////////////////////
        ////// WAIT_FOR_CHANNEL_LIST_READY //////
        /////////////////////////////////////////
        .state(fsm_state::WAIT_FOR_CHANNEL_LIST_READY)

        .on(fsm_event::CHANNEL_LIST_READY,
            {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                if (!m_cac_request) {
                    LOG(ERROR) << "Received channel switching request without data.";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                std::shared_ptr<BackhaulManager::sRadioInfo> backhaul_radio =
                    m_backhaul_manager.get_radio(m_cac_request_radio.radio_uid);
                if (!backhaul_radio) {
                    LOG(ERROR) << "Failed to find " << m_cac_request_radio.radio_uid
                               << " radio in the backhaul";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                m_ifname      = backhaul_radio->hostap_iface;
                auto db       = AgentDB::get();
                auto db_radio = db->radio(m_ifname);
                if (!db_radio) {
                    LOG(ERROR) << "Failed to find database record for interface: " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                auto channel_info = db_radio->channels_list.find(m_cac_request_radio.channel);
                if (channel_info == db_radio->channels_list.end()) {
                    LOG(ERROR) << "the channel " << m_cac_request_radio.channel
                               << " is not supported for " << m_ifname;
                    LOG(DEBUG) << "you may try - ";
                    for (const auto &it : db_radio->channels_list) {
                        LOG(DEBUG) << "channel: " << +it.first;
                    }
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // find the bandwidth based on the operating class in the request
                beerocks::eWiFiBandwidth bandwidth =
                    son::wireless_utils::operating_class_to_bandwidth(
                        m_cac_request_radio.operating_class);

                // save current channel - to know where to switch back if needed
                m_original_channel                  = db_radio->channel;
                m_original_bandwidth                = db_radio->bandwidth;
                m_original_center_frequency         = db_radio->vht_center_frequency;
                m_original_secondary_channel_offset = db_radio->channel_ext_above_primary ? 1 : -1;

                // save the time point we started the switch channel
                m_switch_channel_start_time_point = std::chrono::steady_clock::now();

                // sending switch channel request (I)
                m_first_switch_channel_request =
                    send_switch_channel_request(m_cac_request_radio.channel, bandwidth);
                if (!m_first_switch_channel_request) {
                    LOG(ERROR) << "Failed to send first channel switching request.";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // store the request in the database
                db_radio->last_swich_channel_request = m_first_switch_channel_request;

                // moving to next state: WAIT_FOR_SWITCH_CHANNEL_REPORT_I
                return true;
            })

        .on(fsm_event::PERIODIC, {fsm_state::WAIT_FOR_CHANNEL_LIST_READY, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                if (is_timeout_waiting_for_channel_list()) {
                    LOG(ERROR) << "Timeout occured waiting for channel list.";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                // returning false means "stay in the same state"
                return false;
            })

        // while waiting for channel list we were requested to teminate
        // the cac. we simply switch to IDLE.
        .on(fsm_event::CAC_TERMINATION_REQUEST, fsm_state::IDLE)

        /////////////////////////////////////////
        //// WAIT_FOR_SWITCH_CHANNEL_REPORT_I ///
        /////////////////////////////////////////
        .state(fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I)

        .on(fsm_event::SWITCH_CHANNEL_DURATION_TIME, {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I},
            [&](TTransition &transition, const void *args) -> bool {
                // update the wait time
                m_max_wait_for_switch_channel =
                    (*(reinterpret_cast<std::shared_ptr<sSwitchChannelDurationTime> *>(
                         const_cast<void *>(args))))
                        ->duration_sec;
                return true;
            })

        .on(fsm_event::SWITCH_CHANNEL_REPORT,
            {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II, fsm_state::IDLE, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                auto switch_channel_report =
                    *(reinterpret_cast<std::shared_ptr<sSwitchChannelReport> *>(
                        const_cast<void *>(args)));

                // validate that the report belongs to the active
                // cac. it might belong to another switch channel
                // or, it might belong to the termination of this cac:
                // the original switch channel, or the report that the
                // old

                db_store_cac_status(switch_channel_report);
                send_preference_report(transition, args);

                // depends on the completion action:
                // remain on the same channel --> IDLE
                // go back to the previous -->
                // 1. send switch channel request
                // 2. --> WAIT_FOR_SWITCH_CHANNEL_REPORT_II

                // stay on channel
                if (m_cac_request_radio.cac_method_bit_field.cac_completion_action == 0x00) {
                    // we were requested to stay on the same channel
                    // therefore we are done
                    LOG(DEBUG)
                        << "Controller requested to stay on the same channel after performing CAC";
                    transition.change_destination(fsm_state::IDLE);
                    return true;
                } else if (m_cac_request_radio.cac_method_bit_field.cac_completion_action == 0x01) {

                    LOG(DEBUG) << "Controller requested to return to original channel after "
                                  "performing CAC";
                    // save the time point we started the switch channel
                    m_switch_channel_start_time_point = std::chrono::steady_clock::now();

                    // reset the wait time
                    m_max_wait_for_switch_channel = DEFAULT_MAX_WAIT_FOR_SWITCH_CHANNEL;

                    // sending switch channel request (II)
                    m_second_switch_channel_request =
                        send_switch_channel_request(m_original_channel, m_original_bandwidth);
                    if (!m_second_switch_channel_request) {
                        LOG(ERROR) << "Failed to send second switch channel request";
                        transition.change_destination(fsm_state::ERROR);
                        return true;
                    }

                    // switch to the first state in the list: WAIT_FOR_SWITCH_CHANNEL_REPORT_II
                    return true;

                } else {
                    LOG(ERROR) << "Unknown completion action";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                return true;
            })

        .on(fsm_event::CAC_STARTED_NOTIFICATION, fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I,
            [&](TTransition &transition, const void *args) -> bool {
                auto cac_started_notification =
                    *(reinterpret_cast<std::shared_ptr<sCacStartedNotification> *>(
                        const_cast<void *>(args)));
                db_store_cac_status(cac_started_notification);
                return true;
            })

        .on(fsm_event::CAC_COMPLETED_NOTIFICATION, fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I,
            [&](TTransition &transition, const void *args) -> bool {
                auto cac_completed_notification =
                    *(reinterpret_cast<std::shared_ptr<sCacCompletedNotification> *>(
                        const_cast<void *>(args)));
                db_store_cac_status(cac_completed_notification);
                return true;
            })

        .on(fsm_event::PERIODIC, {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                if (is_timeout_waiting_for_switch_channel_report()) {
                    LOG(ERROR) << "Timeout occurred waiting for switch channel report (I)";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                // returning false means "stay in the same state"
                return false;
            })

        .on(fsm_event::CAC_TERMINATION_REQUEST, fsm_state::WAIT_FOR_CAC_TERMINATION,
            [&](TTransition &transition, const void *args) -> bool {
                m_cac_termination =
                    *(reinterpret_cast<std::shared_ptr<wfa_map::tlvProfile2CacTermination> *>(
                        const_cast<void *>(args)));
                if (!m_cac_termination) {
                    LOG(ERROR) << "null cac termination. ignoring";
                    return false;
                }

                // validate that the termination refers to the running cac request
                auto termination_cac_radio = m_cac_termination->cac_radios(0);
                if (!std::get<0>(termination_cac_radio)) {
                    LOG(ERROR) << "empty cac termination. ignoring";
                    return false;
                }

                auto request_cac_radio = m_cac_request->cac_radios(0);
                if (!std::get<0>(request_cac_radio)) {
                    LOG(ERROR) << "empty cac request. ignoring";
                    return false;
                }

                bool termination_on_active_request =
                    std::get<1>(termination_cac_radio).operating_class ==
                        std::get<1>(request_cac_radio).operating_class &&
                    std::get<1>(termination_cac_radio).channel ==
                        std::get<1>(request_cac_radio).channel;

                if (!termination_on_active_request) {
                    LOG(WARNING) << "requested cac termination not on the active request. ignoring";
                    return false;
                }

                // 2. send stop-cac request to the driver

                // save the time point we asked for stopping the cac
                m_terminate_cac_start_time_point = std::chrono::steady_clock::now();

                // create cancel cac request
                auto cancel_cac_request = message_com::create_vs_message<
                    beerocks_message::cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST>(m_cmdu_tx);
                if (!cancel_cac_request) {
                    LOG(ERROR) << "Failed to build cancel cac message";
                    return false;
                }

                cancel_cac_request->cs_params().channel = m_original_channel;
                cancel_cac_request->cs_params().bandwidth =
                    beerocks::utils::convert_bandwidth_to_int(m_original_bandwidth);
                cancel_cac_request->cs_params().vht_center_frequency = m_original_center_frequency;
                cancel_cac_request->cs_params().channel_ext_above_primary =
                    m_original_secondary_channel_offset;

                // find fd using the if-name
                int ifname_fd = m_backhaul_manager.front_iface_name_to_socket(m_ifname);

                if (ifname_fd == beerocks::net::FileDescriptor::invalid_descriptor) {
                    LOG(ERROR) << "can't find a socket for front interface name: " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

                // send the cmdu using the fd
                bool cmdu_sent = m_backhaul_manager.send_cmdu(ifname_fd, m_cmdu_tx);
                if (!cmdu_sent) {
                    LOG(ERROR) << "Failed to send cancel cac request";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // moving to next state: WAIT_FOR_SWITCH_CHANNEL_REPORT_II
                return true;
            })

        .on(fsm_event::CHANNEL_LIST_READY, fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_I)

        //////////////////////////////////////////
        //// WAIT_FOR_SWITCH_CHANNEL_REPORT_II ///
        //////////////////////////////////////////
        .state(fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II)

        .on(fsm_event::SWITCH_CHANNEL_DURATION_TIME, {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II},
            [&](TTransition &transition, const void *args) -> bool {
                // update the wait time
                m_max_wait_for_switch_channel =
                    (*(reinterpret_cast<std::shared_ptr<sSwitchChannelDurationTime> *>(
                         const_cast<void *>(args))))
                        ->duration_sec;
                return true;
            })

        .on(fsm_event::SWITCH_CHANNEL_REPORT, {fsm_state::IDLE},
            [&](TTransition &transition, const void *args) -> bool {
                // we are done - all is good
                // note: maybe we should take a look at the values
                // of the report to make sure all is indeed good.
                // currently we are satisfied just from getting in here
                return true;
            })
        .on(fsm_event::PERIODIC, {fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                // check timeout
                if (is_timeout_waiting_for_switch_channel_report()) {
                    LOG(ERROR) << "timeout occured waiting for switch channel report (II)";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                // returning false means "stay in the same state"
                return false;
            })

        .on(fsm_event::CHANNEL_LIST_READY, fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II)
        .on(fsm_event::CAC_TERMINATION_REQUEST, fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II)

        /////////////////////////////////
        //// WAIT_FOR_CAC_TERMINATION ///
        /////////////////////////////////
        .state(fsm_state::WAIT_FOR_CAC_TERMINATION)

        .on(fsm_event::CAC_TERMINATION_RESPONSE, {fsm_state::IDLE, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                auto success =
                    (*(reinterpret_cast<std::shared_ptr<bool> *>(const_cast<void *>(args))));
                if (!success) {
                    LOG(ERROR) << "null cac-termination success pointer";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }

                // just reporting
                LOG(DEBUG) << "cancel cac reported as ended with: " << std::hex << *success;
                return true;
            })

        .on(fsm_event::PERIODIC, fsm_state::WAIT_FOR_SWITCH_CHANNEL_REPORT_II,
            [&](TTransition &transition, const void *args) -> bool {
                // check timeout
                if (is_timeout_waiting_for_cac_termination()) {
                    LOG(ERROR) << "timeout occured waiting for cac termination";
                    transition.change_destination(fsm_state::ERROR);
                    return true;
                }
                // returning false means "stay in the same state"
                return false;
            })

        //////////////
        //// ERROR ///
        //////////////
        .state(fsm_state::ERROR)

        // for now - just going back to idle
        .on(fsm_event::PERIODIC, fsm_state::IDLE)
        .on(fsm_event::CHANNEL_LIST_READY, fsm_state::ERROR)
        .on(fsm_event::CAC_TERMINATION_REQUEST, fsm_state::ERROR);

    start();
}

bool CacFsm::send_preference_report(TTransition &transition, const void *args)
{
    LOG(DEBUG) << "time to send preference report";

    if (m_cac_termination) {
        LOG(DEBUG) << "but cac-termination was requested, so skipping";
        return false;
    }

    // we are triggering preference report by sending
    // channel list request. The end of this request
    // is a preference report being sent to the controller.
    // collecting the cac values is done from the database
    auto request =
        message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_REQUEST>(
            m_cmdu_tx);
    if (!request) {
        LOG(ERROR) << "Failed to build message";
    }

    auto ifname_sd = m_backhaul_manager.front_iface_name_to_socket(m_ifname);
    if (ifname_sd == beerocks::net::FileDescriptor::invalid_descriptor) {
        LOG(DEBUG) << "socket to " << m_ifname << " wasn't found";
        return false;
    }

    m_backhaul_manager.send_cmdu(ifname_sd, m_cmdu_tx);

    return true;
}

std::shared_ptr<sSwitchChannelRequest>
CacFsm::send_switch_channel_request(uint8_t channel, beerocks::eWiFiBandwidth bandwidth)
{
    // sending switch channel request
    auto switch_channel_request = std::make_shared<sSwitchChannelRequest>();
    if (!switch_channel_request) {
        LOG(ERROR) << "unable to create switch channel request data"
                   << " for "
                   << "channel: " << channel << " bandwidth: " << bandwidth;
        return nullptr;
    }

    switch_channel_request->ifname    = m_ifname;
    switch_channel_request->channel   = channel;
    switch_channel_request->bandwidth = bandwidth;

    LOG(DEBUG) << *switch_channel_request;

    m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_REQUEST, switch_channel_request);

    return switch_channel_request;
}

bool CacFsm::is_timeout_waiting_for_switch_channel_report()
{
    // check switch channel timeout
    return (std::chrono::steady_clock::now() - m_switch_channel_start_time_point) >
           m_max_wait_for_switch_channel;
}

bool CacFsm::is_timeout_waiting_for_channel_list()
{
    // check channel list timeout
    return (std::chrono::steady_clock::now() - m_channel_list_start_time_point) >
           m_max_wait_for_channel_list;
}

bool CacFsm::is_timeout_waiting_for_cac_termination()
{
    // check cac termination timeout
    return (std::chrono::steady_clock::now() - m_terminate_cac_start_time_point) >
           m_max_wait_for_cac_termination;
}

void CacFsm::db_store_cac_status(std::shared_ptr<sSwitchChannelReport> switch_channel_report)
{
    if (!switch_channel_report) {
        LOG(ERROR) << "can't store null switch-channel-report";
        return;
    }

    if (switch_channel_report->cac_happened) {
        db_store_cac_status(switch_channel_report->cac_completed_notification);
    }
}

void CacFsm::db_store_cac_status(std::shared_ptr<sCacStartedNotification> cac_started)
{
    if (!cac_started) {
        LOG(WARNING) << "can't store empty cac-completed";
        return;
    }

    auto db    = AgentDB::get();
    auto radio = db->radio(m_ifname);
    if (!radio) {
        LOG(ERROR) << "can't find radio in the databse for " << m_ifname;
        return;
    }

    const auto channel_record = radio->channels_list.find(cac_started->cac_started_params.channel);
    if (channel_record == radio->channels_list.end()) {
        LOG(ERROR) << "received cac started on non existed channel: "
                   << "ifname: " << m_ifname
                   << " channel: " << cac_started->cac_started_params.channel;
        return;
    }
}

void CacFsm::db_store_cac_status(std::shared_ptr<sCacCompletedNotification> cac_completed)
{
    if (!cac_completed) {
        LOG(WARNING) << "can't store empty cac-completed";
        return;
    }

    auto db    = AgentDB::get();
    auto radio = db->radio(m_ifname);
    if (!radio) {
        LOG(ERROR) << "can't find radio in the databse for " << m_ifname;
        return;
    }

    const auto channel_record =
        radio->channels_list.find(cac_completed->cac_completed_params.channel);
    if (channel_record == radio->channels_list.end()) {
        LOG(ERROR) << "received cac completed on non existed channel: "
                   << "ifname: " << m_ifname
                   << " channel: " << cac_completed->cac_completed_params.channel;
        return;
    }

    if (!cac_completed->cac_completed_params.success) {
        LOG(WARNING) << "cac comleted with fauilre";
        channel_record->second.dfs_state = beerocks_message::eDfsState::USABLE;
        return;
    }
    channel_record->second.dfs_state = beerocks_message::eDfsState::AVAILABLE;
}

///////////////
// cac task ///
///////////////
CoordinatedCacTask::CoordinatedCacTask(TaskPoolInterface &task_pool,
                                       BackhaulManager &backhaul_manager,
                                       ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::CAC_TASK), m_backhaul_manager(backhaul_manager), m_cmdu_tx(cmdu_tx),
      m_fsm(task_pool, backhaul_manager, cmdu_tx)
{
}

std::vector<eTaskEvent> CoordinatedCacTask::get_task_event_list() const
{
    return {eTaskEvent::SWITCH_CHANNEL_DURATION_TIME, eTaskEvent::CHANNEL_LIST_READY,
            eTaskEvent::SWITCH_CHANNEL_REPORT, eTaskEvent::CAC_STARTED_NOTIFICATION,
            eTaskEvent::CAC_COMPLETED_NOTIFICATION};
}

void CoordinatedCacTask::work()
{
    // work is called periodically
    // this is the chance to handle periodic "event"
    m_fsm.fire(fsm_event::PERIODIC);
}

void CoordinatedCacTask::handle_event(uint8_t event_enum_value, const void *event_obj) {}

void CoordinatedCacTask::handle_event(eTaskEvent event, std::shared_ptr<void> event_obj)
{
    LOG(DEBUG) << "got event to handle: " << event;

    switch (event) {

    case eTaskEvent::SWITCH_CHANNEL_DURATION_TIME: {
        auto switch_channel_duration_time =
            std::static_pointer_cast<const sSwitchChannelDurationTime>(event_obj);
        if (!switch_channel_duration_time) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        m_fsm.fire(fsm_event::SWITCH_CHANNEL_DURATION_TIME,
                   reinterpret_cast<const void *>(&switch_channel_duration_time));
    } break;

    case eTaskEvent::CHANNEL_LIST_READY: {
        m_fsm.fire(fsm_event::CHANNEL_LIST_READY);
    } break;

    case eTaskEvent::SWITCH_CHANNEL_REPORT: {
        auto switch_channel_report =
            std::static_pointer_cast<const sSwitchChannelReport>(event_obj);
        if (!switch_channel_report) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        m_fsm.fire(fsm_event::SWITCH_CHANNEL_REPORT,
                   reinterpret_cast<const void *>(&switch_channel_report));
    } break;

    case eTaskEvent::CAC_STARTED_NOTIFICATION: {
        auto cac_started_notification =
            std::static_pointer_cast<const sCacStartedNotification>(event_obj);
        if (!cac_started_notification) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        m_fsm.fire(fsm_event::CAC_STARTED_NOTIFICATION,
                   reinterpret_cast<const void *>(&cac_started_notification));
    } break;

    case eTaskEvent::CAC_COMPLETED_NOTIFICATION: {
        auto cac_completed_notification =
            std::static_pointer_cast<const sCacCompletedNotification>(event_obj);
        if (!cac_completed_notification) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        m_fsm.fire(fsm_event::CAC_COMPLETED_NOTIFICATION,
                   reinterpret_cast<const void *>(&cac_completed_notification));
    } break;

    default: {
        LOG(WARNING) << "got unexpected event: " << static_cast<uint8_t>(event);
    } break;
    }
}

bool CoordinatedCacTask::handle_cmdu(ieee1905_1::CmduMessageRx &cmdu_rx, uint32_t iface_index,
                                     const sMacAddr &dst_mac, const sMacAddr &src_mac, int fd,
                                     std::shared_ptr<beerocks_header> beerocks_header)
{
    switch (cmdu_rx.getMessageType()) {
    case ieee1905_1::eMessageType::CAC_REQUEST_MESSAGE: {
        const auto mid       = cmdu_rx.getMessageId();
        auto cac_request_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2CacRequest>();
        if (!cac_request_tlv) {
            LOG(ERROR) << "CAC REQUEST CMDU mid=" << std::hex << mid
                       << " does not have profile 2 cac request TLV";
            return true;
        }
        // send ACK to the controller
        bool ack_sent = m_backhaul_manager.send_ack_to_controller(m_cmdu_tx, mid);
        LOG(DEBUG) << "CAC REQUEST: Ack was sent to controller? " << std::boolalpha << ack_sent;

        // let the fsm handle the request
        m_fsm.fire(fsm_event::CAC_REQUEST, reinterpret_cast<const void *>(&cac_request_tlv));
    } break;

    case ieee1905_1::eMessageType::CAC_TERMINATION_MESSAGE: {
        const auto mid           = cmdu_rx.getMessageId();
        auto cac_termination_tlv = cmdu_rx.getClass<wfa_map::tlvProfile2CacTermination>();
        if (!cac_termination_tlv) {
            LOG(ERROR) << "CAC TERMINATION CMDU mid=" << std::hex << mid
                       << " does not have profile 2 cac itermination TLV";
            return true;
        }
        // send ACK to the controller
        bool ack_sent = m_backhaul_manager.send_ack_to_controller(m_cmdu_tx, mid);
        LOG(DEBUG) << "CAC TERMINATION: Ack was sent to controller? " << std::boolalpha << ack_sent;

        // let the fsm handle the termination
        m_fsm.fire(fsm_event::CAC_TERMINATION_REQUEST,
                   reinterpret_cast<const void *>(&cac_termination_tlv));
    } break;

    case ieee1905_1::eMessageType::VENDOR_SPECIFIC_MESSAGE: {
        // Internally, the 'handle_vendor_specific' might not really handle
        // the CMDU, thus we need to return the real return value and not 'true'.
        return handle_vendor_specific(cmdu_rx, src_mac, fd, beerocks_header);
    }
    default: {
        return false;
    }
    }
    return true;
}

bool CoordinatedCacTask::handle_vendor_specific(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                const sMacAddr &src_mac, int sd,
                                                std::shared_ptr<beerocks_header> beerocks_header)
{
    if (!beerocks_header) {
        LOG(ERROR) << "beerocks_header is nullptr";
        return false;
    }

    // Since currently we handle only action_ops of action type "ACTION_BACKHAUL", use a single
    // switch-case on "ACTION_BACKHAUL" only.
    // Once the son_slave will be unified, need to replace the expected action to
    // "ACTION_AP_MANAGER". PPM-352.
    if (beerocks_header->action() != beerocks_message::ACTION_BACKHAUL) {
        return false;
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE: {
        auto cac_response =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE>();
        if (!cac_response) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE failed";
            return false;
        }
        auto cancel_cac_success = std::make_shared<bool>(cac_response->success());
        m_fsm.fire(fsm_event::CAC_TERMINATION_RESPONSE,
                   reinterpret_cast<const void *>(&cancel_cac_success));
        break;
    }
    default: {
        // Message was not handled, therefore return false.
        return false;
    }
    }
    return true;
}

} // namespace coordinated_cac
} // namespace beerocks
