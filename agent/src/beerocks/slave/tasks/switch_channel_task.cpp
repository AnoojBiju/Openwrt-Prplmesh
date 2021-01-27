/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "switch_channel_task.h"
#include "../backhaul_manager/backhaul_manager.h"

namespace beerocks {
namespace switch_channel {

////////////////////////
// switch channel fsm //
////////////////////////
enum class fsm_state { IDLE, WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION, WAIT_FOR_CAC_COMPLETED, ERROR };
enum class fsm_event { SWITCH_CHANNEL_REQUEST, CSA, CAC_STARTED, CAC_COMPLETED, PERIODIC };

std::ostream &operator<<(std::ostream &out, const fsm_state &value);
std::ostream &operator<<(std::ostream &out, const fsm_event &value);

class SwitchChannelFsm : public beerocks::beerocks_fsm<fsm_state, fsm_event> {
public:
    SwitchChannelFsm()                         = delete;
    SwitchChannelFsm(const SwitchChannelFsm &) = delete;
    SwitchChannelFsm(const std::string &ifname, TaskPoolInterface &task_pool,
                     BackhaulManager &backhaul_manager, ieee1905_1::CmduMessageTx &cmdu_tx);
    ~SwitchChannelFsm();

private:
    void config_fsm();
    void reset()
    {
        m_switch_channel_request.reset();
        m_switch_channel_notification.reset();
        m_cac_started_notification.reset();
        m_cac_completed_notification.reset();
        m_max_wait_for_switch_channel_notification_sec =
            DEFAULT_WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION;
    }
    bool report_switch_channel_in_progress(std::shared_ptr<sSwitchChannelRequest> request);
    bool handle_switch_channel_request_while_in_another_switch_channel(TTransition &transition,
                                                                       const void *args, bool &error_occured);
    bool disable_interface();
    bool enable_aps(int channel, eWiFiBandwidth bandwidth);

    static constexpr std::chrono::seconds DEFAULT_WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION =
        std::chrono::seconds(2);

public:
    // the interface this fsm handles
    const std::string m_ifname;

    // interface for sending inter-task communications messages
    TaskPoolInterface &m_task_pool;

    // temportary - interface for sending CMDUs
    // should be replaced with a decent interface instead of the whole backhaul
    BackhaulManager &m_backhaul_manager;

    // a container for sending cmdus
    ieee1905_1::CmduMessageTx &m_cmdu_tx;

    // the switch chanel request
    std::shared_ptr<const sSwitchChannelRequest> m_switch_channel_request;

    // switch chanel notificatoin (aka csa)
    std::shared_ptr<sSwitchChannelNotification> m_switch_channel_notification;

    // cac started data
    std::shared_ptr<sCacStartedNotification> m_cac_started_notification;

    // cac completed data
    std::shared_ptr<sCacCompletedNotification> m_cac_completed_notification;

    // max time to wait for a notification about switch channel
    std::chrono::seconds m_max_wait_for_switch_channel_notification_sec;

    // the point in time we started waiting for notificaion report
    std::chrono::time_point<std::chrono::steady_clock>
        m_wait_for_switch_channel_notification_time_point;

    // max time to wait for cac-completed
    std::chrono::seconds m_max_wait_for_cac_completed_sec = std::chrono::seconds(0);

    // the point in time we we started waiting for cac-comleted
    std::chrono::time_point<std::chrono::steady_clock> m_cac_started_time_point;

    // a factor used to calculate how long to wait for cac-completed
    static constexpr float CAC_TIMEOUT_FACTOR = 1.2;
};

/*
 * @brief Loads switch channel request to cmdu
 *
 * @param the cmdu tx to add the switch channel request to
 * @param the switch channel request to be added to the cmdu
 * @return bool On success true, otherwise false
 */
bool load_switch_channel_request_to_cmdu_tx(ieee1905_1::CmduMessageTx &cmdu_tx,
                                            const sSwitchChannelRequest &switch_channel_request);

SwitchChannelFsm::SwitchChannelFsm(const std::string &ifname, TaskPoolInterface &task_pool,
                                   BackhaulManager &backhaul_manager,
                                   ieee1905_1::CmduMessageTx &cmdu_tx)
    : beerocks_fsm(fsm_state::IDLE), m_ifname(ifname), m_task_pool(task_pool),
      m_backhaul_manager(backhaul_manager), m_cmdu_tx(cmdu_tx)
{
    config_fsm();
}

SwitchChannelFsm::~SwitchChannelFsm() {}

std::ostream &operator<<(std::ostream &out, const fsm_state &value)
{
    switch (value) {
    case fsm_state::IDLE:
        out << "IDLE";
        break;
    case fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION:
        out << "WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION";
        break;
    case fsm_state::WAIT_FOR_CAC_COMPLETED:
        out << "WAIT_FOR_CAC_COMPLETED";
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
    case fsm_event::SWITCH_CHANNEL_REQUEST:
        out << "SWITCH_CHANNEL_REQUEST";
        break;
    case fsm_event::CSA:
        out << "CSA";
        break;
    case fsm_event::CAC_STARTED:
        out << "CAC_STARTED";
        break;
    case fsm_event::CAC_COMPLETED:
        out << "CAC_COMPLETED";
        break;
    case fsm_event::PERIODIC:
        out << "PERIODIC";
        break;
    }

    return out;
}

void SwitchChannelFsm::config_fsm()
{
    config()
        //////////////////////
        //////// IDLE ////////
        //////////////////////
        .state(fsm_state::IDLE)

        .entry([&](const void *args) -> bool {
            reset();

            return true;
        })

        .on(fsm_event::SWITCH_CHANNEL_REQUEST,
            {fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                m_switch_channel_request =
                    *(reinterpret_cast<std::shared_ptr<sSwitchChannelRequest> *>(
                        const_cast<void *>(args)));

                if (!m_switch_channel_request) {
                    LOG(ERROR) << "request for switch channel with no data";
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

                // actual switch

                // fill the cmdu with the request
                bool loaded =
                    load_switch_channel_request_to_cmdu_tx(m_cmdu_tx, *m_switch_channel_request);
                if (!loaded) {
                    LOG(ERROR) << "failed to load switch channel request to cmdutx";
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

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
                    LOG(ERROR) << "Failed to send switch channel request";
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

                // set the wait start time
                m_wait_for_switch_channel_notification_time_point =
                    std::chrono::steady_clock::now();

                // wait for the switch report
                // (returning true means: switch to the first state that is in the list)
                return true;
            })

        .on(fsm_event::PERIODIC, fsm_state::IDLE)

        //////////////////////////////////////////////////////
        //////// WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION ////////
        //////////////////////////////////////////////////////
        .state(fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION)

        .on(fsm_event::CSA, {fsm_state::IDLE, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                // CSA means that the switch channel ended,
                // we are taking all information and sending the report
                m_switch_channel_notification =
                    *(reinterpret_cast<std::shared_ptr<sSwitchChannelNotification> *>(
                        const_cast<void *>(args)));

                // prepare the report
                auto switch_channel_report = std::make_shared<sSwitchChannelReport>(
                    false, m_switch_channel_request, m_switch_channel_notification,
                    m_cac_started_notification, m_cac_completed_notification);

                if (!switch_channel_report) {
                    LOG(ERROR) << "failed to create switch channel report for " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }
                // report
                m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_REPORT, switch_channel_report);

                // start the fsm
                reset();

                return true;
            })

        .on(fsm_event::CAC_STARTED, {fsm_state::WAIT_FOR_CAC_COMPLETED, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                // the indication for switch channel that is about to happen
                // starts here with a cac started notification
                m_cac_started_notification =
                    *(reinterpret_cast<std::shared_ptr<sCacStartedNotification> *>(
                        const_cast<void *>(args)));

                if (!m_cac_started_notification) {
                    LOG(ERROR) << "can't handle cac started without cac-started-notfication";
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

                // calculate how long to wait
                m_max_wait_for_cac_completed_sec = std::chrono::seconds(
                    uint16_t(m_cac_started_notification->cac_started_params.cac_duration_sec *
                             CAC_TIMEOUT_FACTOR));

                // report about the waiting time
                auto max_wait_time = std::make_shared<sSwitchChannelDurationTime>();
                if (!max_wait_time) {
                    LOG(ERROR) << "can't report about waiting for cac completed time";
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }
                max_wait_time->ifname       = m_ifname;
                max_wait_time->duration_sec = m_max_wait_for_cac_completed_sec;

                m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_DURATION_TIME, max_wait_time);

                // keep the start time of the wait
                m_cac_started_time_point = std::chrono::steady_clock::now();

                // now waiting
                // return true means: change to the first state that is in the list of possible
                // transitions (in this case: wait-for-cac-completed)
                return true;
            })

        .on(fsm_event::SWITCH_CHANNEL_REQUEST, fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION,
            [&](TTransition &transition, const void *args) -> bool {
                bool error_occured = false;
                handle_switch_channel_request_while_in_another_switch_channel(transition, args, error_occured);

                if (error_occured) {
                    transition.change_destination(fsm_state::ERROR); 
                    return true;
                }
                    
                // regardless of how we handled this request we wait
                // for switch channel notification.
                // i.e staying in the same state
                return false;
            })

        .on(fsm_event::PERIODIC, fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION)

        //////////////////////////////////////////////////////
        //////// WAIT_FOR_CAC_COMPLETED               ////////
        //////////////////////////////////////////////////////
        .state(fsm_state::WAIT_FOR_CAC_COMPLETED)

        .on(fsm_event::CAC_COMPLETED, {fsm_state::IDLE, fsm_state::ERROR},
            [&](TTransition &transition, const void *args) -> bool {
                // TODO: add validation that the completed-params matches the started-params

                m_cac_completed_notification =
                    *(reinterpret_cast<std::shared_ptr<sCacCompletedNotification> *>(
                        const_cast<void *>(args)));

                // send the report
                auto switch_channel_report = std::make_shared<sSwitchChannelReport>(
                    true, m_switch_channel_request, m_switch_channel_notification,
                    m_cac_started_notification, m_cac_completed_notification);

                if (!switch_channel_report) {
                    LOG(ERROR) << "failed to create switch channel report for " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

                // report
                m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_REPORT, switch_channel_report);

                // start the fsm
                return true;
            })

        .on(fsm_event::SWITCH_CHANNEL_REQUEST, fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION,
            [&](TTransition &transition, const void *args) -> bool {
                auto request = *(reinterpret_cast<std::shared_ptr<sSwitchChannelRequest> *>(
                    const_cast<void *>(args)));
                return report_switch_channel_in_progress(request);
            })

        .on(fsm_event::PERIODIC, fsm_state::ERROR,
            [&](TTransition &transition, const void *args) -> bool {
                // check timeout
                bool timeout = (std::chrono::steady_clock::now() - m_cac_started_time_point) >
                               m_max_wait_for_cac_completed_sec;

                if (timeout) {
                    LOG(ERROR) << "timeout occured waiting for cac completed";
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }
                // returning false means "stay in the same state"
                return false;
            })

        .on(fsm_event::SWITCH_CHANNEL_REQUEST, fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION,
            [&](TTransition &transition, const void *args) -> bool {
                bool error_occured = false;
                bool switched =
                    handle_switch_channel_request_while_in_another_switch_channel(transition, args, error_occured);

                if (error_occured) {
                    transition.change_destination(fsm_state::ERROR); 
                    return true;
                }

                if (switched) {
                    // move to wait for notification
                    return true;
                } else {
                    // wait for cac
                    return false;
                }
            })
        //////////////////////////////////////////////////////
        //////// ERROR                                ////////
        //////////////////////////////////////////////////////
        .state(fsm_state::ERROR)

        .on(fsm_event::PERIODIC, fsm_state::WAIT_FOR_SWITCH_CHANNEL_NOTIFICATION,
            [&](TTransition &transition, const void *args) -> bool {
                // here we report about the switch channel - giving all that we have
                // the report itself calculate its status
                auto switch_channel_report = std::make_shared<sSwitchChannelReport>(
                    false, m_switch_channel_request, m_switch_channel_notification,
                    m_cac_started_notification, m_cac_completed_notification);

                if (!switch_channel_report) {
                    LOG(ERROR) << "failed to create switch channel report for " << m_ifname;
                    transition.change_destination(fsm_state::ERROR);

                    return true;
                }

                // report
                m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_REPORT, switch_channel_report);

                // go back to the initial state
                return true;
            });
    start();
}

bool SwitchChannelFsm::report_switch_channel_in_progress(
    std::shared_ptr<sSwitchChannelRequest> request)
{
    // we are in the middle of another switch channel.
    // construct switch-channel-report with an ERROR.
    auto switch_channel_report = std::make_shared<sSwitchChannelReport>(
        false, request, nullptr, nullptr, nullptr,
        eSwitchChannelReportStatus::ANOTHER_SWITCH_IN_PROGRESS);

    // we care about request not being nullptr just in the case that we
    // failed to create the shared object, therefore we check its nullness only
    // for the error printing
    if (!switch_channel_report && request) {
        LOG(ERROR) << "failed to create switch channel report for " << request->ifname;
        return false;
    }

    // report
    m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_REPORT, switch_channel_report);

    return true;
}

bool load_switch_channel_request_to_cmdu_tx(ieee1905_1::CmduMessageTx &cmdu_tx,
                                            const sSwitchChannelRequest &switch_channel_request)
{
    auto request = message_com::create_vs_message<
        beerocks_message::cACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START>(cmdu_tx);
    if (!request) {
        LOG(ERROR) << "Failed to build message";
        return false;
    }

    request->cs_params().channel   = switch_channel_request.channel;
    request->cs_params().bandwidth = switch_channel_request.bandwidth;

    uint8_t center_channel = 0;
    auto center_channel_it =
        son::wireless_utils::channels_table_5g.find(switch_channel_request.channel);
    if (center_channel_it == son::wireless_utils::channels_table_5g.end()) {
        LOG(ERROR) << "can't find channel " << switch_channel_request.channel
                   << " in the 5g table, center channel is set to zero";
    } else {
        auto bandwidth_it = center_channel_it->second.find(switch_channel_request.bandwidth);
        if (bandwidth_it == center_channel_it->second.end()) {
            LOG(ERROR) << "can't find bandwidth for " << switch_channel_request.channel
                       << " in the 5g table, center channel is set to zero";
        } else {
            center_channel = bandwidth_it->second.center_channel;
        }
    }

    request->cs_params().vht_center_frequency =
        son::wireless_utils::channel_to_freq(center_channel);

    return true;
}

// return true if switch channel was really forwarded
// return false otherwise
bool SwitchChannelFsm::handle_switch_channel_request_while_in_another_switch_channel(
    TTransition &transition, const void *args, bool &error_occured)
{
    auto request =
        *(reinterpret_cast<std::shared_ptr<sSwitchChannelRequest> *>(const_cast<void *>(args)));

    if (!request) {
        LOG(ERROR) << "can't handle null swich-channel-request";
        // switch didn't happen
        error_occured = true;
        return false;
    }

    // we were asked to forcely switch the channel.
    // it means that we need to stop current switch channel
    // and start the switch channel with the new values
    // in the given request
    if (request->force) {
        // 1. report fail for the ongoing
        auto switch_channel_report = std::make_shared<sSwitchChannelReport>(
            false, m_switch_channel_request, m_switch_channel_notification,
            m_cac_started_notification, m_cac_completed_notification,
            eSwitchChannelReportStatus::FORCED_STOP);

        if (!switch_channel_report) {
            LOG(ERROR) << "failed to create switch channel report for " << m_ifname;
            // switch didn't happen
            error_occured = true;
            return false;
        }

        m_task_pool.send_event(eTaskEvent::SWITCH_CHANNEL_REPORT, switch_channel_report);

        // 2. restart the switch channel.
        // restarting the switch channel is composed of
        // two actions (as messges):
        // - radio disable requet
        // - enable aps request (cACTION_APMANAGER_ENABLE_APS_REQUEST)
        disable_interface();
        enable_aps(request->channel, request->bandwidth);

        // start all over
        reset();
        m_switch_channel_request = request;
        error_occured = false;
        return true;

    } else {
        report_switch_channel_in_progress(request);
        error_occured = false;
        return false;
    }
}

bool SwitchChannelFsm::disable_interface()
{
    // disable the radio
    auto radio = std::find_if(m_backhaul_manager.slaves_sockets.begin(),
                              m_backhaul_manager.slaves_sockets.end(),
                              [&](std::shared_ptr<BackhaulManager::sRadioInfo> s_radio) {
                                  return s_radio->hostap_iface == m_ifname;
                              });

    if (radio == m_backhaul_manager.slaves_sockets.end()) {
        LOG(ERROR) << "can't find radio info for " << m_ifname << " at the backhaul";
        return false;
    }

    auto msg =
        message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_RADIO_DISABLE_REQUEST>(
            m_cmdu_tx);

    if (!msg) {
        LOG(ERROR) << "Failed building cACTION_BACKHAUL_RADIO_DISABLE_REQUEST";
        return false;
    }
    LOG(DEBUG) << "Request Agent to disable the radio interface " << m_ifname
               << " before forcing switch channel";
    if (!m_backhaul_manager.send_cmdu((*radio)->slave, m_cmdu_tx)) {
        LOG(ERROR) << "Failed to send cACTION_BACKHAUL_RADIO_DISABLE_REQUEST";
        return false;
    }
    return true;
}

bool SwitchChannelFsm::enable_aps(int channel, eWiFiBandwidth bandwidth)
{
    auto radio = std::find_if(m_backhaul_manager.slaves_sockets.begin(),
                              m_backhaul_manager.slaves_sockets.end(),
                              [&](const std::shared_ptr<BackhaulManager::sRadioInfo> s_radio) {
                                  return s_radio->hostap_iface == m_ifname;
                              });

    if (radio == m_backhaul_manager.slaves_sockets.end()) {
        LOG(ERROR) << "can't find radio info for " << m_ifname << " at the backhaul";
        return false;
    }

    auto request =
        message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_ENABLE_APS_REQUEST>(
            m_cmdu_tx);

    if (!request) {
        LOG(ERROR) << "Failed building cACTION_BACKHAUL_ENABLE_APS_REQUEST";
        return false;
    }

    request->bandwidth() = bandwidth;
    request->channel()   = channel;
    request->center_channel() =
        son::wireless_utils::get_5g_center_channel(channel, bandwidth, true);

    m_backhaul_manager.send_cmdu((*radio)->slave, m_cmdu_tx);
    return true;
}

/////////////////////////
// switch channel task //
/////////////////////////
SwitchChannelTask::SwitchChannelTask(TaskPoolInterface &task_pool,
                                     BackhaulManager &backhaul_manager,
                                     ieee1905_1::CmduMessageTx &cmdu_tx)
    : Task(eTaskType::SWITCH_CHANNEL), m_task_pool(task_pool), m_backhaul_manager(backhaul_manager),
      m_cmdu_tx(cmdu_tx)
{
}

SwitchChannelTask::~SwitchChannelTask() {}

std::vector<eTaskEvent> SwitchChannelTask::get_task_event_list() const
{
    return {eTaskEvent::SWTICH_CHANNEL_REQUEST, eTaskEvent::CAC_STARTED_NOTIFICATION,
            eTaskEvent::CAC_COMPLETED_NOTIFICATION, eTaskEvent::SWITCH_CHANNEL_NOTIFICATION_EVENT};
}

SwitchChannelFsm &SwitchChannelTask::get_fsm_by_ifname(const std::string &ifname)
{
    auto fsm_it = m_fsms.find(ifname);

    if (fsm_it == m_fsms.end()) {
        fsm_it = m_fsms
                     .insert(std::make_pair(
                         ifname, std::unique_ptr<SwitchChannelFsm>(new SwitchChannelFsm(
                                     ifname, m_task_pool, m_backhaul_manager, m_cmdu_tx))))
                     .first;

        LOG(DEBUG) << "Added " << ifname << " to switch channel task. There are now "
                   << m_fsms.size() << " managed interfaces";
    }

    return *(fsm_it->second);
}

void SwitchChannelTask::work()
{
    // work is called periodically
    // this is the chance to handle periodic "event"
    for (auto &fsm : m_fsms) {
        if (!fsm.second) {
            LOG(ERROR) << "null fsm for interface " << fsm.first << ". skipping";
            continue;
        }
        fsm.second->fire(fsm_event::PERIODIC);
    }
}

void SwitchChannelTask::handle_event(eTaskEvent event, std::shared_ptr<void> event_obj)
{
    if (!event_obj) {
        LOG(WARNING) << "Received event " << static_cast<uint8_t>(event)
                     << " without data. Unable to handle the event.";
        return;
    }

    LOG(DEBUG) << "Received event to handle: " << static_cast<uint8_t>(event);

    switch (event) {
    case eTaskEvent::SWTICH_CHANNEL_REQUEST: {
        auto switch_channel_request =
            std::static_pointer_cast<const sSwitchChannelRequest>(event_obj);
        if (!switch_channel_request) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        get_fsm_by_ifname(switch_channel_request->ifname)
            .fire(fsm_event::SWITCH_CHANNEL_REQUEST,
                  reinterpret_cast<const void *>(&switch_channel_request));
    } break;

    case eTaskEvent::SWITCH_CHANNEL_NOTIFICATION_EVENT: {
        auto switch_channel_notification =
            std::static_pointer_cast<sSwitchChannelNotification>(event_obj);
        if (!switch_channel_notification) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        get_fsm_by_ifname(switch_channel_notification->ifname)
            .fire(fsm_event::CSA, reinterpret_cast<const void *>(&switch_channel_notification));
    } break;

    case eTaskEvent::CAC_STARTED_NOTIFICATION: {
        auto cac_started_notification =
            std::static_pointer_cast<sCacStartedNotification>(event_obj);
        if (!cac_started_notification) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        get_fsm_by_ifname(cac_started_notification->ifname)
            .fire(fsm_event::CAC_STARTED,
                  reinterpret_cast<const void *>(&cac_started_notification));
    } break;

    case eTaskEvent::CAC_COMPLETED_NOTIFICATION: {
        auto cac_completed_notification =
            std::static_pointer_cast<sCacCompletedNotification>(event_obj);
        if (!cac_completed_notification) {
            LOG(ERROR) << "casting event_obj resulted in nullptr";
            return;
        }
        get_fsm_by_ifname(cac_completed_notification->ifname)
            .fire(fsm_event::CAC_COMPLETED,
                  reinterpret_cast<const void *>(&cac_completed_notification));
    } break;

    default: {
        LOG(WARNING) << "Received unexpected event: " << static_cast<uint8_t>(event);
    } break;
    }
}

} // namespace switch_channel
} // namespace beerocks
