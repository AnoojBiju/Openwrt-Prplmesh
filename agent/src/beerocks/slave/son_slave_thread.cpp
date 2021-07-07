/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#include "son_slave_thread.h"

#include "agent_db.h"

#include "tlvf_utils.h"

#include "cac_status_database.h"
#include "gate/1905_beacon_query_to_vs.h"
#include "gate/vs_beacon_response_to_1905.h"
#include <bcl/beerocks_utils.h>
#include <bcl/beerocks_version.h>
#include <bcl/network/network_utils.h>
#include <beerocks/tlvf/beerocks_message.h>
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <beerocks/tlvf/beerocks_message_apmanager.h>
#include <beerocks/tlvf/beerocks_message_backhaul.h>
#include <beerocks/tlvf/beerocks_message_control.h>
#include <beerocks/tlvf/beerocks_message_monitor.h>
#include <beerocks/tlvf/beerocks_message_platform.h>
#include <easylogging++.h>
#include <mapf/common/utils.h>
#include <tlvf/WSC/AttrList.h>
#include <tlvf/ieee_1905_1/tlvAlMacAddress.h>
#include <tlvf/ieee_1905_1/tlvSupportedFreqBand.h>
#include <tlvf/ieee_1905_1/tlvSupportedRole.h>
#include <tlvf/wfa_map/tlvApRadioIdentifier.h>
#include <tlvf/wfa_map/tlvAssociatedStaTrafficStats.h>
#include <tlvf/wfa_map/tlvBeaconMetricsResponse.h>
#include <tlvf/wfa_map/tlvChannelPreference.h>
#include <tlvf/wfa_map/tlvChannelSelectionResponse.h>
#include <tlvf/wfa_map/tlvClientAssociationControlRequest.h>
#include <tlvf/wfa_map/tlvClientAssociationEvent.h>
#include <tlvf/wfa_map/tlvHigherLayerData.h>
#include <tlvf/wfa_map/tlvOperatingChannelReport.h>
#include <tlvf/wfa_map/tlvProfile2ApCapability.h>
#include <tlvf/wfa_map/tlvProfile2ApRadioAdvancedCapabilities.h>
#include <tlvf/wfa_map/tlvProfile2CacCompletionReport.h>
#include <tlvf/wfa_map/tlvProfile2CacStatusReport.h>
#include <tlvf/wfa_map/tlvProfile2Default802dotQSettings.h>
#include <tlvf/wfa_map/tlvProfile2ReasonCode.h>
#include <tlvf/wfa_map/tlvProfile2SteeringRequest.h>
#include <tlvf/wfa_map/tlvProfile2TrafficSeparationPolicy.h>
#include <tlvf/wfa_map/tlvStaMacAddressType.h>
#include <tlvf/wfa_map/tlvSteeringBTMReport.h>
#include <tlvf/wfa_map/tlvSteeringRequest.h>
#include <tlvf/wfa_map/tlvTransmitPowerLimit.h>

#include "gate/1905_beacon_query_to_vs.h"
#include "gate/vs_beacon_response_to_1905.h"
#include "traffic_separation.h"

// BPL Error Codes
#include <bpl/bpl_cfg.h>
#include <bpl/bpl_err.h>

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

#define SLAVE_STATE_CONTINUE() call_slave_select = false

using namespace beerocks;
using namespace net;
using namespace son;

slave_thread::slave_thread(sSlaveConfig conf, beerocks::logging &logger_)
    : socket_thread(conf.temp_path + std::string(BEEROCKS_SLAVE_UDS) + +"_" + conf.hostap_iface),
      config(conf), logger(logger_)
{
    thread_name = "son_slave_" + conf.hostap_iface;
    slave_uds   = conf.temp_path + std::string(BEEROCKS_SLAVE_UDS) + "_" + conf.hostap_iface;
    backhaul_manager_uds    = conf.temp_path + std::string(BEEROCKS_BACKHAUL_MGR_UDS);
    platform_manager_uds    = conf.temp_path + std::string(BEEROCKS_PLAT_MGR_UDS);
    backhaul_manager_socket = nullptr;
    master_socket           = nullptr;
    monitor_socket          = nullptr;
    ap_manager_socket       = nullptr;
    platform_manager_socket = nullptr;

    // Set configuration on Agent database.
    auto db = AgentDB::get();

    db->device_conf.stop_on_failure_attempts = conf.stop_on_failure_attempts;
    m_stop_on_failure_attempts               = db->device_conf.stop_on_failure_attempts;

    db->bridge.iface_name        = conf.bridge_iface;
    db->backhaul.preferred_bssid = tlvf::mac_from_string(conf.backhaul_preferred_bssid);

    auto radio = db->add_radio(conf.hostap_iface, conf.backhaul_wireless_iface);
    if (!radio) {
        m_constructor_failed = true;
        // No need to print here anything, 'add_radio()' does it internally
        return;
    }
    m_fronthaul_iface = conf.hostap_iface;

    radio->sta_iface_filter_low = conf.backhaul_wireless_iface_filter_low;

    slave_state = STATE_INIT;
    set_select_timeout(SELECT_TIMEOUT_MSEC);
}

slave_thread::~slave_thread()
{
    LOG(DEBUG) << "destructor - slave_reset()";
    stop_slave_thread();
}

bool slave_thread::init()
{
    LOG(INFO) << "Slave Info:";
    LOG(INFO) << "hostap_iface=" << config.hostap_iface;
    LOG(INFO) << "hostap_iface_type=" << config.hostap_iface_type;

    if (m_constructor_failed) {
        LOG(ERROR) << "Not initalizing slave_thread. There was an error in the constructor";
        return false;
    }

    if (config.hostap_iface_type == beerocks::IFACE_TYPE_UNSUPPORTED) {
        LOG(ERROR) << "hostap_iface_type '" << config.hostap_iface_type << "' UNSUPPORTED!";
        return false;
    }

    return socket_thread::init();
}

void slave_thread::stop_slave_thread()
{
    LOG(DEBUG) << "stop_slave_thread()";
    slave_reset();
    should_stop = true;
}

void slave_thread::slave_reset()
{
    slave_resets_counter++;
    LOG(DEBUG) << "slave_reset() #" << slave_resets_counter << " - start";
    if (!detach_on_conf_change) {
        backhaul_manager_stop();
    }
    platform_manager_stop();
    hostap_services_off();
    fronthaul_stop();
    is_backhaul_manager   = false;
    detach_on_conf_change = false;

    auto db = AgentDB::get();

    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(ERROR) << "Radio of iface " << m_fronthaul_iface << " does not exist on the db";
        return;
    }
    // Clear the front interface mac.
    radio->front.iface_mac = network_utils::ZERO_MAC;

    if (db->device_conf.stop_on_failure_attempts && !m_stop_on_failure_attempts) {
        LOG(ERROR) << "Reached to max stop on failure attempts!";
        stopped = true;
    }

    if (stopped && slave_state != STATE_INIT) {
        platform_notify_error(beerocks::bpl::eErrorCode::SLAVE_STOPPED, "");
        LOG(DEBUG) << "goto STATE_STOPPED";
        slave_state = STATE_STOPPED;
    } else if (is_backhaul_disconnected) {
        slave_state_timer =
            std::chrono::steady_clock::now() + std::chrono::seconds(SLAVE_INIT_DELAY_SEC);
        LOG(DEBUG) << "goto STATE_WAIT_BEFORE_INIT";
        slave_state = STATE_WAIT_BEFORE_INIT;
    } else {
        LOG(DEBUG) << "goto STATE_INIT";
        slave_state = STATE_INIT;
    }

    is_slave_reset = true;
    LOG(DEBUG) << "slave_reset() #" << slave_resets_counter << " - done";
}

void slave_thread::platform_notify_error(beerocks::bpl::eErrorCode code,
                                         const std::string &error_data)
{
    if (platform_manager_socket == nullptr) {
        LOG(ERROR) << "Invalid Platform Manager socket!";
        return;
    }

    auto error =
        message_com::create_vs_message<beerocks_message::cACTION_PLATFORM_ERROR_NOTIFICATION>(
            cmdu_tx);

    if (error == nullptr) {
        LOG(ERROR) << "Failed building message!";
        return;
    }

    error->code() = uint32_t(code);
    string_utils::copy_string(error->data(0), error_data.c_str(),
                              message::PLATFORM_ERROR_DATA_SIZE);

    // Send the message
    message_com::send_cmdu(platform_manager_socket, cmdu_tx);
}

void slave_thread::on_thread_stop() { stop_slave_thread(); }

bool slave_thread::socket_disconnected(Socket *sd)
{
    if (configuration_in_progress) {
        LOG(DEBUG) << "configuration is in progress, ignoring";
        detach_on_conf_change = true;
        if (sd == ap_manager_socket || sd == monitor_socket) {
            fronthaul_stop();
            return false;
        }
        return true;
    }

    if (sd == backhaul_manager_socket) {
        LOG(DEBUG) << "backhaul manager & master socket disconnected! - slave_reset()";
        platform_notify_error(bpl::eErrorCode::SLAVE_SLAVE_BACKHAUL_MANAGER_DISCONNECTED, "");
        stop_slave_thread();
        return false;
    } else if (sd == platform_manager_socket) {
        LOG(DEBUG) << "platform_manager disconnected! - slave_reset()";
        stop_slave_thread();
        return false;
    } else if (sd == ap_manager_socket || sd == monitor_socket) {
        LOG(DEBUG) << (sd == ap_manager_socket ? "ap_manager" : "monitor")
                   << " socket disconnected - slave_reset()";
        slave_reset();
        return false;
    }

    return true;
}

std::string slave_thread::print_cmdu_types(const message::sUdsHeader *cmdu_header)
{
    return message_com::print_cmdu_types(cmdu_header);
}

bool slave_thread::work()
{
    if (!m_logger_configured) {
        logger.set_thread_name(logger.get_module_name());
        logger.attach_current_thread_to_logger_id();
        m_logger_configured = true;
    }

    bool call_slave_select = true;

    if (!monitor_heartbeat_check() || !ap_manager_heartbeat_check()) {
        slave_reset();
    }

    if (!slave_fsm(call_slave_select)) {
        return false;
    }

    if (call_slave_select) {
        if (!socket_thread::work()) {
            return false;
        }
    }
    return true;
}

bool slave_thread::handle_cmdu(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    if (cmdu_rx.getMessageType() == ieee1905_1::eMessageType::VENDOR_SPECIFIC_MESSAGE) {

        auto beerocks_header = message_com::parse_intel_vs_message(cmdu_rx);

        if (!beerocks_header) {
            LOG(ERROR) << "Not a vendor specific message";
            return false;
        }

        switch (beerocks_header->action()) {
        case beerocks_message::ACTION_CONTROL: {
            return handle_cmdu_control_message(sd, beerocks_header);
        } break;
        case beerocks_message::ACTION_BACKHAUL: {
            return handle_cmdu_backhaul_manager_message(sd, beerocks_header);
        } break;
        case beerocks_message::ACTION_PLATFORM: {
            return handle_cmdu_platform_manager_message(sd, beerocks_header);
        } break;
        case beerocks_message::ACTION_APMANAGER: {
            return handle_cmdu_ap_manager_message(sd, beerocks_header);
        } break;
        case beerocks_message::ACTION_MONITOR: {
            return handle_cmdu_monitor_message(sd, beerocks_header);
        } break;
        default: {
            LOG(ERROR) << "Unknown message, action: " << int(beerocks_header->action());
        }
        }
    } else if (sd == ap_manager_socket) {
        // Handle IEEE 1905.1 messages from the AP Manager
        return handle_cmdu_ap_manager_ieee1905_1_message(*sd, cmdu_rx);
    } else if (sd == monitor_socket) {
        // Handle IEEE 1905.1 messages from the Monitor
        return handle_cmdu_monitor_ieee1905_1_message(*sd, cmdu_rx);
    } else { // IEEE 1905.1 message
        // Handle IEEE 1905.1 messages from the Controller
        return handle_cmdu_control_ieee1905_1_message(sd, cmdu_rx);
    }
    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////// HANDLE CMDU ACTIONS /////////////////////////
////////////////////////////////////////////////////////////////////////

bool slave_thread::handle_cmdu_control_ieee1905_1_message(Socket *sd,
                                                          ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto cmdu_message_type = cmdu_rx.getMessageType();

    if (master_socket == nullptr) {
        LOG(WARNING) << "master_socket == nullptr";
        return true;
    } else if (master_socket != sd) {
        LOG(DEBUG) << "Unknown socket, cmdu message type: " << int(cmdu_message_type); //TODO:
    }

    if (slave_state == STATE_STOPPED) {
        LOG(WARNING) << "slave_state == STATE_STOPPED";
        return true;
    }
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        return false;
    }

    // ZWDFS Radio should ignore messages from the Controller
    if (radio->front.zwdfs) {
        return true;
    }

    switch (cmdu_message_type) {
    case ieee1905_1::eMessageType::ACK_MESSAGE:
        return handle_ack_message(sd, cmdu_rx);
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_RENEW_MESSAGE:
        return handle_autoconfiguration_renew(sd, cmdu_rx);
    case ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_WSC_MESSAGE:
        return handle_autoconfiguration_wsc(sd, cmdu_rx);
    case ieee1905_1::eMessageType::AP_METRICS_QUERY_MESSAGE:
        return handle_ap_metrics_query(*sd, cmdu_rx);
    case ieee1905_1::eMessageType::BEACON_METRICS_QUERY_MESSAGE:
        return handle_beacon_metrics_query(sd, cmdu_rx);
    case ieee1905_1::eMessageType::CHANNEL_PREFERENCE_QUERY_MESSAGE:
        return handle_channel_preference_query(sd, cmdu_rx);
    case ieee1905_1::eMessageType::CHANNEL_SELECTION_REQUEST_MESSAGE:
        return handle_channel_selection_request(sd, cmdu_rx);
    case ieee1905_1::eMessageType::CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE:
        return handle_client_association_request(sd, cmdu_rx);
    case ieee1905_1::eMessageType::CLIENT_STEERING_REQUEST_MESSAGE:
        return handle_client_steering_request(sd, cmdu_rx);
    case ieee1905_1::eMessageType::HIGHER_LAYER_DATA_MESSAGE:
        return handle_1905_higher_layer_data_message(*sd, cmdu_rx);
    case ieee1905_1::eMessageType::MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE:
        return handle_multi_ap_policy_config_request(sd, cmdu_rx);

    default:
        LOG(ERROR) << "Unknown CMDU message type: " << std::hex << int(cmdu_message_type);
        return false;
    }

    return true;
}

bool slave_thread::handle_cmdu_ap_manager_ieee1905_1_message(Socket &sd,
                                                             ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto cmdu_message_type = cmdu_rx.getMessageType();
    switch (cmdu_message_type) {
    // Forward unhandled messages to the backhaul manager (probably headed to the controller)
    default:
        const auto mid = cmdu_rx.getMessageId();
        LOG(DEBUG) << "Forwarding ieee1905 message " << std::hex << int(cmdu_message_type)
                   << " to backhaul_manager, mid = " << std::hex << int(mid);

        uint16_t length = message_com::get_uds_header(cmdu_rx)->length;
        cmdu_rx.swap(); // swap back before forwarding
        if (!message_com::forward_cmdu_to_uds(backhaul_manager_socket, cmdu_rx, length)) {
            LOG(ERROR) << "Failed forwarding message 0x" << std::hex << int(cmdu_message_type)
                       << " to backhaul_manager";

            return false;
        }
    }

    return true;
}

bool slave_thread::handle_cmdu_monitor_ieee1905_1_message(Socket &sd,
                                                          ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto cmdu_message_type = cmdu_rx.getMessageType();
    switch (cmdu_message_type) {
    case ieee1905_1::eMessageType::AP_METRICS_RESPONSE_MESSAGE:
        return handle_monitor_ap_metrics_response(sd, cmdu_rx);
    default:
        LOG(ERROR) << "Unknown CMDU message type: " << std::hex << int(cmdu_message_type);
        return false;
    }
}

bool slave_thread::handle_cmdu_control_message(Socket *sd,
                                               std::shared_ptr<beerocks_header> beerocks_header)
{
    // LOG(DEBUG) << "handle_cmdu_control_message(), INTEL_VS: action=" + std::to_string(beerocks_header->action()) + ", action_op=" + std::to_string(beerocks_header->action_op());
    // LOG(DEBUG) << "received radio_mac=" << beerocks_header->radio_mac() << ", local radio_mac=" << hostap_params.iface_mac;

    // Scope this code block to prevent shadowing of "db" and "radio" variables internally on the
    // switch case.
    {
        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }

        // to me or not to me, this is the question...
        if (beerocks_header->actionhdr()->radio_mac() != radio->front.iface_mac) {
            return true;
        }
    }

    if (beerocks_header->actionhdr()->direction() == beerocks::BEEROCKS_DIRECTION_CONTROLLER) {
        return true;
    }

    if (master_socket == nullptr) {
        // LOG(WARNING) << "master_socket == nullptr";
        return true;
    } else if (master_socket != sd) {
        LOG(WARNING) << "Unknown socket, ACTION_CONTROL action_op: "
                     << int(beerocks_header->action_op());
        return true;
    }

    if (slave_state == STATE_STOPPED) {
        return true;
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_CONTROL_ARP_QUERY_REQUEST: {
        LOG(TRACE) << "ACTION_CONTROL_ARP_QUERY_REQUEST";
        auto request_in =
            beerocks_header->addClass<beerocks_message::cACTION_CONTROL_ARP_QUERY_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_CONTROL_ARP_QUERY_REQUEST failed";
            return false;
        }
        auto request_out =
            message_com::create_vs_message<beerocks_message::cACTION_PLATFORM_ARP_QUERY_REQUEST>(
                cmdu_tx, beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        // notify platform manager
        request_out->params() = request_in->params();
        message_com::send_cmdu(platform_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_SON_CONFIG_UPDATE: {
        LOG(DEBUG) << "received ACTION_CONTROL_SON_CONFIG_UPDATE";
        auto update =
            beerocks_header->addClass<beerocks_message::cACTION_CONTROL_SON_CONFIG_UPDATE>();
        if (update == nullptr) {
            LOG(ERROR) << "addClass cACTION_CONTROL_SON_CONFIG_UPDATE failed";
            return false;
        }
        son_config = update->config();
        log_son_config();
        break;
    }
    case beerocks_message::ACTION_CONTROL_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_REQUEST: {
        LOG(DEBUG) << "received ACTION_CONTROL_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_REQUEST";

        auto request_in = beerocks_header->addClass<
            beerocks_message::cACTION_CONTROL_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR)
                << "addClass cACTION_CONTROL_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_REQUEST>(
            cmdu_tx);
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        LOG(DEBUG) << "send ACTION_APMANAGER_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_REQUEST";
        request_out->params() = request_in->params();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_HOSTAP_CHANNEL_SWITCH_ACS_START: {
        LOG(DEBUG) << "received ACTION_CONTROL_HOSTAP_CHANNEL_SWITCH_ACS_START";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_HOSTAP_CHANNEL_SWITCH_ACS_START>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_CONTROL_HOSTAP_CHANNEL_SWITCH_ACS_START failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_CHANNEL_SWITCH_ACS_START>(
            cmdu_tx, beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        LOG(DEBUG) << "send cACTION_APMANAGER_HOSTAP_CHANNEL_SWITCH_ACS_START";
        request_out->cs_params() = request_in->cs_params();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_CLIENT_START_MONITORING_REQUEST: {
        LOG(DEBUG) << "received ACTION_CONTROL_CLIENT_START_MONITORING_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CLIENT_START_MONITORING_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_CONTROL_CLIENT_START_MONITORING_REQUEST failed";
            return false;
        }

        std::string client_mac = tlvf::mac_to_string(request_in->params().mac);
        std::string client_bridge_4addr_mac =
            tlvf::mac_to_string(request_in->params().bridge_4addr_mac);
        std::string client_ip = network_utils::ipv4_to_string(request_in->params().ipv4);

        LOG(DEBUG) << "START_MONITORING_REQUEST: mac=" << client_mac << " ip=" << client_ip
                   << " bridge_4addr_mac=" << client_bridge_4addr_mac;

        //notify monitor
        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CLIENT_START_MONITORING_REQUEST>(
            cmdu_tx, beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_MONITOR_CLIENT_START_MONITORING_REQUEST message!";
            return false;
        }
        request_out->params() = request_in->params();
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }

    case beerocks_message::ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST: {
        LOG(DEBUG) << "received ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST";

        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST failed";
            return false;
        }
        auto hostap_mac = tlvf::mac_to_string(request_in->params().mac);
        bool forbackhaul =
            (is_backhaul_manager && backhaul_params.backhaul_is_wireless) ? true : false;

        if (request_in->params().cross && (request_in->params().ipv4.oct[0] == 0) &&
            forbackhaul) { //if backhaul manager and wireless send to backhaul else front.
            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>(
                cmdu_tx, beerocks_header->id());
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST "
                              "message!";
                return false;
            }

            request_out->params() = request_in->params();
            message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        } else if (request_in->params().cross &&
                   (request_in->params().ipv4.oct[0] ==
                    0)) { // unconnected client cross --> send to ap_manager
            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>(
                cmdu_tx, beerocks_header->id());
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building ACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_REQUEST "
                              "message!";
                return false;
            }
            request_out->params() = request_in->params();
            message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        } else {
            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_REQUEST>(
                cmdu_tx, beerocks_header->id());
            if (request_out == nullptr) {
                LOG(ERROR)
                    << "Failed building ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_REQUEST message!";
                return false;
            }
            request_out->params() = request_in->params();
            message_com::send_cmdu(monitor_socket, cmdu_tx);
        }

        LOG(INFO) << "rx_rssi measurement request for client mac=" << request_in->params().mac
                  << " ip=" << network_utils::ipv4_to_string(request_in->params().ipv4)
                  << " channel=" << int(request_in->params().channel) << " bandwidth="
                  << utils::convert_bandwidth_to_int(
                         (beerocks::eWiFiBandwidth)request_in->params().bandwidth)
                  << " cross=" << int(request_in->params().cross)
                  << " id=" << int(beerocks_header->id());
        break;
    }
    case beerocks_message::ACTION_CONTROL_CLIENT_DISCONNECT_REQUEST: {
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CLIENT_DISCONNECT_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_CONTROL_CLIENT_DISCONNECT_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_CLIENT_DISCONNECT_REQUEST>(cmdu_tx,
                                                                           beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_APMANAGER_CLIENT_DISCONNECT_REQUEST message!";
            return false;
        }

        request_out->mac()    = request_in->mac();
        request_out->vap_id() = request_in->vap_id();
        request_out->type()   = request_in->type();
        request_out->reason() = request_in->reason();

        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_CLIENT_NEW_IP_ADDRESS_NOTIFICATION: {
        LOG(DEBUG) << "received ACTION_CONTROL_CLIENT_NEW_IP_ADDRESS_NOTIFICATION";
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CLIENT_NEW_IP_ADDRESS_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass ACTION_CONTROL_CLIENT_NEW_IP_ADDRESS_NOTIFICATION failed";
            return false;
        }

        // Notify monitor
        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CLIENT_NEW_IP_ADDRESS_NOTIFICATION>(cmdu_tx);
        if (!notification_out) {
            LOG(ERROR)
                << "Failed building cACTION_MONITOR_CLIENT_NEW_IP_ADDRESS_NOTIFICATION message!";
            return false;
        }

        notification_out->mac()  = notification_in->mac();
        notification_out->ipv4() = notification_in->ipv4();
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_CHANGE_MODULE_LOGGING_LEVEL: {
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CHANGE_MODULE_LOGGING_LEVEL>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_CONTROL_CHANGE_MODULE_LOGGING_LEVEL failed";
            return false;
        }
        bool all = false;
        if (request_in->params().module_name == beerocks::BEEROCKS_PROCESS_ALL) {
            all = true;
        }
        if (all || request_in->params().module_name == beerocks::BEEROCKS_PROCESS_SLAVE) {
            logger.set_log_level_state((eLogLevel)request_in->params().log_level,
                                       request_in->params().enable);
        }
        if (all || request_in->params().module_name == beerocks::BEEROCKS_PROCESS_MONITOR) {
            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_MONITOR_CHANGE_MODULE_LOGGING_LEVEL>(cmdu_tx);
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }
            request_out->params() = request_in->params();
            message_com::send_cmdu(monitor_socket, cmdu_tx);
        }
        if (all || request_in->params().module_name == beerocks::BEEROCKS_PROCESS_PLATFORM) {
            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_PLATFORM_CHANGE_MODULE_LOGGING_LEVEL>(cmdu_tx);
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }
            request_out->params() = request_in->params();
            message_com::send_cmdu(platform_manager_socket, cmdu_tx);
        }
        break;
    }
    case beerocks_message::ACTION_CONTROL_BACKHAUL_ROAM_REQUEST: {
        LOG(TRACE) << "received ACTION_CONTROL_BACKHAUL_ROAM_REQUEST";
        if (is_backhaul_manager && backhaul_params.backhaul_is_wireless) {
            auto request_in =
                beerocks_header
                    ->addClass<beerocks_message::cACTION_CONTROL_BACKHAUL_ROAM_REQUEST>();
            if (request_in == nullptr) {
                LOG(ERROR) << "addClass cACTION_CONTROL_BACKHAUL_ROAM_REQUEST failed";
                return false;
            }
            auto bssid = tlvf::mac_to_string(request_in->params().bssid);
            LOG(DEBUG) << "reconfigure wpa_supplicant to bssid " << bssid
                       << " channel=" << int(request_in->params().channel);

            auto request_out =
                message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_ROAM_REQUEST>(
                    cmdu_tx, beerocks_header->id());
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }
            request_out->params() = request_in->params();
            message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        }
        break;
    }
    case beerocks_message::ACTION_CONTROL_BACKHAUL_RESET: {
        LOG(TRACE) << "received ACTION_CONTROL_BACKHAUL_RESET";
        auto request =
            message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_RESET>(cmdu_tx);
        if (request == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST: {
        if (monitor_socket) {
            // LOG(TRACE) << "received ACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST"; // floods the log
            auto request_in = beerocks_header->addClass<
                beerocks_message::cACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST>();
            if (request_in == nullptr) {
                LOG(ERROR) << "addClass cACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST failed";
                return false;
            }

            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_MONITOR_HOSTAP_STATS_MEASUREMENT_REQUEST>(
                cmdu_tx, beerocks_header->id());
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }
            request_out->sync() = request_in->sync();
            message_com::send_cmdu(monitor_socket, cmdu_tx);
        }
        break;
    }
    case beerocks_message::ACTION_CONTROL_HOSTAP_SET_NEIGHBOR_11K_REQUEST: {
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_HOSTAP_SET_NEIGHBOR_11K_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_CONTROL_HOSTAP_SET_NEIGHBOR_11K_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_SET_NEIGHBOR_11K_REQUEST>(
            cmdu_tx, beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        request_out->params() = request_in->params();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_HOSTAP_REMOVE_NEIGHBOR_11K_REQUEST: {
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_HOSTAP_REMOVE_NEIGHBOR_11K_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_CONTROL_HOSTAP_REMOVE_NEIGHBOR_11K_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_REMOVE_NEIGHBOR_11K_REQUEST>(
            cmdu_tx, beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        request_out->params() = request_in->params();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_CLIENT_BEACON_11K_REQUEST: {
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CLIENT_BEACON_11K_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_CONTROL_CLIENT_BEACON_11K_REQUEST failed";
            return false;
        }

        auto db = AgentDB::get();

        //LOG(DEBUG) << "ACTION_CONTROL_CLIENT_BEACON_11K_REQUEST";
        // override ssid in case of:
        if (request_in->params().use_optional_ssid &&
            std::string((char *)request_in->params().ssid).empty()) {
            //LOG(DEBUG) << "ssid field is empty! using slave ssid -> " << config.ssid;
            string_utils::copy_string(request_in->params().ssid, db->device_conf.front_radio.ssid,
                                      message::WIFI_SSID_MAX_LENGTH);
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CLIENT_BEACON_11K_REQUEST>(cmdu_tx,
                                                                         beerocks_header->id());
        if (request_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_MONITOR_CLIENT_BEACON_11K_REQUEST message!";
            return false;
        }
        request_out->params() = request_in->params();

        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_HOSTAP_UPDATE_STOP_ON_FAILURE_ATTEMPTS_REQUEST: {
        auto request_in = beerocks_header->addClass<
            beerocks_message::cACTION_CONTROL_HOSTAP_UPDATE_STOP_ON_FAILURE_ATTEMPTS_REQUEST>();
        if (request_in == nullptr) {
            LOG(ERROR)
                << "addClass cACTION_CONTROL_HOSTAP_UPDATE_STOP_ON_FAILURE_ATTEMPTS_REQUEST failed";
            return false;
        }
        auto db = AgentDB::get();

        db->device_conf.stop_on_failure_attempts = request_in->attempts();
        m_stop_on_failure_attempts               = db->device_conf.stop_on_failure_attempts;
        LOG(DEBUG) << "stop_on_failure_attempts new value: "
                   << db->device_conf.stop_on_failure_attempts;

        if (is_backhaul_manager) {
            auto request_out = message_com::create_vs_message<
                beerocks_message::cACTION_BACKHAUL_UPDATE_STOP_ON_FAILURE_ATTEMPTS_REQUEST>(
                cmdu_tx);
            if (request_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            request_out->attempts() = request_in->attempts();
            message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        }
        break;
    }
    case beerocks_message::ACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST: {
        LOG(TRACE) << "ACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST";
        auto update =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_REQUEST>();
        if (update == nullptr) {
            LOG(ERROR) << "addClass failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_STEERING_CLIENT_SET_GROUP_REQUEST>(
            cmdu_tx, beerocks_header->id());

        if (notification_out == nullptr) {
            LOG(ERROR)
                << "Failed building cACTION_MONITOR_STEERING_CLIENT_SET_GROUP_REQUEST message!";
            break;
        }
        notification_out->params() = update->params();

        LOG(DEBUG) << std::endl
                   << "remove = " << int(update->params().remove) << std::endl
                   << "steeringGroupIndex = " << update->params().steeringGroupIndex << std::endl
                   << "bssid = " << update->params().cfg.bssid << std::endl
                   << "utilCheckIntervalSec = " << update->params().cfg.utilCheckIntervalSec
                   << std::endl
                   << "utilAvgCount = " << update->params().cfg.utilAvgCount << std::endl
                   << "inactCheckIntervalSec = " << update->params().cfg.inactCheckIntervalSec
                   << std::endl
                   << "inactCheckThresholdSec = " << update->params().cfg.inactCheckThresholdSec
                   << std::endl;

        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_STEERING_CLIENT_SET_REQUEST: {
        LOG(TRACE) << "ACTION_CONTROL_STEERING_CLIENT_SET_REQUEST";
        auto update =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_REQUEST>();
        if (update == nullptr) {
            LOG(ERROR) << "addClass failed";
            return false;
        }

        // send to Monitor
        auto notification_mon_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_STEERING_CLIENT_SET_REQUEST>(cmdu_tx,
                                                                           beerocks_header->id());

        if (notification_mon_out == nullptr) {
            LOG(ERROR) << "Failed building cACTION_MONITOR_STEERING_CLIENT_SET_REQUEST message!";
            break;
        }

        notification_mon_out->params() = update->params();

        message_com::send_cmdu(monitor_socket, cmdu_tx);

        // send to AP MANAGER
        auto notification_ap_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_STEERING_CLIENT_SET_REQUEST>(cmdu_tx,
                                                                             beerocks_header->id());

        if (notification_ap_out == nullptr) {
            LOG(ERROR) << "Failed building cACTION_APMANAGER_STEERING_CLIENT_SET_REQUEST message!";
            break;
        }

        notification_ap_out->params() = update->params();

        message_com::send_cmdu(ap_manager_socket, cmdu_tx);

        LOG(DEBUG) << std::endl
                   << "remove = " << notification_ap_out->params().remove << std::endl
                   << "steeringGroupIndex = " << notification_ap_out->params().steeringGroupIndex
                   << std::endl
                   << "client_mac = " << notification_ap_out->params().client_mac << std::endl
                   << "bssid = " << update->params().bssid << std::endl
                   << "config.snrProbeHWM = " << notification_ap_out->params().config.snrProbeHWM
                   << std::endl
                   << "config.snrProbeLWM = " << notification_ap_out->params().config.snrProbeLWM
                   << std::endl
                   << "config.snrAuthHWM = " << notification_ap_out->params().config.snrAuthHWM
                   << std::endl
                   << "config.snrAuthLWM = " << notification_ap_out->params().config.snrAuthLWM
                   << std::endl
                   << "config.snrInactXing = " << notification_ap_out->params().config.snrInactXing
                   << std::endl
                   << "config.snrHighXing = " << notification_ap_out->params().config.snrHighXing
                   << std::endl
                   << "config.snrLowXing = " << notification_ap_out->params().config.snrLowXing
                   << std::endl
                   << "config.authRejectReason = "
                   << notification_ap_out->params().config.authRejectReason << std::endl;

        break;
    }
    case beerocks_message::ACTION_CONTROL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST: {
        LOG(TRACE) << "ACTION_CONTROL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_CONTROL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST failed";
            return false;
        }

        auto db = AgentDB::get();

        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            return false;
        }

        bool radio_5g = wireless_utils::is_frequency_band_5ghz(radio->freq_type);

        // If received scan request and ZWDFS CAC is about to finish refuse to start the
        // background scan only on the 5G radio.
        LOG(DEBUG) << "zwdfs_cac_remaining_time_sec=" << db->statuses.zwdfs_cac_remaining_time_sec;
        if (radio_5g && db->statuses.zwdfs_cac_remaining_time_sec > 0) {
            constexpr uint8_t ETSI_CAC_TIME_SEC = 72; // ETSI CAC time sec (60) * factor of 1.2
            float dwell_time_sec                = request_in->scan_params().dwell_time_ms / 1000.0;
            auto number_of_channel_to_scan      = request_in->scan_params().channel_pool_size;

            constexpr float SCAN_TIME_FACTOR = 89.1;
            // scan time factor (89.1) is calculated in this way:
            // factor * (scan_break_time / slice_size + 1) = 89.1
            // when: factor=1.1, scan_break_time=1600ms, slice_size=20ms
            auto total_scan_time = number_of_channel_to_scan * dwell_time_sec * SCAN_TIME_FACTOR;
            LOG(DEBUG) << "total_scan_time=" << total_scan_time
                       << " on number_of_channels=" << number_of_channel_to_scan;

            if (db->statuses.zwdfs_cac_remaining_time_sec < ETSI_CAC_TIME_SEC &&
                db->statuses.zwdfs_cac_remaining_time_sec < total_scan_time) {
                LOG(DEBUG) << "Refuse DCS scan";
                auto notification = message_com::create_vs_message<
                    beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION>(cmdu_tx);
                if (!notification) {
                    LOG(ERROR)
                        << "Failed building cACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION msg";
                    return false;
                }

                send_cmdu_to_controller(cmdu_tx);
                break;
            }
        }

        radio->statuses.channel_scan_in_progress = true;

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR)
                << "Failed building cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST message!";
            return false;
        }

        request_out->scan_params() = request_in->scan_params();

        LOG(DEBUG) << "send cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST";
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_CONTROL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST: {
        LOG(TRACE) << "ACTION_CONTROL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_CONTROL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR)
                << "Failed building cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_REQUEST message!";
            return false;
        }

        LOG(DEBUG) << "send cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_REQUEST";
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    default: {
        LOG(ERROR) << "Unknown CONTROL message, action_op: " << int(beerocks_header->action_op());
        return false;
    }
    }

    return true;
}

bool slave_thread::handle_cmdu_backhaul_manager_message(
    Socket *sd, std::shared_ptr<beerocks_header> beerocks_header)
{
    if (backhaul_manager_socket == nullptr) {
        LOG(ERROR) << "backhaul_socket == nullptr";
        return true;
    } else if (backhaul_manager_socket != sd) {
        LOG(ERROR) << "Unknown socket, ACTION_BACKHAUL action_op: "
                   << int(beerocks_header->action_op());
        return true;
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_BACKHAUL_REGISTER_RESPONSE: {
        LOG(DEBUG) << "ACTION_BACKHAUL_REGISTER_RESPONSE";
        if (slave_state == STATE_WAIT_FOR_BACKHAUL_MANAGER_REGISTER_RESPONSE) {
            auto response =
                beerocks_header->addClass<beerocks_message::cACTION_BACKHAUL_REGISTER_RESPONSE>();
            if (!response) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }
            LOG(DEBUG) << "goto STATE_JOIN_INIT";
            slave_state = STATE_JOIN_INIT;
        } else {
            LOG(ERROR) << "slave_state != STATE_WAIT_FOR_BACKHAUL_MANAGER_REGISTER_RESPONSE";
        }
        break;
    }

    case beerocks_message::ACTION_BACKHAUL_ENABLE_APS_REQUEST: {
        auto notification_in =
            beerocks_header->addClass<beerocks_message::cACTION_BACKHAUL_ENABLE_APS_REQUEST>();
        if (!notification_in) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_ENABLE_APS_REQUEST message!";
            return false;
        }

        auto notification_out =
            message_com::create_vs_message<beerocks_message::cACTION_APMANAGER_ENABLE_APS_REQUEST>(
                cmdu_tx);
        if (!notification_out) {
            LOG(ERROR) << "Failed building ACTION_APMANAGER_ENABLE_APS_REQUEST message!";
            return false;
        }

        notification_out->channel()        = notification_in->channel();
        notification_out->bandwidth()      = notification_in->bandwidth();
        notification_out->center_channel() = notification_in->center_channel();
        LOG(DEBUG) << "Sending ACTION_APMANAGER_ENABLE_APS_REQUEST";
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);

        configuration_in_progress = true;

        break;
    }

    case beerocks_message::ACTION_BACKHAUL_CONNECTED_NOTIFICATION: {

        auto notification =
            beerocks_header->addClass<beerocks_message::cACTION_BACKHAUL_CONNECTED_NOTIFICATION>();
        if (!notification) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        LOG(DEBUG) << "ACTION_BACKHAUL_CONNECTED_NOTIFICATION";

        if (slave_state >= STATE_WAIT_FOR_BACKHAUL_MANAGER_CONNECTED_NOTIFICATION &&
            slave_state <= STATE_OPERATIONAL) {

            // Already sent join_master request, mark as reconfiguration
            if (slave_state >= STATE_WAIT_FOR_JOINED_RESPONSE && slave_state <= STATE_OPERATIONAL)
                is_backhaul_reconf = true;

            is_backhaul_manager = (bool)notification->params().is_backhaul_manager;
            LOG_IF(is_backhaul_manager, DEBUG) << "Selected as backhaul manager";

            auto db = AgentDB::get();

            backhaul_params.bridge_ipv4 =
                network_utils::ipv4_to_string(notification->params().bridge_ipv4);
            backhaul_params.backhaul_mac = tlvf::mac_to_string(notification->params().backhaul_mac);
            backhaul_params.backhaul_ipv4 =
                network_utils::ipv4_to_string(notification->params().backhaul_ipv4);
            backhaul_params.backhaul_bssid =
                tlvf::mac_to_string(notification->params().backhaul_bssid);
            // backhaul_params.backhaul_freq        = notification->params.backhaul_freq; // HACK temp disabled because of a bug on endian converter
            backhaul_params.backhaul_channel     = notification->params().backhaul_channel;
            backhaul_params.backhaul_is_wireless = notification->params().backhaul_is_wireless;
            backhaul_params.backhaul_iface_type  = notification->params().backhaul_iface_type;

            std::copy_n(notification->params().backhaul_scan_measurement_list,
                        beerocks::message::BACKHAUL_SCAN_MEASUREMENT_MAX_LENGTH,
                        backhaul_params.backhaul_scan_measurement_list);

            for (unsigned int i = 0; i < message::BACKHAUL_SCAN_MEASUREMENT_MAX_LENGTH; i++) {
                if (backhaul_params.backhaul_scan_measurement_list[i].channel > 0) {
                    LOG(DEBUG) << "mac = " << backhaul_params.backhaul_scan_measurement_list[i].mac
                               << " channel = "
                               << int(backhaul_params.backhaul_scan_measurement_list[i].channel)
                               << " rssi = "
                               << int(backhaul_params.backhaul_scan_measurement_list[i].rssi);
                }
            }

            if (notification->params().backhaul_is_wireless) {
                backhaul_params.backhaul_iface = config.backhaul_wireless_iface;
            } else {
                backhaul_params.backhaul_iface = db->ethernet.wan.iface_name;
            }

            LOG(DEBUG) << "goto STATE_BACKHAUL_MANAGER_CONNECTED";
            slave_state = STATE_BACKHAUL_MANAGER_CONNECTED;

        } else {
            LOG(WARNING) << "slave_state != STATE_WAIT_FOR_BACKHAUL_CONNECTED_NOTIFICATION";
        }
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_BUSY_NOTIFICATION: {
        if (slave_state != STATE_WAIT_FOR_BACKHAUL_MANAGER_CONNECTED_NOTIFICATION) {
            LOG(WARNING) << "slave_state != STATE_WAIT_FOR_BACKHAUL_CONNECTED_NOTIFICATION";
            break;
        }

        slave_state_timer = std::chrono::steady_clock::now() +
                            std::chrono::seconds(WAIT_BEFORE_SEND_BH_ENABLE_NOTIFICATION_SEC);

        LOG(DEBUG) << "goto STATE_WAIT_BACKHAUL_MANAGER_BUSY";
        slave_state = STATE_WAIT_BACKHAUL_MANAGER_BUSY;

        break;
    }
    case beerocks_message::ACTION_BACKHAUL_DISCONNECTED_NOTIFICATION: {

        if (is_slave_reset)
            break;

        LOG(DEBUG) << "ACTION_BACKHAUL_DISCONNECTED_NOTIFICATION";

        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_DISCONNECTED_NOTIFICATION>();
        if (!notification) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        stopped |= bool(notification->stopped());

        is_backhaul_disconnected = true;
        slave_state_timer =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(beerocks::IRE_MAX_WIRELESS_RECONNECTION_TIME_MSC);

        master_socket = nullptr;

        slave_reset();
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_APPLY_VLAN_POLICY_REQUEST: {
        LOG(DEBUG) << "received ACTION_BACKHAUL_APPLY_VLAN_POLICY_REQUEST";
        TrafficSeparation::apply_traffic_separation();
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE: {
        LOG(DEBUG) << "ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE";

        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE>();
        if (!response_in) {
            LOG(ERROR)
                << "Failed building ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE message!";
            return false;
        }

        LOG(DEBUG) << "ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE mac="
                   << response_in->params().result.mac
                   << " rx_rssi=" << int(response_in->params().rx_rssi)
                   << " id=" << int(beerocks_header->id());

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE>(
            cmdu_tx, beerocks_header->id());

        if (response_out == nullptr) {
            LOG(ERROR)
                << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE message!";
            break;
        }

        response_out->params()            = response_in->params();
        response_out->params().src_module = beerocks::BEEROCKS_ENTITY_BACKHAUL_MANAGER;
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE: {
        LOG(DEBUG) << "ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE";
        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE>();
        if (!response_in) {
            LOG(ERROR) << "Failed building ACTION_BACKHAUL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE "
                          "message!";
            return false;
        }

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE>(
            cmdu_tx, beerocks_header->id());

        if (!response_out) {
            LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE "
                          "message!";
            break;
        }
        response_out->mac() = response_in->mac();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }

    case beerocks_message::ACTION_BACKHAUL_DL_RSSI_REPORT_NOTIFICATION: {
        LOG(DEBUG) << "ACTION_BACKHAUL_DL_RSSI_REPORT_NOTIFICATION";
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_DL_RSSI_REPORT_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "Failed building ACTION_BACKHAUL_DL_RSSI_REPORT_NOTIFICATION message!";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_BACKHAUL_DL_RSSI_REPORT_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());

        if (!notification_out) {
            LOG(ERROR)
                << "Failed building ACTION_CONTROL_BACKHAUL_DL_RSSI_REPORT_NOTIFICATION message!";
            break;
        }

        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);

        break;
    }
    case beerocks_message::ACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST: {
        LOG(DEBUG) << "ACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST";
        if (!monitor_socket) {
            LOG(ERROR) << "monitor_socket is null";
            return false;
        }
        auto request_in = beerocks_header->addClass<
            beerocks_message::cACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CLIENT_ASSOCIATED_STA_LINK_METRIC_REQUEST>(
            cmdu_tx, beerocks_header->id());
        if (!request_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        request_out->sync()    = request_in->sync();
        request_out->sta_mac() = request_in->sta_mac();
        LOG(DEBUG) << "send ACTION_MONITOR_CLIENT_ASSOCIATED_STA_LINK_METRIC_REQUEST";
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_START_WPS_PBC_REQUEST: {
        LOG(DEBUG) << "ACTION_BACKHAUL_START_WPS_PBC_REQUEST";
        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_START_WPS_PBC_REQUEST>(cmdu_tx);

        if (!notification_out) {
            LOG(ERROR) << "Failed building message cACTION_APMANAGER_START_WPS_PBC_REQUEST!";
            return false;
        }
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_SET_ASSOC_DISALLOW_REQUEST: {
        if (!ap_manager_socket) {
            LOG(ERROR) << "ap_manager_socket is null";
            return false;
        }
        LOG(DEBUG) << "ACTION_BACKHAUL_SET_ASSOC_DISALLOW_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_SET_ASSOC_DISALLOW_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_SET_ASSOC_DISALLOW_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_SET_ASSOC_DISALLOW_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        request_out->enable() = request_in->enable();
        request_out->bssid()  = request_in->bssid();
        LOG(DEBUG) << "send ACTION_APMANAGER_SET_ASSOC_DISALLOW_REQUEST";
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNELS_LIST_REQUEST: {
        auto request_in =
            beerocks_header->addClass<beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNELS_LIST_REQUEST "
                          "message!";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_CHANNELS_LIST_REQUEST>(cmdu_tx);

        if (!request_out) {
            LOG(ERROR) << "Failed building "
                          "cACTION_APMANAGER_CHANNELS_LIST_REQUEST "
                          "message!";
            return false;
        }
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START: {
        LOG(DEBUG) << "received ACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_HOSTAP_CHANNEL_SWITCH_ACS_START failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_CHANNEL_SWITCH_ACS_START>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        LOG(DEBUG) << "send cACTION_APMANAGER_HOSTAP_CHANNEL_SWITCH_ACS_START";
        request_out->cs_params() = request_in->cs_params();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }

    case beerocks_message::ACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST: {
        LOG(DEBUG) << "received ACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST failed";
            return false;
        }

        // we are about to (re)configure
        configuration_in_progress = true;

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        LOG(DEBUG) << "send cACTION_APMANAGER_HOSTAP_CANCEL_ACTIVE_CAC_REQUEST";
        request_out->cs_params() = request_in->cs_params();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }

    case beerocks_message::ACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST: {
        LOG(TRACE) << "Received ACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST";
        auto request_in = beerocks_header->addClass<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST>();
        if (!request_in) {
            LOG(ERROR)
                << "Failed building cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST "
                   "message!";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST>(cmdu_tx);

        if (!request_out) {
            LOG(ERROR) << "Failed building "
                          "cACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_REQUEST "
                          "message!";
            return false;
        }
        request_out->channel()          = request_in->channel();
        request_out->bandwidth()        = request_in->bandwidth();
        request_out->ant_switch_on()    = request_in->ant_switch_on();
        request_out->center_frequency() = request_in->center_frequency();
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_RADIO_DISABLE_REQUEST: {
        LOG(DEBUG) << "ACTION_BACKHAUL_RADIO_DISABLE_REQUEST";
        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_RADIO_DISABLE_REQUEST>(cmdu_tx);

        if (!notification_out) {
            LOG(ERROR) << "Failed building message cACTION_APMANAGER_RADIO_DISABLE_REQUEST!";
            return false;
        }
        configuration_in_progress = true;
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_RADIO_TEAR_DOWN_REQUEST: {
        LOG(DEBUG) << "ACTION_BACKHAUL_RADIO_TEAR_DOWN_REQUEST";

        ///////////////////////////////////////////////////////////////////
        // Short term solution
        // In non-EasyMesh mode, never modify hostapd configuration
        // and in this case VAPs credentials
        //
        // Long term solution
        // All EasyMesh VAPs will be stored in the platform DB.
        // All other VAPs are manual, AKA should not be modified by prplMesh
        ////////////////////////////////////////////////////////////////////
        auto db = AgentDB::get();
        if (db->device_conf.management_mode == BPL_MGMT_MODE_NOT_MULTIAP) {
            LOG(WARNING) << "non-EasyMesh mode - skip updating VAP credentials";
            break;
        }

        // Tear down all VAPS in the radio by sending an update request with an empty configuration.
        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_WIFI_CREDENTIALS_UPDATE_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR)
                << "Failed building message cACTION_APMANAGER_WIFI_CREDENTIALS_UPDATE_REQUEST!";
            return false;
        }

        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST failed";
            return false;
        }

        auto db = AgentDB::get();

        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            return false;
        }

        bool radio_5g = wireless_utils::is_frequency_band_5ghz(radio->freq_type);

        // If received scan request and ZWDFS CAC is about to finish refuse to start the
        // background scan only on the 5G radio.
        LOG(DEBUG) << "zwdfs_cac_remaining_time_sec=" << db->statuses.zwdfs_cac_remaining_time_sec;
        if (radio_5g && db->statuses.zwdfs_cac_remaining_time_sec > 0) {
            constexpr uint8_t ETSI_CAC_TIME_SEC = 72; // ETSI CAC time sec (60) * factor of 1.2
            float dwell_time_sec                = request_in->scan_params().dwell_time_ms / 1000.0;
            auto number_of_channel_to_scan      = request_in->scan_params().channel_pool_size;

            constexpr float SCAN_TIME_FACTOR = 89.1;
            // scan time factor (89.1) is calculated in this way:
            // factor * (scan_break_time / slice_size + 1) = 89.1
            // when: factor=1.1, scan_break_time=1600ms, slice_size=20ms
            auto total_scan_time = number_of_channel_to_scan * dwell_time_sec * SCAN_TIME_FACTOR;
            LOG(DEBUG) << "total_scan_time=" << total_scan_time
                       << " on number_of_channels=" << number_of_channel_to_scan;

            if (db->statuses.zwdfs_cac_remaining_time_sec < ETSI_CAC_TIME_SEC &&
                db->statuses.zwdfs_cac_remaining_time_sec < total_scan_time) {
                LOG(DEBUG) << "Refuse DCS scan";
                auto notification = message_com::create_vs_message<
                    beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION>(cmdu_tx);
                if (!notification) {
                    LOG(ERROR)
                        << "Failed building cACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION msg";
                    return false;
                }

                send_cmdu_to_controller(cmdu_tx);
                break;
            }
        }

        radio->statuses.channel_scan_in_progress = true;

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR)
                << "Failed building cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST message!";
            return false;
        }

        request_out->scan_params() = request_in->scan_params();

        LOG(DEBUG) << "send cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_REQUEST";
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR)
                << "Failed building cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_REQUEST message!";
            return false;
        }

        LOG(DEBUG) << "send cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_REQUEST";
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST: {
        LOG(TRACE) << "ACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST";
        auto request_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST>();
        if (!request_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_REQUEST failed";
            return false;
        }

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_ABORT_REQUEST>(cmdu_tx);
        if (!request_out) {
            LOG(ERROR) << "Failed building cACTION_MONITOR_CHANNEL_SCAN_ABORT_REQUEST message!";
            return false;
        }

        LOG(DEBUG) << "send cACTION_MONITOR_CHANNEL_SCAN_ABORT_REQUEST";
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        break;
    }
    default: {
        LOG(ERROR) << "Unknown BACKHAUL_MANAGER message, action_op: "
                   << int(beerocks_header->action_op());
        return false;
    }
    }

    return true;
}

bool slave_thread::handle_cmdu_platform_manager_message(
    Socket *sd, std::shared_ptr<beerocks_header> beerocks_header)
{
    if (platform_manager_socket != sd) {
        LOG(ERROR) << "Unknown socket, ACTION_PLATFORM_MANAGER action_op: "
                   << int(beerocks_header->action_op());
        return true;
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE: {
        LOG(TRACE) << "ACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE";
        if (slave_state == STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE) {
            auto response =
                beerocks_header
                    ->addClass<beerocks_message::cACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE>();
            if (response == nullptr) {
                LOG(ERROR) << "addClass cACTION_PLATFORM_SON_SLAVE_REGISTER_RESPONSE failed";
                return false;
            }
            // Configuration is invalid
            if (response->valid() == 0) {
                LOG(ERROR) << "response->valid == 0";
                platform_notify_error(
                    bpl::eErrorCode::CONFIG_PLATFORM_REPORTED_INVALID_CONFIGURATION, "");
                m_stop_on_failure_attempts--;
                slave_reset();
                return true;
            }

            /**
             * On GW platform the ethernet interface which is used for backhaul connection must be
             * empty since the GW doesn't need wired backhaul connection. Since it is being set on
             * the constructor from the agent configuration file, clear it here when we know if the
             * agent runs on a GW.
             */
            auto db = AgentDB::get();
            if (db->device_conf.local_gw) {
                db->ethernet.wan.iface_name.clear();
                db->ethernet.wan.mac = network_utils::ZERO_MAC;
            }

            m_stop_on_failure_attempts = db->device_conf.stop_on_failure_attempts;

            LOG(TRACE) << "goto STATE_CONNECT_TO_BACKHAUL_MANAGER";
            slave_state = STATE_CONNECT_TO_BACKHAUL_MANAGER;
        } else {
            LOG(ERROR) << "slave_state != STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE";
        }
        break;
    }
    case beerocks_message::ACTION_PLATFORM_ARP_MONITOR_NOTIFICATION: {
        // LOG(TRACE) << "ACTION_PLATFORM_ARP_MONITOR_NOTIFICATION";
        if (master_socket) {
            auto notification_in =
                beerocks_header
                    ->addClass<beerocks_message::cACTION_PLATFORM_ARP_MONITOR_NOTIFICATION>();
            if (notification_in == nullptr) {
                LOG(ERROR) << "addClass cACTION_PLATFORM_ARP_MONITOR_NOTIFICATION failed";
                return false;
            }

            auto notification_out = message_com::create_vs_message<
                beerocks_message::cACTION_CONTROL_CLIENT_ARP_MONITOR_NOTIFICATION>(cmdu_tx);
            if (notification_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            notification_out->params() = notification_in->params();
            send_cmdu_to_controller(cmdu_tx);
        }
        break;
    }
    case beerocks_message::ACTION_PLATFORM_WLAN_PARAMS_CHANGED_NOTIFICATION: {
        LOG(TRACE) << "ACTION_PLATFORM_WLAN_PARAMS_CHANGED_NOTIFICATION";

        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_PLATFORM_WLAN_PARAMS_CHANGED_NOTIFICATION>();
        if (notification == nullptr) {
            LOG(ERROR) << "addClass cACTION_PLATFORM_WLAN_PARAMS_CHANGED_NOTIFICATION failed";
            return false;
        }

        // slave only reacts to band_enabled change
        auto db = AgentDB::get();
        if (db->device_conf.front_radio.config[config.hostap_iface].band_enabled !=
            notification->wlan_settings().band_enabled) {
            LOG(DEBUG) << "band_enabled changed - performing slave_reset()";
            slave_reset();
        }
        break;
    }
    case beerocks_message::ACTION_PLATFORM_DHCP_MONITOR_NOTIFICATION: {
        auto notification =
            beerocks_header
                ->addClass<beerocks_message::cACTION_PLATFORM_DHCP_MONITOR_NOTIFICATION>();
        if (notification == nullptr) {
            LOG(ERROR) << "addClass ACTION_PLATFORM_DHCP_MONITOR_NOTIFICATION failed";
            return false;
        }

        if (notification->op() == beerocks_message::eDHCPOp_Add ||
            notification->op() == beerocks_message::eDHCPOp_Old) {
            std::string client_mac = tlvf::mac_to_string(notification->mac());
            std::string client_ip  = network_utils::ipv4_to_string(notification->ipv4());

            LOG(DEBUG) << "ACTION_DHCP_LEASE_ADDED_NOTIFICATION mac " << client_mac
                       << " ip = " << client_ip << " name="
                       << std::string(notification->hostname(message::NODE_NAME_LENGTH));

            // notify master
            if (master_socket) {
                auto master_notification = message_com::create_vs_message<
                    beerocks_message::cACTION_CONTROL_CLIENT_DHCP_COMPLETE_NOTIFICATION>(cmdu_tx);
                if (master_notification == nullptr) {
                    LOG(ERROR) << "Failed building message!";
                    return false;
                }

                master_notification->mac()  = notification->mac();
                master_notification->ipv4() = notification->ipv4();
                string_utils::copy_string(master_notification->name(message::NODE_NAME_LENGTH),
                                          notification->hostname(message::NODE_NAME_LENGTH),
                                          message::NODE_NAME_LENGTH);
                send_cmdu_to_controller(cmdu_tx);
            }

        } else {
            LOG(DEBUG) << "ACTION_PLATFORM_DHCP_MONITOR_NOTIFICATION op " << notification->op()
                       << " mac " << notification->mac()
                       << " ip = " << network_utils::ipv4_to_string(notification->ipv4());
        }
        break;
    }
    case beerocks_message::ACTION_PLATFORM_ARP_QUERY_RESPONSE: {
        LOG(TRACE) << "ACTION_PLATFORM_ARP_QUERY_RESPONSE";
        if (master_socket) {
            auto response =
                beerocks_header->addClass<beerocks_message::cACTION_PLATFORM_ARP_QUERY_RESPONSE>();
            if (response == nullptr) {
                LOG(ERROR) << "addClass cACTION_PLATFORM_ARP_QUERY_RESPONSE failed";
                return false;
            }

            auto response_out = message_com::create_vs_message<
                beerocks_message::cACTION_CONTROL_ARP_QUERY_RESPONSE>(cmdu_tx,
                                                                      beerocks_header->id());
            if (response_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            response_out->params() = response->params();
            send_cmdu_to_controller(cmdu_tx);
        }
        break;
    }

    default: {
        LOG(ERROR) << "Unknown PLATFORM_MANAGER message, action_op: "
                   << int(beerocks_header->action_op());
        return false;
    }
    }

    return true;
}

bool slave_thread::handle_cmdu_ap_manager_message(Socket *sd,
                                                  std::shared_ptr<beerocks_header> beerocks_header)
{
    if (ap_manager_socket != sd &&
        beerocks_header->action_op() != beerocks_message::ACTION_APMANAGER_UP_NOTIFICATION) {
        LOG(ERROR) << "Unknown socket, ACTION_APMANAGER action_op: "
                   << int(beerocks_header->action_op())
                   << ", ap_manager_socket=" << intptr_t(ap_manager_socket)
                   << ", incoming sd=" << intptr_t(sd);
        return true;
    } else if (beerocks_header->action_op() ==
               beerocks_message::ACTION_APMANAGER_HEARTBEAT_NOTIFICATION) {
        ap_manager_last_seen       = std::chrono::steady_clock::now();
        ap_manager_retries_counter = 0;
        return true;
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_APMANAGER_UP_NOTIFICATION: {
        LOG(INFO) << "received ACTION_APMANAGER_UP_NOTIFICATION from sd=" << intptr_t(sd);
        if (ap_manager_socket) {
            LOG(ERROR) << "AP manager opened new socket altough there is already open socket to it";
            remove_socket(ap_manager_socket);
            delete ap_manager_socket;
            ap_manager_socket = nullptr;
        }

        ap_manager_socket = sd;
        add_socket(ap_manager_socket);

        auto config_msg =
            message_com::create_vs_message<beerocks_message::cACTION_APMANAGER_CONFIGURE>(cmdu_tx);
        if (!config_msg) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        auto db = AgentDB::get();
        config_msg->channel() =
            db->device_conf.front_radio.config[config.hostap_iface].configured_channel;

        message_com::send_cmdu(ap_manager_socket, cmdu_tx);

        break;
    }
    case beerocks_message::ACTION_APMANAGER_JOINED_NOTIFICATION: {
        LOG(INFO) << "received ACTION_APMANAGER_JOINED_NOTIFICATION";
        auto notification =
            beerocks_header->addClass<beerocks_message::cACTION_APMANAGER_JOINED_NOTIFICATION>();
        if (notification == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_JOINED_NOTIFICATION failed";
            return false;
        }
        auto db = AgentDB::get();

        m_fronthaul_iface = notification->params().iface_name;
        auto radio        = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }

        radio->front.iface_mac    = notification->params().iface_mac;
        radio->number_of_antennas = notification->params().ant_num;
        radio->antenna_gain_dB    = notification->params().ant_gain;
        radio->tx_power_dB        = notification->params().tx_power;
        radio->freq_type          = notification->params().frequency_band;
        radio->max_supported_bw   = notification->params().max_bandwidth;

        radio->ht_supported  = notification->params().ht_supported;
        radio->ht_capability = notification->params().ht_capability;
        std::copy_n(notification->params().ht_mcs_set, beerocks::message::HT_MCS_SET_SIZE,
                    radio->ht_mcs_set.begin());

        radio->vht_supported  = notification->params().vht_supported;
        radio->vht_capability = notification->params().vht_capability;
        std::copy_n(notification->params().vht_mcs_set, beerocks::message::VHT_MCS_SET_SIZE,
                    radio->vht_mcs_set.begin());

        save_channel_params_to_db(notification->cs_params());

        radio->front.zwdfs                 = notification->params().zwdfs;
        radio->front.hybrid_mode_supported = notification->params().hybrid_mode_supported;
        LOG(DEBUG) << "ZWDFS AP: " << radio->front.zwdfs;

        fill_channel_list_to_agent_db(notification->channel_list());

        // cac
        save_cac_capabilities_params_to_db();

        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_RESPONSE: {
        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass "
                          "cACTION_APMANAGER_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_RESPONSE "
                          "failed";
            return false;
        }
        LOG(INFO) << "received ACTION_APMANAGER_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_RESPONSE";

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_SET_RESTRICTED_FAILSAFE_CHANNEL_RESPONSE>(
            cmdu_tx);
        if (response_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        response_out->success() = response_in->success();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_AP_DISABLED_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_HOSTAP_AP_DISABLED_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_AP_DISABLED_NOTIFICATION failed";
            return false;
        }
        LOG(INFO) << "received ACTION_APMANAGER_HOSTAP_AP_DISABLED_NOTIFICATION on vap_id="
                  << int(notification_in->vap_id());
        if (notification_in->vap_id() == beerocks::IFACE_RADIO_ID) {
            LOG(WARNING) << __FUNCTION__ << "AP_Disabled on radio, slave reset";
            if (configuration_in_progress) {
                LOG(INFO) << "configuration in progress, ignoring";
                detach_on_conf_change = true;
                break;
            }
            slave_reset();
        } else {
            auto notification_out = message_com::create_vs_message<
                beerocks_message::cACTION_CONTROL_HOSTAP_AP_DISABLED_NOTIFICATION>(cmdu_tx);
            if (notification_out == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            notification_out->vap_id() = notification_in->vap_id();
            send_cmdu_to_controller(cmdu_tx);
        }
        break;
    }
    case beerocks_message::ACTION_APMANAGER_ENABLE_APS_RESPONSE: {
        configuration_in_progress = false;
        LOG(INFO) << "received ACTION_APMANAGER_ENABLE_APS_RESPONSE";

        auto response =
            beerocks_header->addClass<beerocks_message::cACTION_APMANAGER_ENABLE_APS_RESPONSE>();
        if (!response) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_ENABLE_APS_RESPONSE failed";
            return false;
        }

        if (!response->success()) {
            LOG(ERROR) << "failed to enable APs";
            slave_reset();
        }

        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_AP_ENABLED_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_HOSTAP_AP_ENABLED_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_AP_ENABLED_NOTIFICATION failed";
            return false;
        }
        LOG(INFO) << "received ACTION_APMANAGER_HOSTAP_AP_ENABLED_NOTIFICATION vap_id="
                  << int(notification_in->vap_id());

        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(ERROR) << "Radio of iface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }

        const auto &vap_info = notification_in->vap_info();
        auto bssid =
            std::find_if(radio->front.bssids.begin(), radio->front.bssids.end(),
                         [&vap_info](const beerocks::AgentDB::sRadio::sFront::sBssid &bssid) {
                             return bssid.mac == vap_info.mac;
                         });
        if (bssid == radio->front.bssids.end()) {
            LOG(ERROR) << "Radio does not contain BSSID: " << vap_info.mac;
            return false;
        }

        // Update VAP info (BSSID) in the AgentDB
        bssid->ssid          = vap_info.ssid;
        bssid->fronthaul_bss = vap_info.fronthaul_vap;
        bssid->backhaul_bss  = vap_info.backhaul_vap;
        if (vap_info.backhaul_vap) {
            bssid->backhaul_bss_disallow_profile1_agent_association =
                vap_info.profile1_backhaul_sta_association_disallowed;
            bssid->backhaul_bss_disallow_profile2_agent_association =
                vap_info.profile2_backhaul_sta_association_disallowed;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_AP_ENABLED_NOTIFICATION>(cmdu_tx);
        if (!notification_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->vap_id()   = notification_in->vap_id();
        notification_out->vap_info() = notification_in->vap_info();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_NOTIFICATION failed";
            return false;
        }

        LOG(INFO) << "received ACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_NOTIFICATION";

        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(DEBUG) << "Radio of iface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }
        for (uint8_t vap_idx = 0; vap_idx < eBeeRocksIfaceIds::IFACE_TOTAL_VAPS; vap_idx++) {
            auto &bss         = radio->front.bssids[vap_idx];
            bss.mac           = notification_in->params().vaps[vap_idx].mac;
            bss.ssid          = notification_in->params().vaps[vap_idx].ssid;
            bss.fronthaul_bss = notification_in->params().vaps[vap_idx].fronthaul_vap;
            bss.backhaul_bss  = notification_in->params().vaps[vap_idx].backhaul_vap;
            bss.backhaul_bss_disallow_profile1_agent_association =
                notification_in->params()
                    .vaps[vap_idx]
                    .profile1_backhaul_sta_association_disallowed;
            bss.backhaul_bss_disallow_profile2_agent_association =
                notification_in->params()
                    .vaps[vap_idx]
                    .profile2_backhaul_sta_association_disallowed;

            if (notification_in->params().vaps[vap_idx].mac != network_utils::ZERO_MAC) {
                LOG(DEBUG) << "BSS " << bss.mac << ", ssid:" << bss.ssid
                           << ", fBSS: " << bss.fronthaul_bss << ", bBSS: " << bss.backhaul_bss
                           << ", p1_dis: " << bss.backhaul_bss_disallow_profile1_agent_association
                           << ", p2_dis: " << bss.backhaul_bss_disallow_profile2_agent_association;
            }
        }

        TrafficSeparation::apply_traffic_separation(m_fronthaul_iface);

        // When the AP-Manager sends VAPS_LIST_UPDATE_NOTIFICATION the autoconfiguration is
        // is completed
        m_autoconfiguration_completed = true;

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_VAPS_LIST_UPDATE_NOTIFICATION>(cmdu_tx);
        if (!notification_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->params() = notification_in->params();
        LOG(TRACE) << "send ACTION_CONTROL_HOSTAP_VAPS_LIST_UPDATE_NOTIFICATION";
        send_cmdu_to_controller(cmdu_tx);

        // This probably changed the "AP Operational BSS" list in topology, so send a notification
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_NOTIFICATION_MESSAGE)) {
            LOG(ERROR) << "cmdu creation of type TOPOLOGY_NOTIFICATION_MESSAGE, has failed";
            return false;
        }

        auto tlvAlMacAddress = cmdu_tx.addClass<ieee1905_1::tlvAlMacAddress>();
        if (!tlvAlMacAddress) {
            LOG(ERROR) << "addClass ieee1905_1::tlvAlMacAddress failed";
            return false;
        }
        tlvAlMacAddress->mac() = db->bridge.mac;
        send_cmdu_to_controller(cmdu_tx);

        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_ACS_NOTIFICATION: {
        LOG(INFO) << "ACTION_APMANAGER_HOSTAP_ACS_NOTIFICATION";
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_HOSTAP_ACS_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_APMANAGER_HOSTAP_ACS_NOTIFICATION failed";
            return false;
        }

        save_channel_params_to_db(notification_in->cs_params());

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_ACS_NOTIFICATION>(cmdu_tx,
                                                                       beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->cs_params() = notification_in->cs_params();
        send_cmdu_to_controller(cmdu_tx);
        send_operating_channel_report();
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION: {
        LOG(INFO) << "ACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION";

        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_HOSTAP_CSA_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION failed";
            return false;
        }

        save_channel_params_to_db(notification_in->cs_params());

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_CSA_NOTIFICATION>(cmdu_tx,
                                                                       beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->cs_params() = notification_in->cs_params();
        send_cmdu_to_controller(cmdu_tx);
        send_operating_channel_report();

        auto notification_out_bhm = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_CSA_NOTIFICATION>(cmdu_tx);
        if (!notification_out_bhm) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out_bhm->cs_params() = notification_in->cs_params();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION: {
        LOG(INFO) << "received ACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION";
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_HOSTAP_CSA_ERROR_NOTIFICATION failed";
            return false;
        }

        save_channel_params_to_db(notification_in->cs_params());

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_CSA_ERROR_NOTIFICATION>(cmdu_tx,
                                                                             beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->cs_params() = notification_in->cs_params();
        send_cmdu_to_controller(cmdu_tx);
        send_operating_channel_report();

        auto notification_out_bhm = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_CSA_ERROR_NOTIFICATION>(cmdu_tx);
        if (!notification_out_bhm) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out_bhm->cs_params() = notification_in->cs_params();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE: {
        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE failed";
            return false;
        }
        LOG(INFO) << "APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE mac="
                  << response_in->params().result.mac
                  << " rx_rssi=" << int(response_in->params().rx_rssi)
                  << " id=" << int(beerocks_header->id());

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE>(
            cmdu_tx, beerocks_header->id());

        if (response_out == nullptr) {
            LOG(ERROR)
                << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE message!";
            break;
        }

        response_out->params()            = response_in->params();
        response_out->params().src_module = beerocks::BEEROCKS_ENTITY_AP_MANAGER;
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_APMANAGER_CLIENT_DISCONNECTED_NOTIFICATION failed";
            return false;
        }

        auto &client_mac = notification_in->params().mac;
        auto &bssid      = notification_in->params().bssid;
        LOG(INFO) << "client disconnected sta_mac=" << client_mac << " from bssid=" << bssid;

        // notify master
        if (!master_socket) {
            LOG(DEBUG) << "Controller is not connected";
            return true;
        }

        // If exists, remove client association information for disconnected client.
        auto db = AgentDB::get();
        db->erase_client(client_mac, bssid);

        // build 1905.1 message CMDU to send to the controller
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_NOTIFICATION_MESSAGE)) {
            LOG(ERROR) << "cmdu creation of type TOPOLOGY_NOTIFICATION_MESSAGE, has failed";
            return false;
        }

        auto tlvAlMacAddress = cmdu_tx.addClass<ieee1905_1::tlvAlMacAddress>();
        if (!tlvAlMacAddress) {
            LOG(ERROR) << "addClass ieee1905_1::tlvAlMacAddress failed";
            return false;
        }
        tlvAlMacAddress->mac() = db->bridge.mac;

        auto client_association_event_tlv = cmdu_tx.addClass<wfa_map::tlvClientAssociationEvent>();
        if (!client_association_event_tlv) {
            LOG(ERROR) << "addClass tlvClientAssociationEvent failed";
            return false;
        }
        client_association_event_tlv->client_mac() = notification_in->params().mac;
        client_association_event_tlv->bssid()      = notification_in->params().bssid;
        client_association_event_tlv->association_event() =
            wfa_map::tlvClientAssociationEvent::CLIENT_HAS_LEFT_THE_BSS;

        if (!db->controller_info.prplmesh_controller) {
            LOG(DEBUG) << "non-prplMesh, not adding ClientAssociationEvent VS TLV";
        } else {
            // Add vendor specific tlv
            auto vs_tlv =
                message_com::add_vs_tlv<beerocks_message::tlvVsClientAssociationEvent>(cmdu_tx);

            if (!vs_tlv) {
                LOG(ERROR) << "add_vs_tlv tlvVsClientAssociationEvent failed";
                return false;
            }

            vs_tlv->mac()               = notification_in->params().mac;
            vs_tlv->bssid()             = notification_in->params().bssid;
            vs_tlv->vap_id()            = notification_in->params().vap_id;
            vs_tlv->disconnect_reason() = notification_in->params().reason;
            vs_tlv->disconnect_source() = notification_in->params().source;
            vs_tlv->disconnect_type()   = notification_in->params().type;
        }

        send_cmdu_to_controller(cmdu_tx);

        // profile-2

        // build 1905.1 0x8022 Client Disassociation Stats
        // message CMDU to send to the controller
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CLIENT_DISASSOCIATION_STATS_MESSAGE)) {
            LOG(ERROR) << "cmdu creation of type CLIENT_DISASSOCIATION_STATS_MESSAGE, has failed";
            return false;
        }

        // 17.2.23 STA MAC Address Type
        auto sta_mac_address_tlv = cmdu_tx.addClass<wfa_map::tlvStaMacAddressType>();
        if (!sta_mac_address_tlv) {
            LOG(ERROR) << "addClass sta_mac_address_tlv failed";
            return false;
        }
        sta_mac_address_tlv->sta_mac() = notification_in->params().mac;

        // 17.2.64 Reason Code
        auto reason_code_tlv = cmdu_tx.addClass<wfa_map::tlvProfile2ReasonCode>();
        if (!reason_code_tlv) {
            LOG(ERROR) << "addClass reason_code_tlv failed";
            return false;
        }
        reason_code_tlv->reason_code() = wfa_map::tlvProfile2ReasonCode::LEAVING_NETWORK_DISASSOC;

        // 17.2.35 Associated STA Traffic Stats
        // TEMPORARY: adding empty statistics
        auto associated_sta_traffic_stats_tlv =
            cmdu_tx.addClass<wfa_map::tlvAssociatedStaTrafficStats>();
        if (!associated_sta_traffic_stats_tlv) {
            LOG(ERROR) << "addClass associated_sta_traffic_stats_tlv failed";
            return false;
        }
        associated_sta_traffic_stats_tlv->sta_mac() = notification_in->params().mac;

        send_cmdu_to_controller(cmdu_tx);

        break;
    }
    case beerocks_message::ACTION_APMANAGER_ACK: {
        auto response_in = beerocks_header->addClass<beerocks_message::cACTION_APMANAGER_ACK>();
        if (!response_in) {
            LOG(ERROR) << "addClass ACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE failed";
            return false;
        }

        auto cmdu_tx_header =
            cmdu_tx.create(beerocks_header->id(), ieee1905_1::eMessageType::ACK_MESSAGE);

        if (!cmdu_tx_header) {
            LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
            return false;
        }

        LOG(DEBUG) << "sending ACK message back to controller";
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE failed";
            return false;
        }
        LOG(INFO) << "ACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE, rep_mode="
                  << int(response_in->params().status_code);

        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::CLIENT_STEERING_BTM_REPORT_MESSAGE)) {
            LOG(ERROR) << "cmdu creation of type CLIENT_STEERING_BTM_REPORT_MESSAGE, has failed";
            return false;
        }
        auto steering_btm_report_tlv = cmdu_tx.addClass<wfa_map::tlvSteeringBTMReport>();
        if (!steering_btm_report_tlv) {
            LOG(ERROR) << "addClass wfa_map::tlvSteeringBTMReport failed";
            return false;
        }
        //TODO Add target BSSID
        steering_btm_report_tlv->sta_mac()         = response_in->params().mac;
        steering_btm_report_tlv->btm_status_code() = response_in->params().status_code;

        /*
            If ACTION_APMANAGER_CLIENT_BSS_STEER_RESPONSE contains
            non-zero MAC fill up BSSID (client associated with) for
            CLIENT_STEERING_BTM_REPORT_MESSAGE otherwise find BSSID
            in the AgentDB.
        */
        if (response_in->params().source_bssid != net::network_utils::ZERO_MAC) {
            steering_btm_report_tlv->bssid() = response_in->params().source_bssid;
        } else {
            auto agent_db = AgentDB::get();

            /*
                For finding BSSID in AgentDB need to find STA entry.
                STA entry can be found by checking associated clients list
                per radio.
            */
            steering_btm_report_tlv->bssid() = net::network_utils::ZERO_MAC;
            for (const auto &radio : agent_db->get_radios_list()) {
                auto sta =
                    find_if(radio->associated_clients.begin(), radio->associated_clients.end(),
                            [&](const std::pair<sMacAddr, AgentDB::sRadio::sClient> &sta) {
                                return sta.first == steering_btm_report_tlv->sta_mac();
                            });
                if (sta != radio->associated_clients.end()) {
                    steering_btm_report_tlv->bssid() = sta->second.bssid;
                    break;
                }
            }
        }

        LOG(DEBUG) << "sending CLIENT_STEERING_BTM_REPORT_MESSAGE back to controller";
        LOG(DEBUG) << "BTM report source bssid: " << steering_btm_report_tlv->bssid();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE: {
        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR)
                << "addClass ACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE failed";
            return false;
        }

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE>(
            cmdu_tx, beerocks_header->id());
        if (response_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE "
                          "message!";
            break;
        }
        LOG(INFO) << "ACTION_APMANAGER_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE";
        response_out->mac() = response_in->mac();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass ACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION failed";
            return false;
        }
        LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CAC_STARTED_NOTIFICATION";

        auto notification_out_bhm = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_DFS_CAC_STARTED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_bhm) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out_bhm->params() = notification_in->params();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass sACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION failed";
            return false;
        }
        LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION";

        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            return false;
        }

        radio->channel              = notification_in->params().channel;
        radio->bandwidth            = beerocks::eWiFiBandwidth(notification_in->params().bandwidth);
        radio->vht_center_frequency = notification_in->params().center_frequency1;
        radio->channel_ext_above_primary =
            radio->vht_center_frequency > wireless_utils::channel_to_freq(radio->channel);

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);

        send_operating_channel_report();

        auto notification_out_bhm = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_DFS_CAC_COMPLETED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_bhm) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out_bhm->params() = notification_in->params();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR)
                << "addClass cACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION failed";
            return false;
        }
        LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION";

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_DFS_CHANNEL_AVAILABLE_NOTIFICATION>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION failed";
            return false;
        }
        LOG(TRACE) << "received ACTION_APMANAGER_CLIENT_ASSOCIATED_NOTIFICATION";
        auto &client_mac = notification_in->mac();
        auto &bssid      = notification_in->bssid();
        LOG(INFO) << "Client associated sta_mac=" << client_mac << " to bssid=" << bssid;

        // Check if the client is an Multi-AP Agent, '0' means a regular station.
        if (notification_in->multi_ap_profile() != 0) {
            // TODO:
            // If the Multi-AP Agent supports "Combined Profile-1 and Profile-2" mode, need to
            // configure the bBSS to support it on L2.
        }

        if (!master_socket) {
            LOG(DEBUG) << "Controller is not connected";
            return true;
        }

        // Save information AgentDB
        auto db = AgentDB::get();
        db->erase_client(client_mac);

        // Set client association information for associated client
        auto radio = db->get_radio_by_mac(bssid, AgentDB::eMacType::BSSID);
        if (!radio) {
            LOG(DEBUG) << "Radio containing bssid " << bssid << " not found";
            break;
        }

        radio->associated_clients.emplace(
            client_mac, AgentDB::sRadio::sClient{bssid, notification_in->association_frame_length(),
                                                 notification_in->association_frame()});

        // build 1905.1 message CMDU to send to the controller
        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::TOPOLOGY_NOTIFICATION_MESSAGE)) {
            LOG(ERROR) << "cmdu creation of type TOPOLOGY_NOTIFICATION_MESSAGE, has failed";
            return false;
        }

        auto tlvAlMacAddress = cmdu_tx.addClass<ieee1905_1::tlvAlMacAddress>();
        if (!tlvAlMacAddress) {
            LOG(ERROR) << "addClass ieee1905_1::tlvAlMacAddress failed";
            return false;
        }
        tlvAlMacAddress->mac() = db->bridge.mac;

        auto client_association_event_tlv = cmdu_tx.addClass<wfa_map::tlvClientAssociationEvent>();
        if (!client_association_event_tlv) {
            LOG(ERROR) << "addClass tlvClientAssociationEvent failed";
            return false;
        }
        client_association_event_tlv->client_mac() = notification_in->mac();
        client_association_event_tlv->bssid()      = notification_in->bssid();
        client_association_event_tlv->association_event() =
            wfa_map::tlvClientAssociationEvent::CLIENT_HAS_JOINED_THE_BSS;

        if (!db->controller_info.prplmesh_controller) {
            LOG(DEBUG) << "non-prlMesh, not adding ClientAssociationEvent VS TLV";
        } else {
            // Add vendor specific tlv
            auto vs_tlv =
                message_com::add_vs_tlv<beerocks_message::tlvVsClientAssociationEvent>(cmdu_tx);

            if (!vs_tlv) {
                LOG(ERROR) << "add_vs_tlv tlvVsClientAssociationEvent failed";
                return false;
            }

            vs_tlv->mac()          = notification_in->mac();
            vs_tlv->bssid()        = notification_in->bssid();
            vs_tlv->vap_id()       = notification_in->vap_id();
            vs_tlv->capabilities() = notification_in->capabilities();
        }

        send_cmdu_to_controller(cmdu_tx);

        break;
    }
    case beerocks_message::ACTION_APMANAGER_STEERING_EVENT_PROBE_REQ_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_STEERING_EVENT_PROBE_REQ_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_STEERING_EVENT_PROBE_REQ_NOTIFICATION failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_EVENT_PROBE_REQ_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }

    case beerocks_message::ACTION_APMANAGER_STEERING_EVENT_AUTH_FAIL_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_STEERING_EVENT_AUTH_FAIL_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass "
                          "cACTION_APMANAGER_CLIENT_ScACTION_APMANAGER_STEERING_EVENT_AUTH_FAIL_"
                          "NOTIFICATIONOFTBLOCK_NOTIFICATION failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_EVENT_AUTH_FAIL_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CLIENT_DISCONNECT_RESPONSE: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_CLIENT_DISCONNECT_RESPONSE>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_CLIENT_DISCONNECT_RESPONSE failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_DISCONNECT_RESPONSE>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_STEERING_CLIENT_SET_RESPONSE: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_APMANAGER_STEERING_CLIENT_SET_RESPONSE>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_CLIENT_DISCONNECT_RESPONSE failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_RESPONSE>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_APMANAGER_CHANNELS_LIST_RESPONSE: {
        LOG(TRACE) << "received ACTION_APMANAGER_CHANNELS_LIST_RESPONSE";
        auto response =
            beerocks_header->addClass<beerocks_message::cACTION_APMANAGER_CHANNELS_LIST_RESPONSE>();
        if (!response) {
            LOG(ERROR) << "addClass cACTION_APMANAGER_CHANNELS_LIST_RESPONSE failed";
            return false;
        }

        fill_channel_list_to_agent_db(response->channel_list());

        // Forward channels list to the Backhaul manager
        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNELS_LIST_RESPONSE>(cmdu_tx);
        if (!response_out) {
            LOG(ERROR) << "Failed to build message";
            break;
        }
        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);

        // build channel preference report
        auto cmdu_tx_header = cmdu_tx.create(
            beerocks_header->id(), ieee1905_1::eMessageType::CHANNEL_PREFERENCE_REPORT_MESSAGE);

        if (!cmdu_tx_header) {
            LOG(ERROR) << "cmdu creation of type CHANNEL_PREFERENCE_REPORT_MESSAGE, has failed";
            return false;
        }

        auto preferences = get_channel_preferences_from_channels_list();

        auto channel_preference_tlv = cmdu_tx.addClass<wfa_map::tlvChannelPreference>();
        if (!channel_preference_tlv) {
            LOG(ERROR) << "addClass ieee1905_1::tlvChannelPreference has failed";
            return false;
        }

        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            return false;
        }
        channel_preference_tlv->radio_uid() = radio->front.iface_mac;

        for (const auto &preference : preferences) {
            // Create operating class object
            auto op_class_channels = channel_preference_tlv->create_operating_classes_list();
            if (!op_class_channels) {
                LOG(ERROR) << "create_operating_classes_list() has failed!";
                return false;
            }
            // TODO: check that the data is parsed properly after fixing the following bug:
            // Since sFlags is defined after dynamic list cPreferenceOperatingClasses it cause data override
            // on the first channel on the list and sFlags itself.
            // See: https://github.com/prplfoundation/prplMesh/issues/8

            auto &operating_class_info           = preference.first;
            auto &operating_class_channels_list  = preference.second;
            op_class_channels->operating_class() = operating_class_info.operating_class;
            if (!op_class_channels->alloc_channel_list(operating_class_channels_list.size())) {
                LOG(ERROR) << "alloc_channel_list() has failed!";
                return false;
            }

            uint8_t idx = 0;
            for (auto channel : operating_class_channels_list) {
                *op_class_channels->channel_list(idx) = channel;
                idx++;
            }

            // Update channel list flags
            op_class_channels->flags() = operating_class_info.flags;

            // Push operating class object to the list of operating class objects
            if (!channel_preference_tlv->add_operating_classes_list(op_class_channels)) {
                LOG(ERROR) << "add_operating_classes_list() has failed!";
                return false;
            }
        }

        // cac tlvs //

        // create status report
        auto cac_status_report_tlv = cmdu_tx.addClass<wfa_map::tlvProfile2CacStatusReport>();
        if (!cac_status_report_tlv) {
            LOG(ERROR) << "Failed to create cac-status-report-tlv";
            return false;
        }

        CacStatusDatabase cac_status_database;

        // fill status report
        auto available_channels =
            cac_status_database.get_available_channels(radio->front.iface_mac);

        if (!cac_status_report_tlv->alloc_available_channels(available_channels.size())) {
            LOG(ERROR) << "Failed to allocate " << available_channels.size()
                       << " structures for available channels";
            return false;
        }
        for (unsigned int i = 0; i < available_channels.size(); ++i) {
            auto &available_ref = std::get<1>(cac_status_report_tlv->available_channels(i));
            available_ref.operating_class = available_channels[i].operating_class;
            available_ref.channel         = available_channels[i].channel;
            available_ref.minutes_since_cac_completion =
                std::chrono::duration_cast<std::chrono::minutes>(available_channels[i].duration)
                    .count();
        }

        // TODO
        // Complete status report
        // https://jira.prplfoundation.org/browse/PPM-1089

        // create completion report
        auto cac_completion_report_tlv =
            cmdu_tx.addClass<wfa_map::tlvProfile2CacCompletionReport>();
        if (!cac_completion_report_tlv) {
            LOG(ERROR) << "Failed to create cac-completion-report-tlv";
            return false;
        }

        // fill completion report
        auto cac_radio = cac_completion_report_tlv->create_cac_radios();
        if (!cac_radio) {
            LOG(ERROR) << "Failed to create cac radio for " << radio->front.iface_mac;
            return false;
        }
        cac_radio->radio_uid() = radio->front.iface_mac;

        const auto &cac_completion =
            cac_status_database.get_completion_status(radio->front.iface_mac);

        cac_radio->operating_class()       = cac_completion.first.operating_class;
        cac_radio->channel()               = cac_completion.first.channel;
        cac_radio->cac_completion_status() = cac_completion.first.completion_status;

        if (!cac_completion.second.empty()) {
            cac_radio->alloc_detected_pairs(cac_completion.second.size());
            for (unsigned int i = 0; i < cac_completion.second.size(); ++i) {
                if (std::get<0>(cac_radio->detected_pairs(i))) {
                    auto &cac_detected_pair = std::get<1>(cac_radio->detected_pairs(i));
                    cac_detected_pair.operating_class_detected = cac_completion.second[i].first;
                    cac_detected_pair.channel_detected         = cac_completion.second[i].second;
                }
            }
        }

        cac_completion_report_tlv->add_cac_radios(cac_radio);

        LOG(DEBUG) << "sending channel preference report for ruid=" << radio->front.iface_mac;

        send_cmdu_to_controller(cmdu_tx);

        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE: {
        // no more configuration
        configuration_in_progress = false;

        LOG(DEBUG) << "received ACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE";
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE>();
        if (!response_in) {
            LOG(ERROR) << "addClass cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE failed";
            return false;
        }

        // report about the status
        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE>(cmdu_tx);
        if (!response_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        response_out->success() = response_in->success();

        LOG(DEBUG) << "send cACTION_BACKHAUL_HOSTAP_CANCEL_ACTIVE_CAC_RESPONSE";
        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);

        // take actions when the cancelation failed
        if (!response_in->success()) {
            LOG(ERROR) << "cancel active cac failed - resetting the slave";
            slave_reset();
        }

        break;
    }
    case beerocks_message::ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE>();
        if (!notification_in) {
            LOG(ERROR)
                << "addClass ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE failed";
            return false;
        }
        LOG(TRACE) << "received ACTION_APMANAGER_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE";

        auto notification_out_bhm = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_HOSTAP_ZWDFS_ANT_CHANNEL_SWITCH_RESPONSE>(cmdu_tx);
        if (!notification_out_bhm) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out_bhm->success() = notification_in->success();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    default: {
        LOG(ERROR) << "Unknown AP_MANAGER message, action_op: "
                   << int(beerocks_header->action_op());
        return false;
    }
    }

    return true;
}

bool slave_thread::handle_cmdu_monitor_message(Socket *sd,
                                               std::shared_ptr<beerocks_header> beerocks_header)
{
    if (monitor_socket == nullptr) {
        if (beerocks_header->action_op() != beerocks_message::ACTION_MONITOR_JOINED_NOTIFICATION) {
            LOG(ERROR) << "Not MONITOR_JOINED_NOTIFICATION, action_op: "
                       << int(beerocks_header->action_op());
            return true;
        }
    } else if (monitor_socket != sd) {
        LOG(WARNING) << "Unknown socket, ACTION_MONITOR action_op: "
                     << int(beerocks_header->action_op());
        return true;
    } else if (beerocks_header->action_op() ==
               beerocks_message::ACTION_MONITOR_HEARTBEAT_NOTIFICATION) {
        monitor_last_seen       = std::chrono::steady_clock::now();
        monitor_retries_counter = 0;
        return true;
    } else if (master_socket == nullptr) {
        LOG(WARNING) << "master_socket == nullptr, MONITOR action_op: "
                     << int(beerocks_header->action_op());
    }

    switch (beerocks_header->action_op()) {
    case beerocks_message::ACTION_MONITOR_JOINED_NOTIFICATION: {
        LOG(DEBUG) << "Received ACTION_MONITOR_JOINED_NOTIFICATION";
        if (slave_state != STATE_WAIT_FOR_FRONTHAUL_THREADS_JOINED) {
            LOG(WARNING) << "ACTION_MONITOR_JOINED_NOTIFICATION, but slave_state != "
                            "STATE_WAIT_FOR_FRONTHAUL_THREADS_JOINED";
        }

        if (monitor_socket) {
            LOG(ERROR) << "Monitor opened a new socket altough there is already open socket to it";
            remove_socket(monitor_socket);
            delete monitor_socket;
            monitor_socket = nullptr;
        }

        monitor_socket = sd;
        break;
    }
    case beerocks_message::ACTION_MONITOR_HOSTAP_AP_DISABLED_NOTIFICATION: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_HOSTAP_AP_DISABLED_NOTIFICATION>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_HOSTAP_AP_DISABLED_NOTIFICATION failed";
            return false;
        }
        LOG(INFO) << "received ACTION_MONITOR_HOSTAP_AP_DISABLED_NOTIFICATION";
        if (response_in->vap_id() == beerocks::IFACE_RADIO_ID) {
            LOG(WARNING) << __FUNCTION__ << "AP_Disabled on radio, slave reset";
            if (configuration_in_progress) {
                LOG(INFO) << "configuration is in progress, ignoring";
                detach_on_conf_change = true;
                break;
            }
            slave_reset();
        }
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_START_MONITORING_RESPONSE: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CLIENT_START_MONITORING_RESPONSE>();
        if (!response_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CLIENT_START_MONITORING_RESPONSE failed";
            break;
        }

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_START_MONITORING_RESPONSE>(
            cmdu_tx, beerocks_header->id());
        if (!response_out) {
            LOG(ERROR)
                << "Failed building cACTION_CONTROL_CLIENT_START_MONITORING_RESPONSE message!";
            break;
        }
        response_out->success() = response_in->success();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE failed";
            break;
        }
        LOG(INFO) << "ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE mac="
                  << response_in->params().result.mac
                  << " rx_rssi=" << int(response_in->params().rx_rssi)
                  << " id=" << int(beerocks_header->id());

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE>(
            cmdu_tx, beerocks_header->id());
        if (response_out == nullptr) {
            LOG(ERROR)
                << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE message!";
            break;
        }

        response_out->params()            = response_in->params();
        response_out->params().src_module = beerocks::BEEROCKS_ENTITY_MONITOR;
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR)
                << "addClass ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION failed";
            break;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_START_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR)
                << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_RESPONSE message!";
            break;
        }
        notification_out->mac() = notification_in->mac();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_HOSTAP_STATS_MEASUREMENT_RESPONSE: {
        /*
             * the following code will break if the structure of
             * message::sACTION_MONITOR_HOSTAP_STATS_MEASUREMENT_RESPONSE
             * will be different from
             * message::sACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_RESPONSE
             */

        // LOG(DEBUG) << "Received ACTION_MONITOR_HOSTAP_STATS_MEASUREMENT_RESPONSE"; // the print is flooding the log

        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_HOSTAP_STATS_MEASUREMENT_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_HOSTAP_STATS_MEASUREMENT_RESPONSE failed";
            return false;
        }

        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_RESPONSE>(
            cmdu_tx, beerocks_header->id());
        if (response_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        auto ap_stats_size = response_in->ap_stats_size();
        if (ap_stats_size > 0) {
            if (!response_out->alloc_ap_stats(ap_stats_size)) {
                LOG(ERROR) << "Failed buffer allocation to size=" << int(ap_stats_size);
                break;
            }
            auto ap_stats_tuple_in  = response_in->ap_stats(0);
            auto ap_stats_tuple_out = response_out->ap_stats(0);
            std::copy_n(&std::get<1>(ap_stats_tuple_in), ap_stats_size,
                        &std::get<1>(ap_stats_tuple_out));
        }

        auto sta_stats_size = response_in->sta_stats_size();
        if (sta_stats_size > 0) {
            if (!response_out->alloc_sta_stats(sta_stats_size)) {
                LOG(ERROR) << "Failed buffer allocation to size=" << int(sta_stats_size);
                break;
            }
            auto sta_stats_tuple_in  = response_in->sta_stats(0);
            auto sta_stats_tuple_out = response_out->sta_stats(0);
            std::copy_n(&std::get<1>(sta_stats_tuple_in), sta_stats_size,
                        &std::get<1>(sta_stats_tuple_out));
        }

        // LOG(DEBUG) << "send ACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_RESPONSE"; // the print is flooding the log

        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_ASSOCIATED_STA_LINK_METRIC_RESPONSE: {
        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_CLIENT_ASSOCIATED_STA_LINK_METRIC_RESPONSE>();
        if (!response_in) {
            LOG(ERROR)
                << "addClass ACTION_MONITOR_CLIENT_ASSOCIATED_STA_LINK_METRIC_RESPONSE failed";
            return false;
        }
        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_RESPONSE>(
            cmdu_tx, beerocks_header->id());
        if (response_out == nullptr) {
            LOG(ERROR)
                << "Failed building ACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_RESPONSE message!";
            break;
        }

        if (!response_out->alloc_bssid_info_list(response_in->bssid_info_list_length())) {
            LOG(ERROR) << "alloc_per_bss_sta_link_metrics failed";
            return false;
        }

        response_out->sta_mac() = response_in->sta_mac();

        for (size_t i = 0; i < response_out->bssid_info_list_length(); ++i) {
            auto &bss_in  = std::get<1>(response_in->bssid_info_list(i));
            auto &bss_out = std::get<1>(response_out->bssid_info_list(i));

            bss_out = bss_in;
        }

        LOG(DEBUG) << "Send ACTION_BACKHAUL_ASSOCIATED_STA_LINK_METRICS_RESPONSE";
        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_HOSTAP_LOAD_MEASUREMENT_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_HOSTAP_LOAD_MEASUREMENT_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_HOSTAP_LOAD_MEASUREMENT_NOTIFICATION failed";
            return false;
        }
        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_LOAD_MEASUREMENT_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());
        if (!notification_out) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_NO_RESPONSE_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CLIENT_NO_RESPONSE_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_MONITOR_CLIENT_NO_RESPONSE_NOTIFICATION failed";
            break;
        }
        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_NO_RESPONSE_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_NO_RESPONSE_NOTIFICATION message!";
            break;
        }
        notification_out->mac() = notification_in->mac();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_BEACON_11K_RESPONSE: {
        int mid = int(beerocks_header->id());
        LOG(TRACE) << "ACTION_MONITOR_CLIENT_BEACON_11K_RESPONSE id: 0x" << std::hex << mid;

        // flow:
        // 1. extract data from response_in (vendor specific response) and build
        // with the extracted data 1905 reponse_out message
        // 2. send ALSO vs response.
        // The reason for sending _both_ responses is because the 1905 response
        // does not contain the data itself, it is being sent just to pass certification tests

        // response in
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CLIENT_BEACON_11K_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_MONITOR_CLIENT_BEACON_11K_RESPONSE failed";
            break;
        }

        // old vs response:
        auto response_out_vs = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_BEACON_11K_RESPONSE>(cmdu_tx,
                                                                          beerocks_header->id());
        if (response_out_vs == nullptr) {
            LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_BEACON_11K_RESPONSE message!";
            break;
        }
        response_out_vs->params() = response_in->params();

        send_cmdu_to_controller(cmdu_tx);
        // end old response

        // new 1905 response:
        if (!cmdu_tx.create(mid, ieee1905_1::eMessageType::BEACON_METRICS_RESPONSE_MESSAGE)) {
            LOG(ERROR) << "cmdu creation of type BEACON_METRICS_RESPONSE_MESSAGE, has failed";
            return false;
        }

        auto response_out_1905 = cmdu_tx.addClass<wfa_map::tlvBeaconMetricsResponse>();
        if (response_out_1905 == nullptr) {
            LOG(ERROR) << "addClass wfa_map::tlvBeaconMetricsResponse failed";
            return false;
        }

        if (!gate::load(cmdu_tx, response_in)) {
            LOG(ERROR) << "unable to load vs beacon response into 1905";
            return false;
        }

        send_cmdu_to_controller(cmdu_tx);
        // end new 1905 response

        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE: {
        LOG(INFO) << "ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE: action_op: "
                  << int(beerocks_header->action_op());
        auto response_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE>();
        if (response_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE failed";
            break;
        }
        auto response_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE>(
            cmdu_tx, beerocks_header->id());
        if (response_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_CMD_RESPONSE "
                          "message!";
            break;
        }
        response_out->mac() = response_in->mac();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_NO_ACTIVITY_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CLIENT_NO_ACTIVITY_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass ACTION_MONITOR_CLIENT_NO_ACTIVITY_NOTIFICATION failed";
            break;
        }
        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_NO_ACTIVITY_NOTIFICATION>(
            cmdu_tx, beerocks_header->id());
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building ACTION_CONTROL_CLIENT_NO_ACTIVITY_NOTIFICATION message!";
            break;
        }
        // Only mac id is the part of notification now, if this changes in future this message will break
        notification_out->mac() = notification_in->mac();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_HOSTAP_ACTIVITY_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_HOSTAP_ACTIVITY_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_HOSTAP_ACTIVITY_NOTIFICATION failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_HOSTAP_ACTIVITY_NOTIFICATION>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CLIENT_RX_RSSI_MEASUREMENT_NOTIFICATION failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_NOTIFICATION>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR)
                << "addClass cACTION_MONITOR_STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building  "
                          "cACTION_CONTROL_STEERING_EVENT_CLIENT_ACTIVITY_NOTIFICATION message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_STEERING_EVENT_SNR_XING_NOTIFICATION: {
        auto notification_in = beerocks_header->addClass<
            beerocks_message::cACTION_MONITOR_STEERING_EVENT_SNR_XING_NOTIFICATION>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_STEERING_EVENT_SNR_XING_NOTIFICATION failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_EVENT_SNR_XING_NOTIFICATION>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR)
                << "Failed building cACTION_CONTROL_STEERING_EVENT_SNR_XING_NOTIFICATION message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_STEERING_CLIENT_SET_GROUP_RESPONSE: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_STEERING_CLIENT_SET_GROUP_RESPONSE>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_STEERING_CLIENT_SET_GROUP_RESPONSE failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_RESPONSE>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR)
                << "Failed building cACTION_CONTROL_STEERING_CLIENT_SET_GROUP_RESPONSE message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_STEERING_CLIENT_SET_RESPONSE: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_STEERING_CLIENT_SET_RESPONSE>();
        if (notification_in == nullptr) {
            LOG(ERROR) << "addClass cACTION_MONITOR_STEERING_CLIENT_SET_RESPONSE failed";
            return false;
        }

        auto notification_out = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_STEERING_CLIENT_SET_RESPONSE>(cmdu_tx);
        if (notification_out == nullptr) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_STEERING_CLIENT_SET_RESPONSE message!";
            return false;
        }
        notification_out->params() = notification_in->params();
        send_cmdu_to_controller(cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE>();
        if (!response_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE failed";
            return false;
        }

        auto response_out_controller = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE>(cmdu_tx);
        if (!response_out_controller) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE";
            return false;
        }

        response_out_controller->success() = response_in->success();

        send_cmdu_to_controller(cmdu_tx);

        auto response_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE>(cmdu_tx);
        if (!response_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGER_SCAN_RESPONSE";
            return false;
        }

        response_out_backhaul->success() = response_in->success();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE>();
        if (!response_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE failed";
            return false;
        }

        auto response_out_controller = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE>(cmdu_tx);
        if (!response_out_controller) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE";
            return false;
        }

        response_out_controller->success() = response_in->success();

        send_cmdu_to_controller(cmdu_tx);

        auto response_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE>(cmdu_tx);
        if (!response_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_DUMP_RESULTS_RESPONSE";
            return false;
        }

        response_out_backhaul->success() = response_in->success();

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_ABORT_RESPONSE: {
        auto response_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_ABORT_RESPONSE>();
        if (!response_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_ABORT_RESPONSE failed";
            return false;
        }

        auto response_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_RESPONSE>(cmdu_tx);
        if (!response_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_ABORT_RESPONSE";
            return false;
        }

        response_out_backhaul->success() = response_in->success();
        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_TRIGGERED_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_TRIGGERED_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_TRIGGERED_NOTIFICATION failed";
            return false;
        }

        auto notification_out_controller = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_controller) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION !";
            return false;
        }
        send_cmdu_to_controller(cmdu_tx);

        auto notification_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_TRIGGERED_NOTIFICATION !";
            return false;
        }

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_RESULTS_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_RESULTS_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_RESULTS_NOTIFICATION failed";
            return false;
        }

        auto notification_out_controller = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_RESULTS_NOTIFICATION>(cmdu_tx);
        if (!notification_out_controller) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_CHANNEL_SCAN_RESULTS_NOTIFICATION !";
            return false;
        }

        notification_out_controller->scan_results() = notification_in->scan_results();
        notification_out_controller->is_dump()      = notification_in->is_dump();

        send_cmdu_to_controller(cmdu_tx);

        auto notification_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_RESULTS_NOTIFICATION>(cmdu_tx);
        if (!notification_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_RESULTS_NOTIFICATION !";
            return false;
        }

        notification_out_backhaul->scan_results() = notification_in->scan_results();
        notification_out_backhaul->is_dump()      = notification_in->is_dump();
        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_FINISHED_NOTIFICATION: {
        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_FINISHED_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_FINISHED_NOTIFICATION failed";
            return false;
        }

        auto notification_out_controller = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_FINISHED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_controller) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_CHANNEL_SCAN_FINISHED_NOTIFICATION !";
            return false;
        }

        send_cmdu_to_controller(cmdu_tx);

        auto notification_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_FINISHED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_FINISHED_NOTIFICATION !";
            return false;
        }

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    case beerocks_message::ACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION: {

        LOG(DEBUG) << "Received ACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION";

        auto notification_in =
            beerocks_header
                ->addClass<beerocks_message::cACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION>();
        if (!notification_in) {
            LOG(ERROR) << "addClass cACTION_MONITOR_CHANNEL_SCAN_ABORTED_NOTIFICATION failed";
            return false;
        }

        auto notification_out_controller = message_com::create_vs_message<
            beerocks_message::cACTION_CONTROL_CHANNEL_SCAN_ABORT_NOTIFICATION>(cmdu_tx);
        if (!notification_out_controller) {
            LOG(ERROR) << "Failed building cACTION_CONTROL_CHANNEL_SCAN_ABORT_NOTIFICATION!";
            return false;
        }

        send_cmdu_to_controller(cmdu_tx);

        auto notification_out_backhaul = message_com::create_vs_message<
            beerocks_message::cACTION_BACKHAUL_CHANNEL_SCAN_ABORTED_NOTIFICATION>(cmdu_tx);
        if (!notification_out_backhaul) {
            LOG(ERROR) << "Failed building cACTION_BACKHAUL_CHANNEL_SCAN_ABORTED_NOTIFICATION!";
            return false;
        }

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        break;
    }
    default: {
        LOG(ERROR) << "Unknown MONITOR message, action_op: " << int(beerocks_header->action_op());
        return false;
    }
    }

    return true;
}

bool slave_thread::slave_fsm(bool &call_slave_select)
{
    bool slave_ok = true;

    switch (slave_state) {
    case STATE_WAIT_BEFORE_INIT: {
        if (std::chrono::steady_clock::now() > slave_state_timer) {
            is_backhaul_disconnected = false;
            LOG(TRACE) << "goto STATE_INIT";
            slave_state = STATE_INIT;
        }
        break;
    }
    case STATE_INIT: {
        LOG(INFO) << "STATE_INIT";

        auto db = AgentDB::get();
        std::string iface_mac;
        if (!network_utils::linux_iface_get_mac(db->bridge.iface_name, iface_mac)) {
            LOG(ERROR) << "Failed reading addresses from the bridge!";
            platform_notify_error(bpl::eErrorCode::BH_READING_DATA_FROM_THE_BRIDGE, "");
            m_stop_on_failure_attempts--;
            slave_reset();
            break;
        }

        // Update bridge parameters on AgentDB.
        db->bridge.mac = tlvf::mac_from_string(iface_mac);

        // On GW Platform, we clear the WAN interface from the database, once getting the
        // configuration from the Platform Manager. Since we initialize the local_gw flag later,
        // check if the WAN interface is empty instead of the local_gw flag.
        if (!db->ethernet.wan.iface_name.empty()) {
            if (!network_utils::linux_iface_get_mac(db->ethernet.wan.iface_name, iface_mac)) {
                LOG(ERROR) << "Failed reading wan mac address! iface="
                           << db->ethernet.wan.iface_name;
                m_stop_on_failure_attempts--;
                slave_reset();
            }

            // Update wan parameters on AgentDB.
            db->ethernet.wan.mac = tlvf::mac_from_string(iface_mac);
        }

        // Reset the traffic separation configuration as they will be reconfigured on
        // autoconfiguration.
        TrafficSeparation::traffic_seperation_configuration_clear();

        // Clear the channel_list
        // When FCC/ETSI is set, the prplmesh is not restarted, but the salve is.
        // Must clear the map to prevent residues of previous country configuration.
        // This is needed since the map is not cleared when read.
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(FATAL) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }
        radio->channels_list.clear();

        m_autoconfiguration_completed = false;

        slave_state = STATE_CONNECT_TO_PLATFORM_MANAGER;
        break;
    }
    case STATE_CONNECT_TO_PLATFORM_MANAGER: {
        platform_manager_socket = new SocketClient(platform_manager_uds);
        std::string err         = platform_manager_socket->getError();
        if (!err.empty()) {
            delete platform_manager_socket;
            platform_manager_socket = nullptr;

            LOG(WARNING) << "Unable to connect to Platform Manager: " << err;
            if (++connect_platform_retry_counter >= CONNECT_PLATFORM_RETRY_COUNT_MAX) {
                LOG(ERROR) << "Failed connecting to Platform Manager! Resetting...";
                platform_notify_error(bpl::eErrorCode::SLAVE_FAILED_CONNECT_TO_PLATFORM_MANAGER,
                                      "");
                m_stop_on_failure_attempts--;
                slave_reset();
                connect_platform_retry_counter = 0;
            } else {
                LOG(INFO) << "Retrying in " << CONNECT_PLATFORM_RETRY_SLEEP << " milliseconds...";
                UTILS_SLEEP_MSEC(CONNECT_PLATFORM_RETRY_SLEEP);
                break;
            }

        } else {
            add_socket(platform_manager_socket);

            // CMDU Message
            auto request = message_com::create_vs_message<
                beerocks_message::cACTION_PLATFORM_SON_SLAVE_REGISTER_REQUEST>(cmdu_tx);

            if (request == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            string_utils::copy_string(request->iface_name(message::IFACE_NAME_LENGTH),
                                      config.hostap_iface.c_str(), message::IFACE_NAME_LENGTH);
            message_com::send_cmdu(platform_manager_socket, cmdu_tx);

            LOG(TRACE) << "send ACTION_PLATFORM_SON_SLAVE_REGISTER_REQUEST";
            LOG(TRACE) << "goto STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE";
            slave_state_timer =
                std::chrono::steady_clock::now() +
                std::chrono::seconds(WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE_TIMEOUT_SEC);
            slave_state = STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE;
        }
        break;
    }
    case STATE_WAIT_FOR_PLATFORM_MANAGER_CREDENTIALS_UPDATE_RESPONSE: {
        break;
    }
    case STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE: {
        if (std::chrono::steady_clock::now() > slave_state_timer) {
            LOG(ERROR) << "STATE_WAIT_FOR_PLATFORM_MANAGER_REGISTER_RESPONSE timeout!";
            platform_notify_error(bpl::eErrorCode::SLAVE_PLATFORM_MANAGER_REGISTER_TIMEOUT, "");
            m_stop_on_failure_attempts--;
            slave_reset();
        }
        break;
    }
    case STATE_CONNECT_TO_BACKHAUL_MANAGER: {
        if (backhaul_manager_socket == nullptr) {
            LOG(DEBUG) << "create backhaul_manager_socket";
            backhaul_manager_socket = new SocketClient(backhaul_manager_uds);
            std::string err         = backhaul_manager_socket->getError();
            if (!err.empty()) {
                LOG(ERROR) << "backhaul_manager_socket: " << err;
                backhaul_manager_stop();
                platform_notify_error(bpl::eErrorCode::SLAVE_CONNECTING_TO_BACKHAUL_MANAGER,
                                      "iface=" + config.backhaul_wireless_iface);
                m_stop_on_failure_attempts--;
                slave_reset();
                break;
            } else {
                add_socket(backhaul_manager_socket);
            }
        } else {
            LOG(DEBUG) << "using existing backhaul_manager_socket=0x"
                       << intptr_t(backhaul_manager_socket);
        }

        // CMDU Message
        auto request =
            message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_REGISTER_REQUEST>(
                cmdu_tx);

        if (request == nullptr) {
            LOG(ERROR) << "Failed building message!";
            break;
        }

        auto db = AgentDB::get();

        if (db->device_conf.local_gw || config.backhaul_wireless_iface.empty()) {
            memset(request->sta_iface(message::IFACE_NAME_LENGTH), 0, message::IFACE_NAME_LENGTH);
        } else {
            string_utils::copy_string(request->sta_iface(message::IFACE_NAME_LENGTH),
                                      config.backhaul_wireless_iface.c_str(),
                                      message::IFACE_NAME_LENGTH);
        }
        string_utils::copy_string(request->hostap_iface(message::IFACE_NAME_LENGTH),
                                  config.hostap_iface.c_str(), message::IFACE_NAME_LENGTH);

        request->onboarding() = 0;

        LOG(INFO) << "ACTION_BACKHAUL_REGISTER_REQUEST "
                  << " hostap_iface=" << request->hostap_iface(message::IFACE_NAME_LENGTH)
                  << " sta_iface=" << request->sta_iface(message::IFACE_NAME_LENGTH)
                  << " onboarding=" << int(request->onboarding());

        message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);
        LOG(TRACE) << "send ACTION_BACKHAUL_REGISTER_REQUEST";
        LOG(TRACE) << "goto STATE_WAIT_FOR_BACKHAUL_MANAGER_REGISTER_RESPONSE";
        slave_state = STATE_WAIT_FOR_BACKHAUL_MANAGER_REGISTER_RESPONSE;

        break;
    }
    case STATE_WAIT_RETRY_CONNECT_TO_BACKHAUL_MANAGER: {
        if (std::chrono::steady_clock::now() > slave_state_timer) {
            LOG(DEBUG) << "retrying to connect connecting to backhaul manager";
            LOG(TRACE) << "goto STATE_CONNECT_TO_BACKHAUL_MANAGER";
            slave_state = STATE_CONNECT_TO_BACKHAUL_MANAGER;
        }
        break;
    }
    case STATE_WAIT_FOR_BACKHAUL_MANAGER_REGISTER_RESPONSE: {
        break;
    }
    case STATE_JOIN_INIT: {

        auto db = AgentDB::get();
        if (!db->device_conf.front_radio.config[config.hostap_iface].band_enabled) {
            LOG(DEBUG) << "wlan_settings.band_enabled=false";
            LOG(TRACE) << "goto STATE_BACKHAUL_ENABLE";
            slave_state = STATE_BACKHAUL_ENABLE;
            break;
        }

        if (!db->device_conf.local_gw) {
            is_backhaul_manager = false;
        }

        auto radio = db->radio(m_fronthaul_iface);
        if (radio) {
            // Set zwdfs to initial value.
            radio->front.zwdfs = false;
        }
        fronthaul_start();

        is_slave_reset = false;

        LOG(TRACE) << "goto STATE_WAIT_FOR_FRONTHAUL_THREADS_JOINED";
        slave_state = STATE_WAIT_FOR_FRONTHAUL_THREADS_JOINED;
        break;
    }
    case STATE_WAIT_FOR_FRONTHAUL_THREADS_JOINED: {
        if (ap_manager_socket && monitor_socket) {
            LOG(TRACE) << "goto STATE_BACKHAUL_ENABLE";
            slave_state = STATE_BACKHAUL_ENABLE;
            break;
        }
        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (radio && radio->front.zwdfs && ap_manager_socket) {
            auto request = message_com::create_vs_message<
                beerocks_message::cACTION_BACKHAUL_ZWDFS_RADIO_DETECTED>(cmdu_tx);

            if (!request) {
                LOG(ERROR) << "Failed building message!";
                break;
            }
            request->set_front_iface_name(m_fronthaul_iface);
            LOG(DEBUG) << "send ACTION_BACKHAUL_ZWDFS_RADIO_DETECTED for mac " << m_fronthaul_iface;
            message_com::send_cmdu(backhaul_manager_socket, cmdu_tx);

            db->remove_radio_from_radios_list(m_fronthaul_iface);

            LOG(TRACE) << "goto STATE_PRE_OPERATIONAL";
            slave_state = STATE_PRE_OPERATIONAL;
            break;
        }
        break;
    }
    case STATE_BACKHAUL_ENABLE: {
        bool error = false;
        auto db    = AgentDB::get();

        if (db->device_conf.local_gw) {
            LOG(TRACE) << "goto STATE_SEND_BACKHAUL_MANAGER_ENABLE";
            slave_state = STATE_SEND_BACKHAUL_MANAGER_ENABLE;
            break;
        }

        if (db->ethernet.wan.iface_name.empty() && config.backhaul_wireless_iface.empty()) {
            LOG(DEBUG) << "No valid backhaul iface!";
            platform_notify_error(bpl::eErrorCode::CONFIG_NO_VALID_BACKHAUL_INTERFACE, "");
            error = true;
        }

        if (error) {
            m_stop_on_failure_attempts--;
            slave_reset();
        } else {
            // backhaul manager will request for backhaul iface and tx enable after receiving ACTION_BACKHAUL_ENABLE,
            // when wireless connection is required
            LOG(TRACE) << "goto STATE_SEND_BACKHAUL_MANAGER_ENABLE";
            slave_state = STATE_SEND_BACKHAUL_MANAGER_ENABLE;
        }
        break;
    }
    case STATE_SEND_BACKHAUL_MANAGER_ENABLE: {

        // CMDU Message
        auto bh_enable =
            message_com::create_vs_message<beerocks_message::cACTION_BACKHAUL_ENABLE>(cmdu_tx);
        if (bh_enable == nullptr) {
            LOG(ERROR) << "Failed building message!";
            break;
        }

        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }

        if (!db->device_conf.local_gw) {
            // Wireless config

            // TODO: On passive mode, mem_only_psk is always be set, so supplying the credentials
            // to the backhaul manager will no longer be necessary, and therefore should be be
            // removed completely from beerocks including the BPL.

            string_utils::copy_string(bh_enable->wire_iface(message::IFACE_NAME_LENGTH),
                                      db->ethernet.wan.iface_name.c_str(),
                                      message::IFACE_NAME_LENGTH);
        }

        bh_enable->iface_mac() = radio->front.iface_mac;

        string_utils::copy_string(bh_enable->sta_iface(message::IFACE_NAME_LENGTH),
                                  config.backhaul_wireless_iface.c_str(),
                                  message::IFACE_NAME_LENGTH);

        // Send the message
        LOG(DEBUG) << "send ACTION_BACKHAUL_ENABLE for mac " << bh_enable->iface_mac();
        if (!message_com::send_cmdu(backhaul_manager_socket, cmdu_tx)) {
            slave_reset();
        }

        // Next state
        LOG(TRACE) << "goto STATE_WAIT_FOR_BACKHAUL_MANAGER_CONNECTED_NOTIFICATION";
        slave_state = STATE_WAIT_FOR_BACKHAUL_MANAGER_CONNECTED_NOTIFICATION;
        break;
    }
    case STATE_WAIT_FOR_BACKHAUL_MANAGER_CONNECTED_NOTIFICATION: {
        break;
    }
    case STATE_WAIT_BACKHAUL_MANAGER_BUSY: {
        if (std::chrono::steady_clock::now() > slave_state_timer) {
            LOG(TRACE) << "goto STATE_SEND_BACKHAUL_MANAGER_ENABLE";
            slave_state = STATE_SEND_BACKHAUL_MANAGER_ENABLE;
        }
        break;
    }
    case STATE_BACKHAUL_MANAGER_CONNECTED: {
        LOG(TRACE) << "MASTER_CONNECTED";

        master_socket = backhaul_manager_socket;

        auto db = AgentDB::get();
        if (!db->device_conf.front_radio.config[config.hostap_iface].band_enabled) {
            LOG(TRACE) << "goto STATE_PRE_OPERATIONAL";
            slave_state = STATE_PRE_OPERATIONAL;
            break;
        }

        if (db->device_conf.local_gw) {
            //TODO get bridge_iface from platform manager
            network_utils::iface_info bridge_info;
            network_utils::get_iface_info(bridge_info, db->bridge.iface_name);

            backhaul_params.bridge_ipv4    = bridge_info.ip;
            backhaul_params.backhaul_iface = db->bridge.iface_name;
            backhaul_params.backhaul_mac   = bridge_info.mac;
            backhaul_params.backhaul_ipv4  = bridge_info.ip;
            backhaul_params.backhaul_bssid = network_utils::ZERO_MAC_STRING;
            // backhaul_params.backhaul_freq           = 0; // HACK temp disabled because of a bug on endian converter
            backhaul_params.backhaul_channel     = 0;
            backhaul_params.backhaul_is_wireless = 0;
            backhaul_params.backhaul_iface_type  = beerocks::IFACE_TYPE_GW_BRIDGE;
            if (is_backhaul_manager) {
                backhaul_params.backhaul_iface = db->ethernet.wan.iface_name;
            }
        }

        LOG(INFO) << "Backhaul Params Info:";
        LOG(INFO) << "controller_bridge_mac=" << db->controller_info.bridge_mac;
        LOG(INFO) << "prplmesh_controller=" << db->controller_info.prplmesh_controller;
        LOG(INFO) << "bridge_mac=" << db->bridge.mac;
        LOG(INFO) << "bridge_ipv4=" << backhaul_params.bridge_ipv4;
        LOG(INFO) << "backhaul_iface=" << backhaul_params.backhaul_iface;
        LOG(INFO) << "backhaul_mac=" << backhaul_params.backhaul_mac;
        LOG(INFO) << "backhaul_ipv4=" << backhaul_params.backhaul_ipv4;
        LOG(INFO) << "backhaul_bssid=" << backhaul_params.backhaul_bssid;
        LOG(INFO) << "backhaul_channel=" << int(backhaul_params.backhaul_channel);
        LOG(INFO) << "backhaul_is_wireless=" << int(backhaul_params.backhaul_is_wireless);
        LOG(INFO) << "backhaul_iface_type=" << int(backhaul_params.backhaul_iface_type);
        LOG(INFO) << "is_backhaul_manager=" << int(is_backhaul_manager);

        if (is_backhaul_manager) {
            LOG(DEBUG) << "sending "
                          "ACTION_PLATFORM_SON_SLAVE_BACKHAUL_CONNECTION_COMPLETE_NOTIFICATION to "
                          "platform manager";
            auto notification = message_com::create_vs_message<
                beerocks_message::
                    cACTION_PLATFORM_SON_SLAVE_BACKHAUL_CONNECTION_COMPLETE_NOTIFICATION>(cmdu_tx);

            if (notification == nullptr) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            notification->is_backhaul_manager() =
                is_backhaul_manager; //redundant for now but might be needed in the future
            message_com::send_cmdu(platform_manager_socket, cmdu_tx);
        }

        LOG(TRACE) << "goto STATE_JOIN_MASTER";
        slave_state = STATE_JOIN_MASTER;

        SLAVE_STATE_CONTINUE();
        break;
    }
    case STATE_WAIT_BEFORE_JOIN_MASTER: {

        if (std::chrono::steady_clock::now() > slave_state_timer) {
            LOG(TRACE) << "goto STATE_JOIN_MASTER";
            slave_state = STATE_JOIN_MASTER;
        }

        break;
    }
    case STATE_JOIN_MASTER: {

        if (master_socket == nullptr) {
            LOG(ERROR) << "master_socket == nullptr";
            platform_notify_error(bpl::eErrorCode::SLAVE_INVALID_MASTER_SOCKET,
                                  "Invalid master socket");
            m_stop_on_failure_attempts--;
            slave_reset();
            break;
        }

        if (!cmdu_tx.create(0, ieee1905_1::eMessageType::AP_AUTOCONFIGURATION_WSC_MESSAGE)) {
            LOG(ERROR) << "Failed creating AP_AUTOCONFIGURATION_WSC_MESSAGE";
            return false;
        }

        auto db    = AgentDB::get();
        auto radio = db->radio(m_fronthaul_iface);
        if (!radio) {
            LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
            return false;
        }

        if (!tlvf_utils::add_ap_radio_basic_capabilities(cmdu_tx, radio->front.iface_mac)) {
            LOG(ERROR) << "Failed adding AP Radio Basic Capabilities TLV";
            return false;
        }

        if (!autoconfig_wsc_add_m1()) {
            LOG(ERROR) << "Failed adding WSC M1 TLV";
            return false;
        }

        // If the Multi-AP Agent onboards to a Multi-AP Controller that implements Profile-1, the
        // Multi-AP Agent shall set the Byte Counter Units field to 0x00 (bytes) and report the
        // values of the BytesSent and BytesReceived fields in the Associated STA Traffic Stats TLV
        // in bytes. Section 9.1 of the spec.
        db->device_conf.byte_counter_units =
            wfa_map::tlvProfile2ApCapability::eByteCounterUnits::BYTES;

        if (db->controller_info.profile_support ==
            wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::MULTIAP_PROFILE_2) {
            /* One Profile-2 AP Capability TLV */
            auto profile2_ap_capability_tlv = cmdu_tx.addClass<wfa_map::tlvProfile2ApCapability>();
            if (!profile2_ap_capability_tlv) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            // If a Multi-AP Agent that implements Profile-2 sends a Profile-2 AP Capability TLV
            // shall set the Byte Counter Units field to 0x01 (KiB (kibibytes)). Section 9.1 of the spec.
            db->device_conf.byte_counter_units =
                wfa_map::tlvProfile2ApCapability::eByteCounterUnits::KIBIBYTES;
            profile2_ap_capability_tlv->capabilities_bit_field().byte_counter_units =
                db->device_conf.byte_counter_units;

            // Calculate max total number of VLANs which can be configured on the Agent, and save it on
            // on the AgentDB.
            db->traffic_separation.max_number_of_vlans_ids =
                db->get_radios_list().size() * eBeeRocksIfaceIds::IFACE_TOTAL_VAPS;

            profile2_ap_capability_tlv->max_total_number_of_vids() =
                db->traffic_separation.max_number_of_vlans_ids;

            /* One AP Radio Advanced Capabilities TLV */
            auto ap_radio_advanced_capabilities_tlv =
                cmdu_tx.addClass<wfa_map::tlvProfile2ApRadioAdvancedCapabilities>();
            if (!ap_radio_advanced_capabilities_tlv) {
                LOG(ERROR) << "Failed building message!";
                return false;
            }

            ap_radio_advanced_capabilities_tlv->radio_uid() = radio->front.iface_mac;

            // Currently Set the flag as we don't support traffic separation.
            ap_radio_advanced_capabilities_tlv->traffic_separation_flag().combined_front_back =
                radio->front.hybrid_mode_supported;
            ap_radio_advanced_capabilities_tlv->traffic_separation_flag()
                .combined_profile1_and_profile2 = 0;
        }

        if (!db->controller_info.prplmesh_controller) {
            LOG(INFO) << "Configured as non-prplMesh, not sending SLAVE_JOINED_NOTIFICATION";
        } else {
            auto notification = message_com::add_vs_tlv<
                beerocks_message::cACTION_CONTROL_SLAVE_JOINED_NOTIFICATION>(cmdu_tx);

            if (!notification) {
                LOG(ERROR) << "Failed building cACTION_CONTROL_SLAVE_JOINED_NOTIFICATION!";
                return false;
            }

            notification->is_slave_reconf() = is_backhaul_reconf;
            is_backhaul_reconf              = false;

            // Version
            string_utils::copy_string(notification->slave_version(message::VERSION_LENGTH),
                                      BEEROCKS_VERSION, message::VERSION_LENGTH);

            // Platform Configuration
            notification->low_pass_filter_on()   = config.backhaul_wireless_iface_filter_low;
            notification->enable_repeater_mode() = config.enable_repeater_mode;

            // Backhaul Params
            notification->backhaul_params().is_backhaul_manager = is_backhaul_manager;
            notification->backhaul_params().backhaul_iface_type =
                backhaul_params.backhaul_iface_type;
            notification->backhaul_params().backhaul_mac =
                tlvf::mac_from_string(backhaul_params.backhaul_mac);
            notification->backhaul_params().backhaul_channel = backhaul_params.backhaul_channel;
            notification->backhaul_params().backhaul_bssid =
                tlvf::mac_from_string(backhaul_params.backhaul_bssid);
            notification->backhaul_params().backhaul_is_wireless =
                backhaul_params.backhaul_is_wireless;

            if (!db->bridge.iface_name.empty()) {
                notification->backhaul_params().bridge_ipv4 =
                    network_utils::ipv4_from_string(backhaul_params.bridge_ipv4);
                notification->backhaul_params().backhaul_ipv4 =
                    network_utils::ipv4_from_string(backhaul_params.bridge_ipv4);
            } else {
                notification->backhaul_params().backhaul_ipv4 =
                    network_utils::ipv4_from_string(backhaul_params.backhaul_ipv4);
            }

            std::copy_n(backhaul_params.backhaul_scan_measurement_list,
                        beerocks::message::BACKHAUL_SCAN_MEASUREMENT_MAX_LENGTH,
                        notification->backhaul_params().backhaul_scan_measurement_list);

            for (unsigned int i = 0; i < message::BACKHAUL_SCAN_MEASUREMENT_MAX_LENGTH; i++) {
                if (notification->backhaul_params().backhaul_scan_measurement_list[i].channel > 0) {
                    LOG(DEBUG)
                        << "mac = "
                        << notification->backhaul_params().backhaul_scan_measurement_list[i].mac.oct
                        << " channel = "
                        << int(notification->backhaul_params()
                                   .backhaul_scan_measurement_list[i]
                                   .channel)
                        << " rssi = "
                        << int(notification->backhaul_params()
                                   .backhaul_scan_measurement_list[i]
                                   .rssi);
                }

                //Platform Settings
                notification->platform_settings().client_band_steering_enabled =
                    db->device_conf.client_band_steering_enabled;
                notification->platform_settings().client_optimal_path_roaming_enabled =
                    db->device_conf.client_optimal_path_roaming_enabled;
                notification->platform_settings()
                    .client_optimal_path_roaming_prefer_signal_strength_enabled =
                    db->device_conf.client_optimal_path_roaming_prefer_signal_strength_enabled;
                notification->platform_settings().client_11k_roaming_enabled =
                    db->device_conf.client_11k_roaming_enabled;
                notification->platform_settings().load_balancing_enabled =
                    db->device_conf.load_balancing_enabled;
                notification->platform_settings().service_fairness_enabled =
                    db->device_conf.service_fairness_enabled;
                notification->platform_settings().rdkb_extensions_enabled =
                    db->device_conf.rdkb_extensions_enabled;

                notification->platform_settings().local_master = db->device_conf.local_controller;

                //Wlan Settings
                notification->wlan_settings().band_enabled =
                    db->device_conf.front_radio.config[config.hostap_iface].band_enabled;
                notification->wlan_settings().channel =
                    db->device_conf.front_radio.config[config.hostap_iface].configured_channel;
                // Hostap Params
                string_utils::copy_string(notification->hostap().iface_name,
                                          radio->front.iface_name.c_str(),
                                          beerocks::message::IFACE_NAME_LENGTH);
                notification->hostap().iface_mac = radio->front.iface_mac;
                notification->hostap().iface_is_5ghz =
                    wireless_utils::is_frequency_band_5ghz(radio->freq_type);
                notification->hostap().ant_num        = radio->number_of_antennas;
                notification->hostap().tx_power       = radio->tx_power_dB;
                notification->hostap().frequency_band = radio->freq_type;
                notification->hostap().max_bandwidth  = radio->max_supported_bw;
                notification->hostap().ht_supported   = radio->ht_supported;
                notification->hostap().ht_capability  = radio->ht_capability;
                std::copy_n(radio->ht_mcs_set.begin(), beerocks::message::HT_MCS_SET_SIZE,
                            notification->hostap().ht_mcs_set);
                notification->hostap().vht_supported  = radio->vht_supported;
                notification->hostap().vht_capability = radio->vht_capability;
                std::copy_n(radio->vht_mcs_set.begin(), beerocks::message::VHT_MCS_SET_SIZE,
                            notification->hostap().vht_mcs_set);

                notification->hostap().ant_gain = config.hostap_ant_gain;

                // Channel Selection Params
                notification->cs_params().channel   = radio->channel;
                notification->cs_params().bandwidth = radio->bandwidth;
                notification->cs_params().channel_ext_above_primary =
                    radio->channel_ext_above_primary;
                notification->cs_params().vht_center_frequency = radio->vht_center_frequency;
                notification->cs_params().tx_power             = radio->tx_power_dB;
            }
        }

        send_cmdu_to_controller(cmdu_tx);
        LOG(DEBUG) << "sending WSC M1 Size=" << int(cmdu_tx.getMessageLength());

        LOG(TRACE) << "goto STATE_WAIT_FOR_JOINED_RESPONSE";
        slave_state_timer = std::chrono::steady_clock::now() +
                            std::chrono::seconds(WAIT_FOR_JOINED_RESPONSE_TIMEOUT_SEC);

        slave_state = STATE_WAIT_FOR_JOINED_RESPONSE;
        break;
    }
    case STATE_WAIT_FOR_JOINED_RESPONSE: {
        if (std::chrono::steady_clock::now() > slave_state_timer) {
            LOG(INFO) << "STATE_WAIT_FOR_JOINED_RESPONSE timeout!";
            LOG(TRACE) << "goto STATE_JOIN_MASTER";
            slave_state = STATE_JOIN_MASTER;
        }
        break;
    }
    case STATE_UPDATE_MONITOR_SON_CONFIG: {
        LOG(INFO) << "sending ACTION_MONITOR_SON_CONFIG_UPDATE";

        auto update =
            message_com::create_vs_message<beerocks_message::cACTION_MONITOR_SON_CONFIG_UPDATE>(
                cmdu_tx);
        if (update == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }

        update->config() = son_config;
        message_com::send_cmdu(monitor_socket, cmdu_tx);
        LOG(TRACE) << "goto STATE_PRE_OPERATIONAL";
        slave_state = STATE_PRE_OPERATIONAL;
        break;
    }

    case STATE_PRE_OPERATIONAL: {
        auto db                    = AgentDB::get();
        m_stop_on_failure_attempts = db->device_conf.stop_on_failure_attempts;

        LOG(TRACE) << "goto STATE_OPERATIONAL";
        slave_state = STATE_OPERATIONAL;
        break;
    }
    case STATE_OPERATIONAL: {
        break;
    }
    case STATE_VERSION_MISMATCH: {
        break;
    }
    case STATE_SSID_MISMATCH: {
        break;
    }
    case STATE_STOPPED: {
        break;
    }
    default: {
        LOG(ERROR) << "Unknown state!";
        break;
    }
    }

    return slave_ok;
}

void slave_thread::backhaul_manager_stop()
{
    if (backhaul_manager_socket) {
        LOG(DEBUG) << "removing backhaul_manager_socket";
        remove_socket(backhaul_manager_socket);
        delete backhaul_manager_socket;
    }
    backhaul_manager_socket = nullptr;
    master_socket           = nullptr;
}

void slave_thread::platform_manager_stop()
{
    if (platform_manager_socket) {
        LOG(DEBUG) << "removing platform_manager_socket";
        remove_socket(platform_manager_socket);
        delete platform_manager_socket;
        platform_manager_socket = nullptr;
    }
}

void slave_thread::hostap_services_off() { LOG(DEBUG) << "hostap_services_off() - done"; }

bool slave_thread::hostap_services_on()
{
    bool success = true;
    LOG(DEBUG) << "hostap_services_on() - done";
    return success;
}

void slave_thread::fronthaul_stop()
{
    LOG(INFO) << "fronthaul stop";

    if (monitor_socket) {
        remove_socket(monitor_socket);
        delete monitor_socket;
        monitor_socket = nullptr;
    }

    if (ap_manager_socket) {
        remove_socket(ap_manager_socket);
        delete ap_manager_socket;
        ap_manager_socket = nullptr;
    }

    // Kill Fronthaul pid
    os_utils::kill_pid(config.temp_path + "pid/",
                       std::string(BEEROCKS_FRONTHAUL) + "_" + config.hostap_iface);
}

void slave_thread::fronthaul_start()
{
    fronthaul_stop();

    LOG(INFO) << "fronthaul start";

    // Start new Fronthaul process
    std::string file_name = "./" + std::string(BEEROCKS_FRONTHAUL);

    // Check if file does not exist in current location
    if (access(file_name.c_str(), F_OK) == -1) {
        file_name = mapf::utils::get_install_path() + "bin/" + std::string(BEEROCKS_FRONTHAUL);
    }
    std::string cmd = file_name + " -i " + config.hostap_iface;
    SYSTEM_CALL(cmd, true);
}

void slave_thread::log_son_config()
{
    LOG(DEBUG) << "SON_CONFIG_UPDATE: " << std::endl
               << "monitor_total_ch_load_notification_th_hi_percent="
               << int(son_config.monitor_total_ch_load_notification_lo_th_percent) << std::endl
               << "monitor_total_ch_load_notification_th_lo_percent="
               << int(son_config.monitor_total_ch_load_notification_hi_th_percent) << std::endl
               << "monitor_total_ch_load_notification_delta_th_percent="
               << int(son_config.monitor_total_ch_load_notification_delta_th_percent) << std::endl
               << "monitor_min_active_clients=" << int(son_config.monitor_min_active_clients)
               << std::endl
               << "monitor_active_client_th=" << int(son_config.monitor_active_client_th)
               << std::endl
               << "monitor_client_load_notification_delta_th_percent="
               << int(son_config.monitor_client_load_notification_delta_th_percent) << std::endl
               << "monitor_rx_rssi_notification_threshold_dbm="
               << int(son_config.monitor_rx_rssi_notification_threshold_dbm) << std::endl
               << "monitor_rx_rssi_notification_delta_db="
               << int(son_config.monitor_rx_rssi_notification_delta_db) << std::endl
               << "monitor_ap_idle_threshold_B=" << int(son_config.monitor_ap_idle_threshold_B)
               << std::endl
               << "monitor_ap_active_threshold_B=" << int(son_config.monitor_ap_active_threshold_B)
               << std::endl
               << "monitor_ap_idle_stable_time_sec="
               << int(son_config.monitor_ap_idle_stable_time_sec) << std::endl
               << "monitor_disable_initiative_arp="
               << int(son_config.monitor_disable_initiative_arp) << std::endl;
}

bool slave_thread::monitor_heartbeat_check()
{
    if (monitor_socket == nullptr) {
        return true;
    }
    auto now = std::chrono::steady_clock::now();
    int time_elapsed_secs =
        std::chrono::duration_cast<std::chrono::seconds>(now - monitor_last_seen).count();
    if (time_elapsed_secs > MONITOR_HEARTBEAT_TIMEOUT_SEC) {
        monitor_retries_counter++;
        monitor_last_seen = now;
        LOG(INFO) << "time_elapsed_secs > MONITOR_HEARTBEAT_TIMEOUT_SEC monitor_retries_counter = "
                  << int(monitor_retries_counter);
    }
    if (monitor_retries_counter >= MONITOR_HEARTBEAT_RETRIES) {
        LOG(INFO)
            << "monitor_retries_counter >= MONITOR_HEARTBEAT_RETRIES monitor_retries_counter = "
            << int(monitor_retries_counter) << " slave_reset!!";
        monitor_retries_counter = 0;
        return false;
    }
    return true;
}

bool slave_thread::ap_manager_heartbeat_check()
{
    if (ap_manager_socket == nullptr) {
        return true;
    }
    auto now = std::chrono::steady_clock::now();
    int time_elapsed_secs =
        std::chrono::duration_cast<std::chrono::seconds>(now - ap_manager_last_seen).count();
    if (time_elapsed_secs > AP_MANAGER_HEARTBEAT_TIMEOUT_SEC) {
        ap_manager_retries_counter++;
        ap_manager_last_seen = now;
        LOG(INFO) << "time_elapsed_secs > AP_MANAGER_HEARTBEAT_TIMEOUT_SEC "
                     "ap_manager_retries_counter = "
                  << int(ap_manager_retries_counter);
    }
    if (ap_manager_retries_counter >= AP_MANAGER_HEARTBEAT_RETRIES) {
        LOG(INFO) << "ap_manager_retries_counter >= AP_MANAGER_HEARTBEAT_RETRIES "
                     "ap_manager_retries_counter = "
                  << int(ap_manager_retries_counter) << " slave_reset!!";
        ap_manager_retries_counter = 0;
        return false;
    }
    return true;
}

bool slave_thread::send_cmdu_to_controller(ieee1905_1::CmduMessageTx &cmdu_tx)
{
    if (!master_socket) {
        LOG(ERROR) << "socket to master is nullptr";
        return false;
    }

    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }

    if (cmdu_tx.getMessageType() == ieee1905_1::eMessageType::VENDOR_SPECIFIC_MESSAGE) {
        if (!db->controller_info.prplmesh_controller) {
            return true; // don't send VS messages to non prplmesh controllers
        }
        auto beerocks_header = message_com::get_beerocks_header(cmdu_tx);
        if (!beerocks_header) {
            LOG(ERROR) << "Failed getting beerocks_header!";
            return false;
        }

        beerocks_header->actionhdr()->radio_mac() = radio->front.iface_mac;
        beerocks_header->actionhdr()->direction() = beerocks::BEEROCKS_DIRECTION_CONTROLLER;
    }

    auto dst_addr =
        cmdu_tx.getMessageType() == ieee1905_1::eMessageType::TOPOLOGY_NOTIFICATION_MESSAGE
            ? network_utils::MULTICAST_1905_MAC_ADDR
            : tlvf::mac_to_string(db->controller_info.bridge_mac);

    return message_com::send_cmdu(master_socket, cmdu_tx, dst_addr,
                                  tlvf::mac_to_string(db->bridge.mac));
}

/**
 * @brief Diffie-Hellman public key exchange keys calculation
 *        class member params authkey and keywrapauth are computed
 *        on success.
 *
 * @param[in] m2 WSC M2 received from the controller
 * @param[out] authkey 32 bytes calculated authentication key
 * @param[out] keywrapkey 16 bytes calculated key wrap key
 * @return true on success
 * @return false on failure
 */
bool slave_thread::autoconfig_wsc_calculate_keys(WSC::m2 &m2, uint8_t authkey[32],
                                                 uint8_t keywrapkey[16])
{
    if (!dh) {
        LOG(ERROR) << "diffie hellman member not initialized";
        return false;
    }

    auto db = AgentDB::get();
    mapf::encryption::wps_calculate_keys(
        *dh, m2.public_key(), WSC::eWscLengths::WSC_PUBLIC_KEY_LENGTH, dh->nonce(),
        db->bridge.mac.oct, m2.registrar_nonce(), authkey, keywrapkey);

    return true;
}

/**
 * @brief autoconfig global authenticator attribute calculation
 *
 * Calculate authentication on the Full M1 || M2* whereas M2* = M2 without the authenticator
 * attribute. M1 is a saved buffer of the swapped M1 sent in the WSC autoconfig sent by the agent.
 *
 * @param m2 WSC M2 attribute list from the controller
 * @param authkey authentication key
 * @return true on success
 * @return false on failure
 */
bool slave_thread::autoconfig_wsc_authenticate(WSC::m2 &m2, uint8_t authkey[32])
{
    if (!m1_auth_buf) {
        LOG(ERROR) << "Invalid M1";
        return false;
    }

    // This is the content of M1 and M2, without the type and length.
    uint8_t buf[m1_auth_buf_len + m2.getMessageLength() -
                WSC::cWscAttrAuthenticator::get_initial_size()];
    auto next = std::copy_n(m1_auth_buf, m1_auth_buf_len, buf);
    m2.swap(); //swap to get network byte order
    std::copy_n(m2.getMessageBuff(),
                m2.getMessageLength() - WSC::cWscAttrAuthenticator::get_initial_size(), next);
    m2.swap(); //swap back

    uint8_t kwa[WSC::WSC_AUTHENTICATOR_LENGTH];
    // Add KWA which is the 1st 64 bits of HMAC of config_data using AuthKey
    if (!mapf::encryption::kwa_compute(authkey, buf, sizeof(buf), kwa)) {
        LOG(ERROR) << "kwa_compute failure";
        return false;
    }

    if (!std::equal(kwa, kwa + sizeof(kwa), reinterpret_cast<uint8_t *>(m2.authenticator()))) {
        LOG(ERROR) << "WSC Global authentication failed";
        LOG(DEBUG) << "authenticator: "
                   << utils::dump_buffer(reinterpret_cast<uint8_t *>(m2.authenticator()),
                                         WSC::WSC_AUTHENTICATOR_LENGTH);
        LOG(DEBUG) << "calculated:    " << utils::dump_buffer(kwa, WSC::WSC_AUTHENTICATOR_LENGTH);
        LOG(DEBUG) << "authenticator key: " << utils::dump_buffer(authkey, 32);
        LOG(DEBUG) << "authenticator buf:" << std::endl << utils::dump_buffer(buf, sizeof(buf));
        return false;
    }

    LOG(DEBUG) << "WSC Global authentication success";
    return true;
}

bool slave_thread::autoconfig_wsc_parse_m2_encrypted_settings(WSC::m2 &m2, uint8_t authkey[32],
                                                              uint8_t keywrapkey[16],
                                                              WSC::configData::config &config)
{
    auto encrypted_settings = m2.encrypted_settings();
    uint8_t *iv             = reinterpret_cast<uint8_t *>(encrypted_settings.iv());
    auto ciphertext         = reinterpret_cast<uint8_t *>(encrypted_settings.encrypted_settings());
    int cipherlen           = encrypted_settings.encrypted_settings_length();
    // leave room for up to 16 bytes internal padding length - see aes_decrypt()
    int datalen = cipherlen + 16;
    uint8_t decrypted[datalen];

    LOG(DEBUG) << "M2 Parse: received encrypted settings with length " << cipherlen;

    LOG(DEBUG) << "M2 Parse: aes decrypt";
    if (!mapf::encryption::aes_decrypt(keywrapkey, iv, ciphertext, cipherlen, decrypted, datalen)) {
        LOG(ERROR) << "aes decrypt failure";
        return false;
    }

    LOG(DEBUG) << "M2 Parse: parse config_data, len = " << datalen;
    LOG(DEBUG) << "decrypted config_data buffer: " << std::endl
               << utils::dump_buffer(decrypted, datalen);

    // Parsing failure means that the config data is invalid,
    // in which case it is unclear what we should do.
    // In practice, some controllers simply send an empty config data
    // when the radio should be tore down, so let the caller handle this
    // by returning true with a warning for now.
    auto config_data = WSC::configData::parse(decrypted, datalen);
    if (!config_data) {
        LOG(WARNING) << "Invalid config data, skip it";
        return true;
    }

    // get length of config_data for KWA authentication
    size_t len = config_data->getMessageLength();
    // Protect against M2 buffer overflow attacks
    if (len > size_t(datalen)) {
        LOG(ERROR) << "invalid config data length";
        return false;
    }
    // Update VAP configuration
    config.auth_type   = config_data->auth_type();
    config.encr_type   = config_data->encr_type();
    config.bssid       = config_data->bssid();
    config.network_key = config_data->network_key();
    config.ssid        = config_data->ssid();
    config.bss_type    = config_data->bss_type();

    // Get the Key Wrap Authenticator data
    auto kwa_data = config_data->key_wrap_authenticator();
    if (!kwa_data) {
        LOG(ERROR) << "No KeyWrapAuthenticator in config_data";
        return false;
    }

    // The keywrap authenticator is part of the config_data (last member of the
    // config_data to be precise).
    // However, since we need to calculate it over the part of config_data without the keywrap
    // authenticator, substruct it's size from the computation length
    size_t config_data_len_for_kwa = len - config_data->key_wrap_authenticator_size();

    // Swap to network byte order for KWA HMAC calculation
    // from this point config data is not readable!
    config_data->swap();
    uint8_t kwa[WSC::WSC_AUTHENTICATOR_LENGTH];
    // Compute KWA based on decrypted settings
    if (!mapf::encryption::kwa_compute(authkey, decrypted, config_data_len_for_kwa, kwa)) {
        LOG(ERROR) << "kwa compute";
        return false;
    }

    if (!std::equal(kwa, kwa + sizeof(kwa), kwa_data)) {
        LOG(ERROR) << "WSC KWA (Key Wrap Auth) failure";
        return false;
    }
    LOG(DEBUG) << "KWA (Key Wrap Auth) success";

    return true;
}

/**
 * @brief Parse AP-Autoconfiguration Renew message
 *
 * This function checks the TLVs in the AP-Autoconfiguration Renew message. If OK, it triggers
 * autoconfiguration.
 *
 * @param sd socket descriptor
 * @param cmdu_rx received CMDU containing AP-Autoconfiguration Renew
 * @return true on success
 * @return false on failure
 */
bool slave_thread::handle_autoconfiguration_renew(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    LOG(INFO) << "received autoconfig renew message";

    // Load Agent DB & radio
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of iface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }

    auto tlvAlMac = cmdu_rx.getClass<ieee1905_1::tlvAlMacAddress>();
    if (!tlvAlMac) {
        LOG(ERROR) << "tlvAlMac missing - ignoring autconfig renew message";
        return false;
    }

    const auto &src_mac = tlvAlMac->mac();
    LOG(DEBUG) << "AP-Autoconfiguration Renew Message from Controller " << src_mac;
    if (src_mac != db->controller_info.bridge_mac) {
        LOG(ERROR) << "Ignoring AP-Autoconfiguration Renew Message from an unknown controller";
        return false;
    }

    auto tlvSupportedRole = cmdu_rx.getClass<ieee1905_1::tlvSupportedRole>();
    if (!tlvSupportedRole) {
        LOG(ERROR) << "tlvSupportedRole missing - ignoring autconfig renew message";
        return false;
    }

    LOG(DEBUG) << "tlvSupportedRole->value()=" << int(tlvSupportedRole->value());
    if (tlvSupportedRole->value() != ieee1905_1::tlvSupportedRole::REGISTRAR) {
        LOG(ERROR) << "invalid tlvSupportedRole value, supporting only REGISTRAR controllers";
        return false;
    }

    auto tlvSupportedFreqBand = cmdu_rx.getClass<ieee1905_1::tlvSupportedFreqBand>();
    if (!tlvSupportedFreqBand) {
        LOG(ERROR) << "tlvSupportedFreqBand missing - ignoring autoconfig renew message";
        return false;
    }

    std::string band_name;
    switch (tlvSupportedFreqBand->value()) {
    case ieee1905_1::tlvSupportedFreqBand::BAND_2_4G:
        band_name = "2.4GHz";
        break;
    case ieee1905_1::tlvSupportedFreqBand::BAND_5G:
        band_name = "5GHz";
        break;
    case ieee1905_1::tlvSupportedFreqBand::BAND_60G:
        LOG(ERROR) << "Received AP-Autoconfiguration Renew Message for 60GHz band, unsupported";
        return false;
    default:
        LOG(ERROR) << "invalid tlvSupportedFreqBand value";
        return false;
    }
    LOG(INFO) << "Received AP-Autoconfiguration Renew Message for " << band_name << " band";

    // Continue on to STATE_JOIN_MASTER
    LOG(TRACE) << "goto STATE_JOIN_MASTER";
    slave_state = STATE_JOIN_MASTER;
    return true;
}

bool slave_thread::handle_profile2_default_802dotq_settings_tlv(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto db = AgentDB::get();

    auto pvid_set_request = message_com::create_vs_message<
        beerocks_message::cACTION_APMANAGER_HOSTAP_SET_PRIMARY_VLAN_ID_REQUEST>(cmdu_tx);
    if (!pvid_set_request) {
        LOG(ERROR) << "Failed building message!";
        return false;
    }
    auto dot1q_settings = cmdu_rx.getClass<wfa_map::tlvProfile2Default802dotQSettings>();
    // tlvProfile2Default802dotQSettings is not mandatory.
    if (!dot1q_settings) {
        LOG(INFO) << "No tlvProfile2Default802dotQSettings";
        return true;
    }

    LOG(DEBUG) << "Primary VLAN ID: " << dot1q_settings->primary_vlan_id()
               << ", PCP: " << dot1q_settings->default_pcp();

    db->traffic_separation.primary_vlan_id = dot1q_settings->primary_vlan_id();
    db->traffic_separation.default_pcp     = dot1q_settings->default_pcp();

    pvid_set_request->primary_vlan_id() = dot1q_settings->primary_vlan_id();

    // Send ACTION_APMANAGER_HOSTAP_SET_PRIMARY_VLAN_ID_REQUEST.
    message_com::send_cmdu(ap_manager_socket, cmdu_tx);

    return true;
}

bool slave_thread::handle_profile2_traffic_separation_policy_tlv(
    ieee1905_1::CmduMessageRx &cmdu_rx, std::unordered_set<std::string> &misconfigured_ssids)
{
    auto traffic_seperation_policy =
        cmdu_rx.getClass<wfa_map::tlvProfile2TrafficSeparationPolicy>();

    if (!traffic_seperation_policy) {
        LOG(ERROR) << "tlvProfile2TrafficSeparationPolicy not found!";
        return false;
    }

    auto db = AgentDB::get();

    std::unordered_map<std::string, uint16_t> tmp_ssid_vid_mapping;
    for (int i = 0; i < traffic_seperation_policy->ssids_vlan_id_list_length(); i++) {
        auto ssid_vid_tuple = traffic_seperation_policy->ssids_vlan_id_list(i);
        if (!std::get<0>(ssid_vid_tuple)) {
            LOG(ERROR) << "Failed to get ssid_vid mapping, idx=" << i;
            return false;
        }
        auto &ssid_vid_mapping = std::get<1>(ssid_vid_tuple);

        tmp_ssid_vid_mapping[ssid_vid_mapping.ssid_name_str()] = ssid_vid_mapping.vlan_id();
        LOG(DEBUG) << "SSID: " << ssid_vid_mapping.ssid_name_str()
                   << ", VID: " << ssid_vid_mapping.vlan_id();
    }

    // Overwriting the whole container instead of pushing one by one, since we need to remove
    // old configuration from previous configurations messages.
    db->traffic_separation.ssid_vid_mapping = tmp_ssid_vid_mapping;

    // Fill secondary VLANs IDs to the database.
    for (const auto &ssid_vid_pair : db->traffic_separation.ssid_vid_mapping) {
        auto vlan_id = ssid_vid_pair.second;
        if (vlan_id != db->traffic_separation.primary_vlan_id) {
            db->traffic_separation.secondary_vlans_ids.insert(vlan_id);
        }
    }

    // Erase excessive secondary VIDs.
    if (db->traffic_separation.ssid_vid_mapping.size() >
        db->traffic_separation.max_number_of_vlans_ids) {

        for (auto it = std::next(db->traffic_separation.ssid_vid_mapping.begin(),
                                 db->traffic_separation.max_number_of_vlans_ids);
             it != db->traffic_separation.ssid_vid_mapping.end();) {

            auto &ssid = it->first;
            misconfigured_ssids.insert(ssid);
            it = db->traffic_separation.ssid_vid_mapping.erase(it);
        }
    }
    return true;
}

bool slave_thread::send_error_response(
    const std::deque<std::pair<wfa_map::tlvProfile2ErrorCode::eReasonCode, sMacAddr>> &bss_errors)
{
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::ERROR_RESPONSE_MESSAGE)) {
        LOG(ERROR) << "cmdu creation has failed";
        return false;
    }

    LOG(INFO) << "Sending ERROR_RESPONSE_MESSAGE to the controller on:";
    for (const auto &bss_error : bss_errors) {
        auto &reason = bss_error.first;
        auto &bssid  = bss_error.second;
        LOG(INFO) << "reason : " << reason << ", bssid: " << bssid;

        auto profile2_error_code_tlv = cmdu_tx.addClass<wfa_map::tlvProfile2ErrorCode>();
        if (!profile2_error_code_tlv) {
            LOG(ERROR) << "addClass has failed";
            return false;
        }

        profile2_error_code_tlv->reason_code() = reason;
        profile2_error_code_tlv->bssid()       = bssid;

        send_cmdu_to_controller(cmdu_tx);
    }
    return true;
}

/**
 * @brief Parse AP-Autoconfiguration WSC which should include one AP Radio Identifier
 *        TLV and one or more WSC TLV containing M2
 *
 * @param sd socket descriptor
 * @param cmdu_rx received CMDU containing M2
 * @return true on success
 * @return false on failure
 */
bool slave_thread::handle_autoconfiguration_wsc(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    LOG(DEBUG) << "Received AP_AUTOCONFIGURATION_WSC_MESSAGE";

    std::list<WSC::m2> m2_list;
    for (auto tlv : cmdu_rx.getClassList<ieee1905_1::tlvWsc>()) {
        auto m2 = WSC::m2::parse(*tlv);
        if (!m2) {
            LOG(INFO) << "Not a valid M2 - Ignoring WSC CMDU";
            continue;
        }
        m2_list.push_back(*m2);
    }
    if (m2_list.empty()) {
        LOG(ERROR) << "No M2s present";
        return false;
    }

    auto ruid = cmdu_rx.getClass<wfa_map::tlvApRadioIdentifier>();
    if (!ruid) {
        LOG(ERROR) << "getClass<wfa_map::tlvApRadioIdentifier> failed";
        return false;
    }

    auto db = AgentDB::get();

    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }
    // Check if the message is for this radio agent by comparing the ruid
    if (radio->front.iface_mac != ruid->radio_uid()) {
        LOG(DEBUG) << "Message should be handled by another son_slave - ruid "
                   << radio->front.iface_mac << " != " << ruid->radio_uid();
        return true;
    }

    if (!handle_profile2_default_802dotq_settings_tlv(cmdu_rx)) {
        LOG(ERROR) << "handle_profile2_default_802dotq_settings_tlv has failed!";
        return false;
    }

    std::unordered_set<std::string> misconfigured_ssids;
    // tlvProfile2TrafficSeparationPolicy is not mandatory.
    if (!cmdu_rx.getClass<wfa_map::tlvProfile2TrafficSeparationPolicy>()) {
        LOG(INFO) << "tlvProfile2TrafficSeparationPolicy not found";
    } else if (!handle_profile2_traffic_separation_policy_tlv(cmdu_rx, misconfigured_ssids)) {
        LOG(ERROR) << "handle_profile2_traffic_separation_policy_tlv has failed!";
        return false;
    }

    std::deque<std::pair<wfa_map::tlvProfile2ErrorCode::eReasonCode, sMacAddr>> bss_errors;
    std::vector<WSC::configData::config> configs;
    for (auto m2 : m2_list) {
        LOG(DEBUG) << "M2 Parse " << m2.manufacturer()
                   << " Controller configuration (WSC M2 Encrypted Settings)";
        uint8_t authkey[32];
        uint8_t keywrapkey[16];
        LOG(DEBUG) << "M2 Parse: calculate keys";
        if (!autoconfig_wsc_calculate_keys(m2, authkey, keywrapkey))
            return false;

        if (!autoconfig_wsc_authenticate(m2, authkey))
            return false;

        WSC::configData::config config;
        if (!autoconfig_wsc_parse_m2_encrypted_settings(m2, authkey, keywrapkey, config)) {
            LOG(ERROR) << "Invalid config data, skip it";
            continue;
        }

        bool bSTA = bool(config.bss_type & WSC::eWscVendorExtSubelementBssType::BACKHAUL_STA);
        bool fBSS = bool(config.bss_type & WSC::eWscVendorExtSubelementBssType::FRONTHAUL_BSS);
        bool bBSS = bool(config.bss_type & WSC::eWscVendorExtSubelementBssType::BACKHAUL_BSS);
        bool bBSS_p1_disallowed =
            bool(config.bss_type &
                 WSC::eWscVendorExtSubelementBssType::PROFILE1_BACKHAUL_STA_ASSOCIATION_DISALLOWED);
        bool bBSS_p2_disallowed =
            bool(config.bss_type &
                 WSC::eWscVendorExtSubelementBssType::PROFILE2_BACKHAUL_STA_ASSOCIATION_DISALLOWED);
        bool teardown = bool(config.bss_type & WSC::eWscVendorExtSubelementBssType::TEARDOWN);

        LOG(INFO) << "BSS configuration - ";
        LOG(INFO) << "bssid: " << config.bssid;
        LOG(INFO) << "ssid: " << config.ssid;
        LOG(INFO) << "fBSS: " << fBSS;
        LOG(INFO) << "bBSS: " << bBSS;
        LOG(INFO) << "Teardown: " << teardown;
        if (bBSS) {
            LOG(INFO) << "profile1_backhaul_sta_association_disallowed: " << bBSS_p1_disallowed;
            LOG(INFO) << "profile2_backhaul_sta_association_disallowed: " << bBSS_p2_disallowed;
        }

        // TODO - revisit this in the future
        // In practice, some controllers simply send an empty config data when asked for tear down,
        // so tear down the radio if the SSID is empty.
        if (config.ssid.empty()) {
            LOG(INFO) << "Empty config data, tear down radio";
            configs.clear();
            break;
        }

        LOG(INFO) << "bss_type: " << std::hex << int(config.bss_type);
        if (teardown) {
            LOG(INFO) << "Teardown bit set, tear down radio";
            configs.clear();
            break;
        }
        // BACKHAUL_STA bit is not expected to be set
        if (bSTA) {
            LOG(WARNING) << "Unexpected backhaul STA bit";
        }

        if (misconfigured_ssids.find(config.ssid) != misconfigured_ssids.end()) {
            bss_errors.push_back({wfa_map::tlvProfile2ErrorCode::eReasonCode::
                                      NUMBER_OF_UNIQUE_VLAN_ID_EXCEEDS_MAXIMUM_SUPPORTED,
                                  config.bssid});

            // Multi-AP standard requires to tear down any misconfigured BSS.
            config.bss_type = WSC::eWscVendorExtSubelementBssType::TEARDOWN;
        } else if (fBSS && bBSS && !radio->front.hybrid_mode_supported) {
            LOG(WARNING) << "Controller configured hybrid mode, but it is not supported!";
            bss_errors.push_back(
                {wfa_map::tlvProfile2ErrorCode::eReasonCode::
                     TRAFFIC_SEPARATION_ON_COMBINED_FRONTHAUL_AND_PROFILE1_BACKHAUL_UNSUPPORTED,
                 config.bssid});

            // Multi-AP standard requires to tear down any misconfigured BSS.
            config.bss_type = WSC::eWscVendorExtSubelementBssType::TEARDOWN;

        } else if (db->controller_info.profile_support !=
                       wfa_map::tlvProfile2MultiApProfile::eMultiApProfile::MULTIAP_PROFILE_1 &&
                   bBSS && !bBSS_p1_disallowed && !bBSS_p2_disallowed) {

            LOG(WARNING) << "Controller configured Backhaul BSS for combined Profile1 and "
                         << "Profile2, but it is not supported!";
            // bss_errors.push_back(
            //     {wfa_map::tlvProfile2ErrorCode::eReasonCode::
            //          TRAFFIC_SEPARATION_ON_COMBINED_PROFILE1_BACKHAUL_AND_PROFILE2_BACKHAUL_UNSUPPORTED,
            //      config.bssid});

            // // Multi-AP standard requires to tear down any misconfigured BSS.
            // config.bss_type = WSC::eWscVendorExtSubelementBssType::TEARDOWN;

            /**
             * We currently do not support bBSS with both profile 1/2 disallow
             * flags set to false (Combined Profile bBSS mode).
             * When we are configured in a way we don't support, we should tear down the BSS, and
             * send an error response on that BSS.
             * Currently R2 certified controllers (Mediatek/Marvel) have a bug (PPM-1389) that ends
             * up sending M2 with both profile 1/2 disallow flags set to false although we report 
             * combined_profile1_and_profile2 = 0 in ap_radio_advanced_capabilities_tlv.
             * To deal with it, temporarily comment the lines above and allow the BSS to be
             * configured successfully until PPM-1389 is resolved.
             */
            LOG(DEBUG) << "Currently ignore bad configuration";
        }

        LOG(DEBUG) << m2.manufacturer() << " config data:" << std::endl
                   << " ssid: " << config.ssid << ", bssid: " << config.bssid
                   << ", authentication_type: " << std::hex << int(config.auth_type)
                   << ", encryption_type: " << int(config.encr_type);
        configs.push_back(config);
    }

    if (bss_errors.size()) {
        send_error_response(bss_errors);
    }

    auto request = message_com::create_vs_message<
        beerocks_message::cACTION_APMANAGER_WIFI_CREDENTIALS_UPDATE_REQUEST>(cmdu_tx);
    if (!request) {
        LOG(ERROR) << "Failed building message!";
        return false;
    }
    for (auto config : configs) {
        auto c = request->create_wifi_credentials();
        if (!c) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        c->set_ssid(config.ssid);
        c->set_network_key(config.network_key);
        c->bssid_attr().data               = config.bssid;
        c->authentication_type_attr().data = config.auth_type;
        c->encryption_type_attr().data     = config.encr_type;
        c->bss_type()                      = config.bss_type;
        request->add_wifi_credentials(c);
    }

    ///////////////////////////////////////////////////////////////////
    // TODO https://github.com/prplfoundation/prplMesh/issues/797
    //
    // Short term solution
    // In non-EasyMesh mode, never modify hostapd configuration
    // and in this case VAPs credentials
    //
    // Long term solution
    // All EasyMesh VAPs will be stored in the platform DB.
    // All other VAPs are manual, AKA should not be modified by prplMesh
    ////////////////////////////////////////////////////////////////////
    if (db->device_conf.management_mode != BPL_MGMT_MODE_NOT_MULTIAP) {
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
    } else {
        LOG(WARNING) << "non-EasyMesh mode - skip updating VAP credentials";
    }

    if (slave_state != STATE_WAIT_FOR_JOINED_RESPONSE) {
        LOG(ERROR) << "slave_state != STATE_WAIT_FOR_JOINED_RESPONSE";
        return false;
    }

    auto beerocks_header = message_com::parse_intel_vs_message(cmdu_rx);
    if (beerocks_header) {
        LOG(INFO) << "Intel controller join response";
        if (!parse_intel_join_response(sd, *beerocks_header)) {
            LOG(ERROR) << "Parse join response failed";
            return false;
        }
    } else {
        LOG(INFO) << "Non-Intel controller join response";
        if (!parse_non_intel_join_response(sd)) {
            LOG(ERROR) << "Parse join response failed";
            return false;
        }
    }

    return true;
}

bool slave_thread::parse_intel_join_response(Socket *sd, beerocks::beerocks_header &beerocks_header)
{
    LOG(DEBUG) << "ACTION_CONTROL_SLAVE_JOINED_RESPONSE sd=" << intptr_t(sd);
    if (slave_state != STATE_WAIT_FOR_JOINED_RESPONSE) {
        LOG(ERROR) << "slave_state != STATE_WAIT_FOR_JOINED_RESPONSE";
        return false;
    }

    if (beerocks_header.action_op() != beerocks_message::ACTION_CONTROL_SLAVE_JOINED_RESPONSE) {
        LOG(ERROR) << "Unexpected Intel action op " << beerocks_header.action_op();
        return false;
    }

    auto joined_response =
        beerocks_header.addClass<beerocks_message::cACTION_CONTROL_SLAVE_JOINED_RESPONSE>();
    if (joined_response == nullptr) {
        LOG(ERROR) << "addClass cACTION_CONTROL_SLAVE_JOINED_RESPONSE failed";
        return false;
    }

    // check master rejection
    if (joined_response->err_code() == beerocks::JOIN_RESP_REJECT) {
        slave_state_timer = std::chrono::steady_clock::now() +
                            std::chrono::seconds(WAIT_BEFORE_SEND_SLAVE_JOINED_NOTIFICATION_SEC);
        LOG(DEBUG) << "STATE_WAIT_FOR_JOINED_RESPONSE: join rejected!";
        LOG(DEBUG) << "goto STATE_WAIT_BEFORE_JOIN_MASTER";
        slave_state = STATE_WAIT_BEFORE_JOIN_MASTER;
        return true;
    }

    // request the current vap list from ap_manager
    auto request = message_com::create_vs_message<
        beerocks_message::cACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_REQUEST>(cmdu_tx);
    if (request == nullptr) {
        LOG(ERROR) << "Failed building cACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_REQUEST message!";
        return false;
    }
    message_com::send_cmdu(ap_manager_socket, cmdu_tx);

    auto client_notifications_request = message_com::create_vs_message<
        beerocks_message::
            cACTION_APMANAGER_HOSTAP_GENERATE_CLIENT_ASSOCIATION_NOTIFICATIONS_REQUEST>(cmdu_tx);
    if (!client_notifications_request) {
        LOG(ERROR) << "Failed building message!";
        return false;
    }
    message_com::send_cmdu(ap_manager_socket, cmdu_tx);

    master_version.assign(joined_response->master_version(message::VERSION_LENGTH));

    LOG(DEBUG) << "Version (Master/Slave): " << master_version << "/" << BEEROCKS_VERSION;
    auto slave_version_s  = version::version_from_string(BEEROCKS_VERSION);
    auto master_version_s = version::version_from_string(master_version);

    // check for mismatch
    if (master_version_s.major != slave_version_s.major ||
        master_version_s.minor != slave_version_s.minor ||
        master_version_s.build_number != slave_version_s.build_number) {
        LOG(WARNING) << "master_version != slave_version";
        LOG(WARNING) << "Version (Master/Slave): " << master_version << "/" << BEEROCKS_VERSION;
    }

    // check if fatal mismatch
    if (joined_response->err_code() == beerocks::JOIN_RESP_VERSION_MISMATCH) {
        LOG(ERROR) << "Mismatch version! slave_version=" << std::string(BEEROCKS_VERSION)
                   << " master_version=" << master_version;
        LOG(DEBUG) << "goto STATE_VERSION_MISMATCH";
        slave_state = STATE_VERSION_MISMATCH;
    } else if (joined_response->err_code() == beerocks::JOIN_RESP_SSID_MISMATCH) {
        LOG(ERROR) << "Mismatch SSID!";
        LOG(DEBUG) << "goto STATE_SSID_MISMATCH";
        slave_state = STATE_SSID_MISMATCH;
    } else {
        //Send master version + slave version to platform manager
        auto notification = message_com::create_vs_message<
            beerocks_message::cACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION>(cmdu_tx);
        if (notification == nullptr) {
            LOG(ERROR) << "Failed building message!";
            return false;
        }
        string_utils::copy_string(notification->versions().master_version, master_version.c_str(),
                                  sizeof(beerocks_message::sVersions::master_version));
        string_utils::copy_string(notification->versions().slave_version, BEEROCKS_VERSION,
                                  sizeof(beerocks_message::sVersions::slave_version));
        message_com::send_cmdu(platform_manager_socket, cmdu_tx);
        LOG(DEBUG) << "send ACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION";

        son_config = joined_response->config();
        log_son_config();

        slave_state = STATE_UPDATE_MONITOR_SON_CONFIG;
    }

    return true;
}

bool slave_thread::parse_non_intel_join_response(Socket *sd)
{
    // request the current vap list from ap_manager
    auto request = message_com::create_vs_message<
        beerocks_message::cACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_REQUEST>(cmdu_tx);
    if (request == nullptr) {
        LOG(ERROR) << "Failed building cACTION_APMANAGER_HOSTAP_VAPS_LIST_UPDATE_REQUEST message!";
        return false;
    }
    message_com::send_cmdu(ap_manager_socket, cmdu_tx);

    // No version checking for non-Intel controller

    // TODO
    //        auto notification = message_com::create_vs_message<
    //            beerocks_message::cACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION>(cmdu_tx);
    //        if (notification == nullptr) {
    //            LOG(ERROR) << "Failed building message!";
    //            return false;
    //        }
    //        string_utils::copy_string(notification->versions().master_version, master_version.c_str(),
    //                                  sizeof(beerocks_message::sVersions::master_version));
    //        string_utils::copy_string(notification->versions().slave_version, BEEROCKS_VERSION,
    //                                  sizeof(beerocks_message::sVersions::slave_version));
    //        message_com::send_cmdu(platform_manager_socket, cmdu_tx);
    //        LOG(DEBUG) << "send ACTION_PLATFORM_MASTER_SLAVE_VERSIONS_NOTIFICATION";

    // TODO set son_config
    log_son_config();

    slave_state = STATE_UPDATE_MONITOR_SON_CONFIG;

    return true;
}

bool slave_thread::handle_multi_ap_policy_config_request(Socket *sd,
                                                         ieee1905_1::CmduMessageRx &cmdu_rx)
{

    /**
     * The Multi-AP Policy Config Request message is sent by the controller and received by the
     * backhaul manager.
     * The backhaul manager forwards the request message "as is" to all the slaves managing the
     * radios which Radio Unique Identifier has been specified.
     */
    auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE, mid=" << std::hex << int(mid);

    if (!handle_profile2_default_802dotq_settings_tlv(cmdu_rx)) {
        LOG(ERROR) << "handle_profile2_default_802dotq_settings_tlv has failed!";
        return false;
    }

    std::unordered_set<std::string> misconfigured_ssids;
    auto db = AgentDB::get();
    // tlvProfile2TrafficSeparationPolicy is not mandatory. But if it does not exist, need to clear
    // traffic separation settings.
    if (!cmdu_rx.getClass<wfa_map::tlvProfile2TrafficSeparationPolicy>()) {
        LOG(INFO) << "tlvProfile2TrafficSeparationPolicy not found";
        db->traffic_separation.ssid_vid_mapping.clear();
    } else if (!handle_profile2_traffic_separation_policy_tlv(cmdu_rx, misconfigured_ssids)) {
        LOG(ERROR) << "handle_profile2_traffic_separation_policy_tlv has failed!";
        return false;
    }

    if (db->traffic_separation.ssid_vid_mapping.empty()) {
        // If SSID VID map is empty, need to clear traffic separation policy.
        db->traffic_separation.primary_vlan_id = 0;
        db->traffic_separation.default_pcp     = 0;
    }

    /**
     * The slave in turn, forwards the request message again "as is" to the monitor thread.
     */
    if (!monitor_socket) {
        LOG(ERROR) << "monitor_socket is null";
        return false;
    }

    uint16_t length = message_com::get_uds_header(cmdu_rx)->length;
    cmdu_rx.swap(); // swap back before forwarding
    if (!message_com::forward_cmdu_to_uds(monitor_socket, cmdu_rx, length)) {
        LOG(ERROR) << "Failed to forward message to monitor";
        return false;
    }

    std::deque<std::pair<wfa_map::tlvProfile2ErrorCode::eReasonCode, sMacAddr>> bss_errors;
    if (!misconfigured_ssids.empty()) {
        bss_errors.push_back({wfa_map::tlvProfile2ErrorCode::eReasonCode::
                                  NUMBER_OF_UNIQUE_VLAN_ID_EXCEEDS_MAXIMUM_SUPPORTED,
                              sMacAddr()});
    }

    if (bss_errors.size()) {
        send_error_response(bss_errors);
        return false;
    }

    if (m_autoconfiguration_completed) {
        TrafficSeparation::apply_traffic_separation(m_fronthaul_iface);
    } else {
        LOG(WARNING) << "autoconfiguration procedure is not completed yet, traffic separation "
                     << "policy cannot be applied";
    }

    return true;
}

bool slave_thread::handle_client_association_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE, mid=" << std::dec
               << int(mid);

    auto association_control_request_tlv =
        cmdu_rx.getClass<wfa_map::tlvClientAssociationControlRequest>();
    if (!association_control_request_tlv) {
        LOG(ERROR) << "addClass wfa_map::tlvClientAssociationControlRequest failed";
        return false;
    }

    const auto &bssid   = association_control_request_tlv->bssid_to_block_client();
    const auto &sta_mac = std::get<1>(association_control_request_tlv->sta_list(0));

    auto block = association_control_request_tlv->association_control();
    if (block == wfa_map::tlvClientAssociationControlRequest::UNBLOCK) {
        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_CLIENT_ALLOW_REQUEST>(cmdu_tx, mid);
        if (!request_out) {
            LOG(ERROR) << "Failed building ACTION_APMANAGER_CLIENT_ALLOW_REQUEST message!";
            return false;
        }

        request_out->mac()   = sta_mac;
        request_out->bssid() = bssid;
    } else if (block == wfa_map::tlvClientAssociationControlRequest::BLOCK) {
        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_CLIENT_DISALLOW_REQUEST>(cmdu_tx, mid);
        if (!request_out) {
            LOG(ERROR) << "Failed building ACTION_APMANAGER_CLIENT_DISALLOW_REQUEST message!";
            return false;
        }

        request_out->mac()                 = sta_mac;
        request_out->bssid()               = bssid;
        request_out->validity_period_sec() = association_control_request_tlv->validity_period_sec();
    }

    message_com::send_cmdu(ap_manager_socket, cmdu_tx);

    if (!cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return false;
    }

    LOG(DEBUG) << "sending ACK message back to controller";
    return send_cmdu_to_controller(cmdu_tx);
}

bool slave_thread::handle_1905_higher_layer_data_message(Socket &sd,
                                                         ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // Only one son_slave should return ACK for higher layer data message, therefore ignore
    // this message on non backhaul manager son_slaves.
    if (!is_backhaul_manager) {
        return true;
    }

    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received HIGHER_LAYER_DATA_MESSAGE , mid=" << std::hex << int(mid);

    auto tlvHigherLayerData = cmdu_rx.getClass<wfa_map::tlvHigherLayerData>();
    if (!tlvHigherLayerData) {
        LOG(ERROR) << "addClass wfa_map::tlvHigherLayerData failed";
        return false;
    }

    const auto protocol       = tlvHigherLayerData->protocol();
    const auto payload_length = tlvHigherLayerData->payload_length();
    LOG(DEBUG) << "Protocol: " << std::hex << int(protocol);
    LOG(DEBUG) << "Payload-Length: " << std::hex << int(payload_length);

    // Build ACK message CMDU
    auto cmdu_tx_header = cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);
    if (!cmdu_tx_header) {
        LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
        return false;
    }
    LOG(DEBUG) << "Sending ACK message to the originator, mid=" << std::hex << int(mid);
    return send_cmdu_to_controller(cmdu_tx);
}

bool slave_thread::handle_ack_message(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    //TODO - this is a stub handler for the purpose of controller certification testing,
    //       will be implemented later on agent certification
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received ACK_MESSAGE, mid=" << std::dec << int(mid);
    return true;
}

bool slave_thread::handle_client_steering_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    const auto mid = cmdu_rx.getMessageId();

    auto steering_request_tlv          = cmdu_rx.getClass<wfa_map::tlvSteeringRequest>();
    auto steering_request_tlv_profile2 = cmdu_rx.getClass<wfa_map::tlvProfile2SteeringRequest>();
    if (!steering_request_tlv && !steering_request_tlv_profile2) {
        LOG(ERROR) << "addClass wfa_map::tlvSteeringRequest failed";
        return false;
    }

    LOG(DEBUG) << "Received CLIENT_STEERING_REQUEST_MESSAGE , mid=" << std::hex << int(mid);

    auto request_mode = steering_request_tlv_profile2
                            ? steering_request_tlv_profile2->request_flags().request_mode
                            : steering_request_tlv->request_flags().request_mode;
    LOG(DEBUG) << "request_mode: " << std::hex << int(request_mode);

    if (request_mode ==
        wfa_map::tlvSteeringRequest::REQUEST_IS_A_STEERING_MANDATE_TO_TRIGGER_STEERING) {
        //TODO Handle 0 or more then 1 sta in list, currenlty cli steers only 1 client
        LOG(DEBUG) << "Request Mode bit is set - Steering Mandate";

        auto request_out = message_com::create_vs_message<
            beerocks_message::cACTION_APMANAGER_CLIENT_BSS_STEER_REQUEST>(cmdu_tx, mid);
        if (!request_out) {
            LOG(ERROR) << "Failed building ACTION_APMANAGER_CLIENT_BSS_STEER_REQUEST message!";
            return false;
        }

        if (steering_request_tlv_profile2) {
            auto bssid_list                 = steering_request_tlv_profile2->target_bssid_list(0);
            request_out->params().cur_bssid = steering_request_tlv_profile2->bssid();
            request_out->params().mac = std::get<1>(steering_request_tlv_profile2->sta_list(0));
            request_out->params().disassoc_timer_ms =
                steering_request_tlv_profile2->btm_disassociation_timer_ms();
            request_out->params().target.bssid = std::get<1>(bssid_list).target_bssid;
            request_out->params().target.operating_class =
                std::get<1>(bssid_list).target_bss_operating_class;
            request_out->params().target.channel =
                std::get<1>(bssid_list).target_bss_channel_number;
            request_out->params().disassoc_imminent =
                steering_request_tlv_profile2->request_flags().btm_disassociation_imminent_bit;
            request_out->params().target.reason = std::get<1>(bssid_list).target_bss_reason_code;
        } else {
            auto bssid_list                 = steering_request_tlv->target_bssid_list(0);
            request_out->params().cur_bssid = steering_request_tlv->bssid();
            request_out->params().mac       = std::get<1>(steering_request_tlv->sta_list(0));
            request_out->params().disassoc_timer_ms =
                steering_request_tlv->btm_disassociation_timer_ms();
            request_out->params().target.bssid = std::get<1>(bssid_list).target_bssid;
            request_out->params().target.operating_class =
                std::get<1>(bssid_list).target_bss_operating_class;
            request_out->params().target.channel =
                std::get<1>(bssid_list).target_bss_channel_number;
            request_out->params().disassoc_imminent =
                steering_request_tlv->request_flags().btm_disassociation_imminent_bit;
            request_out->params().target.reason = -1; // Mark that reason is not added
        }

        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
        return true;
    } else {

        // Handling of steering opportunity

        // NOTE: the implementation below does not actually take the steering
        // opportunity and tries to steer. Instead, it just reports ACK
        // and steering-completed.
        // Taking no action is a legitimate result of steering opportunity request,
        // and this is what is done here.
        // Later in time we may actually implement the opportunity to steer.

        LOG(DEBUG) << "Request Mode bit is not set - Steering Opportunity";

        auto cmdu_tx_header = cmdu_tx.create(mid, ieee1905_1::eMessageType::ACK_MESSAGE);

        if (!cmdu_tx_header) {
            LOG(ERROR) << "cmdu creation of type ACK_MESSAGE, has failed";
            return false;
        }

        LOG(DEBUG) << "sending ACK message back to controller";
        send_cmdu_to_controller(cmdu_tx);

        // build and send steering completed message
        cmdu_tx_header = cmdu_tx.create(0, ieee1905_1::eMessageType::STEERING_COMPLETED_MESSAGE);

        if (!cmdu_tx_header) {
            LOG(ERROR) << "cmdu creation of type STEERING_COMPLETED_MESSAGE, has failed";
            return false;
        }
        LOG(DEBUG) << "sending STEERING_COMPLETED_MESSAGE back to controller";
        return send_cmdu_to_controller(cmdu_tx);
    }
}

bool slave_thread::handle_beacon_metrics_query(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received BEACON_METRICS_QUERY_MESSAGE, mid=" << std::hex << int(mid);

    // create vs message
    auto request_out =
        message_com::create_vs_message<beerocks_message::cACTION_MONITOR_CLIENT_BEACON_11K_REQUEST>(
            cmdu_tx, mid);
    if (request_out == nullptr) {
        LOG(ERROR) << "Failed building ACTION_MONITOR_CLIENT_BEACON_11K_REQUEST message!";
        return false;
    }

    if (!gate::load(request_out, cmdu_rx)) {
        LOG(ERROR) << "failed translating 1905 message to vs message";
        return false;
    }

    message_com::send_cmdu(monitor_socket, cmdu_tx);

    return true;
}

bool slave_thread::handle_ap_metrics_query(Socket &sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    uint16_t length = message_com::get_uds_header(cmdu_rx)->length;
    cmdu_rx.swap(); // swap back before forwarding
    if (!message_com::forward_cmdu_to_uds(monitor_socket, cmdu_rx, length)) {
        LOG(ERROR) << "Failed sending AP_METRICS_QUERY_MESSAGE message to monitor_socket";
        return false;
    }
    return true;
}

bool slave_thread::handle_monitor_ap_metrics_response(Socket &sd,
                                                      ieee1905_1::CmduMessageRx &cmdu_rx)
{
    uint16_t length = message_com::get_uds_header(cmdu_rx)->length;
    cmdu_rx.swap(); // swap back before forwarding
    if (!message_com::forward_cmdu_to_uds(backhaul_manager_socket, cmdu_rx, length)) {
        LOG(ERROR) << "Failed sending AP_METRICS_RESPONSE_MESSAGE message to backhaul_manager";
        return false;
    }
    return true;
}

bool slave_thread::handle_channel_preference_query(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received CHANNEL_PREFERENCE_QUERY_MESSAGE, mid=" << std::dec << int(mid);

    auto request_out =
        message_com::create_vs_message<beerocks_message::cACTION_APMANAGER_CHANNELS_LIST_REQUEST>(
            cmdu_tx, mid);

    if (!request_out) {
        LOG(ERROR) << "Failed building message ACTION_APMANAGER_CHANNELS_LIST_REQUEST!";
        return false;
    }
    return message_com::send_cmdu(ap_manager_socket, cmdu_tx);
}

wfa_map::cPreferenceOperatingClasses::ePreference
slave_thread::get_channel_preference(beerocks::message::sWifiChannel channel,
                                     const sChannelPreference &preference,
                                     const std::set<uint8_t> &preference_channels_list)
{
    // According to Table 23 in the MultiAP Specification, an empty channel list field
    // indicates that the indicated preference applies to all channels in the operating class.
    if (preference_channels_list.empty()) {
        return wfa_map::cPreferenceOperatingClasses::ePreference(preference.flags.preference);
    }

    uint8_t center_channel = 0;
    auto bw                = static_cast<beerocks::eWiFiBandwidth>(channel.channel_bandwidth);
    auto operating_class   = wireless_utils::get_operating_class_by_channel(channel);

    LOG_IF(operating_class != preference.operating_class, FATAL)
        << "Invalid channel operating class " << int(operating_class)
        << ", preference operating class is " << int(preference.operating_class);

    // operating classes 128,129,130 use center channel **unlike the other classes**,
    // so convert channel and bandwidth to center channel.
    // For more info, refer to Table E-4 in the 802.11 specification.
    if (operating_class == 128 || operating_class == 129 || operating_class == 130) {
        center_channel = wireless_utils::get_5g_center_channel(channel.channel, bw);
    }

    // explicitely restrict non-operable channels
    auto channel_to_check =
        (operating_class == 128 || operating_class == 129 || operating_class == 130)
            ? center_channel
            : channel.channel;
    for (const auto ch : preference_channels_list) {
        if (channel_to_check == ch) {
            return wfa_map::cPreferenceOperatingClasses::ePreference(preference.flags.preference);
        }
    }
    // Default to the highest preference
    return wfa_map::cPreferenceOperatingClasses::ePreference::PREFERRED14;
}

beerocks::message::sWifiChannel slave_thread::channel_selection_select_channel()
{
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return {};
    }

    for (const auto &preference : m_controller_channel_preferences) {
        auto &preference_info         = preference.first;
        auto &preference_channel_list = preference.second;

        if (preference_channel_list.empty()) {
            continue;
        }
        for (const auto &channel_info_pair : radio->channels_list) {
            auto channel       = channel_info_pair.first;
            auto &channel_info = channel_info_pair.second;
            for (auto &bw_info : channel_info.supported_bw_list) {

                beerocks::message::sWifiChannel wifi_channel(channel, bw_info.bandwidth);
                auto operating_class = wireless_utils::get_operating_class_by_channel(wifi_channel);

                // Skip DFS channels
                if (channel_info.dfs_state != beerocks_message::eDfsState::NOT_DFS) {
                    LOG(DEBUG) << "Skip DFS channel " << channel << ", operating class "
                               << operating_class;
                    continue;
                }
                // Skip channels from other operating classes.
                if (operating_class != preference_info.operating_class) {
                    continue;
                }
                // Skip restricted channels
                if (get_channel_preference(wifi_channel, preference_info,
                                           preference_channel_list) ==
                    wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE) {
                    LOG(DEBUG) << "Skip restricted channel " << channel << ", operating class "
                               << operating_class;
                    continue;
                }
                // If we got this far, we found a candidate channel, so switch to it
                LOG(DEBUG) << "Selected channel " << channel << ", operating class "
                           << operating_class;
                return wifi_channel;
            }
        }
    }

    LOG(ERROR) << "Could not find a suitable channel";
    return beerocks::message::sWifiChannel();
}

bool slave_thread::channel_selection_current_channel_restricted()
{
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }

    beerocks::message::sWifiChannel channel(radio->channel, radio->bandwidth);
    auto operating_class = wireless_utils::get_operating_class_by_channel(channel);

    if (operating_class == 0) {
        LOG(ERROR) << "Unknown operating class for bandwidth= " << channel.channel_bandwidth
                   << " channel=" << channel.channel
                   << ". Considering the channel to be restricted";
        return true;
    }

    LOG(DEBUG) << "Current channel " << int(channel.channel) << " bw "
               << beerocks::utils::convert_bandwidth_to_int(
                      beerocks::eWiFiBandwidth(channel.channel_bandwidth))
               << " oper_class " << int(operating_class);
    for (const auto &preference : m_controller_channel_preferences) {
        // for now we handle only non-operable preference
        // TODO - handle as part of https://github.com/prplfoundation/prplMesh/issues/725
        auto &preference_info         = preference.first;
        auto &preference_channel_list = preference.second;
        if (preference_info.flags.preference !=
            wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE) {
            LOG(WARNING) << "Ignoring operable channels preference";
            continue;
        }
        // Skip channels from other operating classes.
        if (operating_class != preference_info.operating_class) {
            continue;
        }
        if (get_channel_preference(channel, preference_info, preference_channel_list) ==
            wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE) {
            LOG(INFO) << "Current channel " << int(channel.channel)
                      << " restricted, channel switch required";
            return true;
        }
    }
    LOG(INFO) << "Current channel " << int(channel.channel)
              << " not restricted, channel switch not required";
    return false;
}

bool slave_thread::get_controller_channel_preference(ieee1905_1::CmduMessageRx &cmdu_rx)
{
    m_controller_channel_preferences.clear();
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }

    for (auto channel_preference_tlv : cmdu_rx.getClassList<wfa_map::tlvChannelPreference>()) {

        const auto &ruid = channel_preference_tlv->radio_uid();
        if (ruid != radio->front.iface_mac) {
            LOG(DEBUG) << "ruid_rx=" << ruid << ", son_slave_ruid=" << radio->front.iface_mac;
            continue;
        }

        // read all operating class list
        auto operating_classes_list_length =
            channel_preference_tlv->operating_classes_list_length();

        for (int oc_idx = 0; oc_idx < operating_classes_list_length; oc_idx++) {
            std::stringstream ss;
            auto operating_class_tuple = channel_preference_tlv->operating_classes_list(oc_idx);
            if (!std::get<0>(operating_class_tuple)) {
                LOG(ERROR) << "getting operating class entry has failed!";
                return false;
            }
            auto &op_class_channels = std::get<1>(operating_class_tuple);
            auto operating_class    = op_class_channels.operating_class();

            auto channel_preference =
                sChannelPreference(op_class_channels.operating_class(), op_class_channels.flags());

            const auto &op_class_chan_set =
                wireless_utils::operating_class_to_channel_set(operating_class);
            ss << "operating class=" << +operating_class;

            auto channel_list_length = op_class_channels.channel_list_length();

            ss << ", preference=" << +channel_preference.flags.preference
               << ", reason=" << +channel_preference.flags.reason_code;
            ss << ", channel_list={";
            if (channel_list_length == 0) {
                ss << "}";
            }

            auto &channels_set = m_controller_channel_preferences[channel_preference];

            for (int ch_idx = 0; ch_idx < channel_list_length; ch_idx++) {
                auto channel = op_class_channels.channel_list(ch_idx);
                if (!channel) {
                    LOG(ERROR) << "getting channel entry has failed!";
                    return false;
                }

                // Check if channel is valid for operating class
                if (op_class_chan_set.find(*channel) == op_class_chan_set.end()) {
                    LOG(ERROR) << "Channel " << *channel << " invalid for operating class "
                               << operating_class;
                    return false;
                }

                ss << +(*channel);

                // add comma if not last channel in the list, else close list by add curl brackets
                ss << (((ch_idx + 1) != channel_list_length) ? "," : "}");

                channels_set.insert(*channel);
            }
            LOG(DEBUG) << ss.str();
        }
    }

    return true;
}

bool slave_thread::channel_selection_get_transmit_power_limit(ieee1905_1::CmduMessageRx &cmdu_rx,
                                                              int &power_limit)
{
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }
    for (const auto &tx_power_limit_tlv : cmdu_rx.getClassList<wfa_map::tlvTransmitPowerLimit>()) {

        const auto &ruid = tx_power_limit_tlv->radio_uid();
        if (ruid != radio->front.iface_mac) {
            LOG(DEBUG) << "ruid_rx=" << ruid << ", son_slave_ruid=" << radio->front.iface_mac;
            continue;
        }

        power_limit = tx_power_limit_tlv->transmit_power_limit_dbm();
        LOG(DEBUG) << std::dec << "received tlvTransmitPowerLimit " << (int)power_limit;
        // Only one limit per ruid
        return true;
    }
    return false;
}

bool slave_thread::handle_channel_selection_request(Socket *sd, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    const auto mid = cmdu_rx.getMessageId();
    LOG(DEBUG) << "Received CHANNEL_SELECTION_REQUEST_MESSAGE, mid=" << std::dec << int(mid);

    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }

    int power_limit           = 0;
    bool power_limit_received = channel_selection_get_transmit_power_limit(cmdu_rx, power_limit);

    auto response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::ACCEPT;
    beerocks::message::sWifiChannel channel_to_switch;
    bool switch_required = false;
    if (get_controller_channel_preference(cmdu_rx)) {
        // Only restricted channels are be included in channel selection request.
        if (channel_selection_current_channel_restricted()) {
            channel_to_switch = channel_selection_select_channel();
            if (channel_to_switch.channel != 0) {
                switch_required = true;
                LOG(INFO) << "Switch to channel " << channel_to_switch.channel << ", bw "
                          << beerocks::utils::convert_bandwidth_to_int(
                                 beerocks::eWiFiBandwidth(channel_to_switch.channel_bandwidth));
            } else {
                LOG(INFO) << "Decline channel selection request " << radio->front.iface_mac;
                response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
                    DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES;
            }
        }
    } else {
        LOG(ERROR) << "Failed to update channel preference";
        response_code = wfa_map::tlvChannelSelectionResponse::eResponseCode::
            DECLINE_VIOLATES_MOST_RECENTLY_REPORTED_PREFERENCES;
    }

    // build and send channel response message
    if (!cmdu_tx.create(mid, ieee1905_1::eMessageType::CHANNEL_SELECTION_RESPONSE_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type CHANNEL_SELECTION_RESPONSE_MESSAGE, has failed";
        return false;
    }

    auto channel_selection_response_tlv = cmdu_tx.addClass<wfa_map::tlvChannelSelectionResponse>();
    if (!channel_selection_response_tlv) {
        LOG(ERROR) << "addClass ieee1905_1::tlvChannelSelectionResponse has failed";
        return false;
    }

    channel_selection_response_tlv->radio_uid()     = radio->front.iface_mac;
    channel_selection_response_tlv->response_code() = response_code;
    if (!message_com::send_cmdu(backhaul_manager_socket, cmdu_tx)) {
        LOG(ERROR) << "failed to send CHANNEL_SELECTION_RESPONSE_MESSAGE";
        return false;
    }

    // Normally, when a channel switch is required, a CSA notification
    // will be received with the new channel setting which is when
    // the agent will send the operating channel report.
    // In case of only a tx power limit change, there will still be
    // a CSA notification which will hold the new power limit and also
    // trigger sending the operating channel report.
    // If neither channel switch nor power limit change is required,
    // we need to explicitly send the event.
    if (!switch_required && !power_limit_received) {
        LOG(DEBUG) << "Channel switch not required, sending operating channel report";
        send_operating_channel_report();
        return true;
    }

    auto request_out = message_com::create_vs_message<
        beerocks_message::cACTION_APMANAGER_HOSTAP_CHANNEL_SWITCH_ACS_START>(cmdu_tx, mid);
    if (!request_out) {
        LOG(ERROR) << "Failed building message!";
        return false;
    }

    LOG(DEBUG) << "send ACTION_APMANAGER_HOSTAP_CHANNEL_SWITCH_ACS_START";

    // If only tx power limit change is required, set channel to current
    request_out->cs_params().channel = switch_required ? channel_to_switch.channel : radio->channel;
    request_out->cs_params().bandwidth =
        switch_required ? channel_to_switch.channel_bandwidth : uint8_t(radio->bandwidth);
    request_out->tx_limit()       = power_limit;
    request_out->tx_limit_valid() = power_limit_received;

    ///////////////////////////////////////////////////////////////////
    // TODO https://github.com/prplfoundation/prplMesh/issues/797
    //
    // Short term solution
    // In non-EasyMesh mode, never modify hostapd configuration
    // and in this case don't switch channel
    //
    ////////////////////////////////////////////////////////////////////
    if (db->device_conf.management_mode != BPL_MGMT_MODE_NOT_MULTIAP) {
        message_com::send_cmdu(ap_manager_socket, cmdu_tx);
    } else {
        LOG(WARNING) << "non-EasyMesh mode - skip channel switch";
    }

    return true;
}

bool slave_thread::send_operating_channel_report()
{
    // build and send operating channel report message
    if (!cmdu_tx.create(0, ieee1905_1::eMessageType::OPERATING_CHANNEL_REPORT_MESSAGE)) {
        LOG(ERROR) << "cmdu creation of type OPERATING_CHANNEL_REPORT_MESSAGE, has failed";
        return false;
    }

    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return false;
    }

    auto operating_channel_report_tlv = cmdu_tx.addClass<wfa_map::tlvOperatingChannelReport>();
    if (!operating_channel_report_tlv) {
        LOG(ERROR) << "addClass ieee1905_1::operating_channel_report_tlv has failed";
        return false;
    }
    operating_channel_report_tlv->radio_uid() = radio->front.iface_mac;

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
    beerocks::message::sWifiChannel channel;
    channel.channel_bandwidth = radio->bandwidth;
    channel.channel           = radio->channel;
    auto center_channel       = wireless_utils::freq_to_channel(radio->vht_center_frequency);
    auto operating_class      = wireless_utils::get_operating_class_by_channel(channel);

    operating_class_entry.operating_class = operating_class;
    // operating classes 128,129,130 use center channel **unlike the other classes** (See Table E-4 in 802.11 spec)
    operating_class_entry.channel_number =
        (operating_class == 128 || operating_class == 129 || operating_class == 130)
            ? center_channel
            : channel.channel;
    operating_channel_report_tlv->current_transmit_power() = radio->tx_power_dB;

    return send_cmdu_to_controller(cmdu_tx);
}

bool slave_thread::autoconfig_wsc_add_m1()
{
    auto tlv = cmdu_tx.addClass<ieee1905_1::tlvWsc>();
    if (tlv == nullptr) {
        LOG(ERROR) << "Error creating tlvWsc";
        return false;
    }

    // Allocate maximum allowed length for the payload, so it can accommodate variable length
    // data inside the internal TLV list.
    // On finalize(), the buffer is shrunk back to its real size.
    size_t payload_length =
        tlv->getBuffRemainingBytes() - ieee1905_1::tlvEndOfMessage::get_initial_size();
    tlv->alloc_payload(payload_length);

    WSC::m1::config cfg;
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(ERROR) << "Cannot find radio for " << m_fronthaul_iface;
        return false;
    }

    cfg.msg_type = WSC::eWscMessageType::WSC_MSG_TYPE_M1;
    cfg.mac      = db->bridge.mac;
    dh           = std::make_unique<mapf::encryption::diffie_hellman>();
    std::copy(dh->nonce(), dh->nonce() + dh->nonce_length(), cfg.enrollee_nonce);
    copy_pubkey(*dh, cfg.pub_key);
    cfg.auth_type_flags =
        WSC::eWscAuth(WSC::eWscAuth::WSC_AUTH_OPEN | WSC::eWscAuth::WSC_AUTH_WPA2PSK |
                      WSC::eWscAuth::WSC_AUTH_SAE);
    cfg.encr_type_flags     = uint16_t(WSC::eWscEncr::WSC_ENCR_AES);
    cfg.manufacturer        = "prplMesh";
    cfg.model_name          = "Ubuntu";
    cfg.model_number        = "18.04";
    cfg.serial_number       = "prpl12345";
    cfg.primary_dev_type_id = WSC::WSC_DEV_NETWORK_INFRA_AP;
    cfg.device_name         = "prplmesh-agent";
    cfg.bands = wireless_utils::is_frequency_band_5ghz(radio->freq_type) ? WSC::WSC_RF_BAND_5GHZ
                                                                         : WSC::WSC_RF_BAND_2GHZ;
    auto attributes = WSC::m1::create(*tlv, cfg);
    if (!attributes)
        return false;

    // Authentication support - store swapped M1 for later M1 || M2* authentication
    // This is the content of M1, without the type and length.
    if (m1_auth_buf)
        delete[] m1_auth_buf;
    m1_auth_buf_len = attributes->len();
    m1_auth_buf     = new uint8_t[m1_auth_buf_len];
    std::copy_n(attributes->buffer(), m1_auth_buf_len, m1_auth_buf);
    return true;
}

void slave_thread::fill_channel_list_to_agent_db(
    const std::shared_ptr<beerocks_message::cChannelList> &channel_list_class)
{
    if (!channel_list_class) {
        LOG(ERROR) << "Channel list is nullptr";
        return;
    }

    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        return;
    }

    // Copy channels list to the AgentDB
    auto channels_list_length = channel_list_class->channels_list_length();
    for (uint8_t ch_idx = 0; ch_idx < channels_list_length; ch_idx++) {
        auto &channel_info = std::get<1>(channel_list_class->channels_list(ch_idx));
        auto channel       = channel_info.beacon_channel();
        radio->channels_list[channel].tx_power_dbm = channel_info.tx_power_dbm();
        radio->channels_list[channel].dfs_state    = channel_info.dfs_state();
        auto supported_bw_size                     = channel_info.supported_bandwidths_length();
        radio->channels_list[channel].supported_bw_list.resize(supported_bw_size);
        std::copy_n(&std::get<1>(channel_info.supported_bandwidths(0)), supported_bw_size,
                    radio->channels_list[channel].supported_bw_list.begin());

        for (const auto &supported_bw : radio->channels_list[channel].supported_bw_list) {
            LOG(DEBUG) << "channel=" << int(channel) << ", bw="
                       << beerocks::utils::convert_bandwidth_to_int(
                              beerocks::eWiFiBandwidth(supported_bw.bandwidth))
                       << ", rank=" << supported_bw.rank
                       << ", multiap_preference=" << int(supported_bw.multiap_preference);
        }
    }
}

void slave_thread::save_channel_params_to_db(beerocks_message::sApChannelSwitch params)
{
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return;
    }

    radio->channel                   = params.channel;
    radio->bandwidth                 = static_cast<beerocks::eWiFiBandwidth>(params.bandwidth);
    radio->channel_ext_above_primary = params.channel_ext_above_primary;
    radio->vht_center_frequency      = params.vht_center_frequency;
    radio->tx_power_dB               = params.tx_power;
}

void slave_thread::save_cac_capabilities_params_to_db()
{
    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        LOG(DEBUG) << "Radio of interface " << m_fronthaul_iface << " does not exist on the db";
        return;
    }
    if (son::wireless_utils::is_frequency_band_5ghz(radio->freq_type)) {
        AgentDB::sRadio::sCacCapabilities::sCacMethodCapabilities cac_capabilities_local;

        // we'll update the value when we receive cac-started event.
        // there is no way to query the hardware until a CAC is
        // actually performed.
        // Until PPM-855 is solved we will set the value to 10 minutes as default.
        cac_capabilities_local.cac_duration_sec = 600;

        for (const auto &channel_info_element : radio->channels_list) {
            auto channel       = channel_info_element.first;
            auto &channel_info = channel_info_element.second;
            if (channel_info.dfs_state == beerocks_message::eDfsState::NOT_DFS) {
                continue;
            }
            for (auto &bw_info : channel_info.supported_bw_list) {
                auto wifi_channel    = beerocks::message::sWifiChannel(channel, bw_info.bandwidth);
                auto operating_class = wireless_utils::get_operating_class_by_channel(wifi_channel);
                if (operating_class == 0) {
                    continue;
                }
                cac_capabilities_local.operating_classes[operating_class].push_back(
                    wifi_channel.channel);
            }
        }

        cac_capabilities_local.cac_method = wfa_map::eCacMethod::CONTINUOUS_CAC;

        // insert "regular" 5g
        radio->cac_capabilities.cac_method_capabilities.insert(
            std::make_pair(cac_capabilities_local.cac_method, cac_capabilities_local));

        // insert zwdfs 5g
        if (radio->front.zwdfs) {
            cac_capabilities_local.cac_method = wfa_map::eCacMethod::MIMO_DIMENSION_REDUCED;
            radio->cac_capabilities.cac_method_capabilities.insert(
                std::make_pair(cac_capabilities_local.cac_method, cac_capabilities_local));
        }
    }
}

std::map<slave_thread::sChannelPreference, std::set<uint8_t>>
slave_thread::get_channel_preferences_from_channels_list()
{
    std::map<sChannelPreference, std::set<uint8_t>> preferences;

    auto db    = AgentDB::get();
    auto radio = db->radio(m_fronthaul_iface);
    if (!radio) {
        return {};
    }

    for (const auto &oper_class : wireless_utils::operating_classes_list) {
        auto oper_class_num             = oper_class.first;
        const auto &oper_class_channels = oper_class.second.channels;
        auto oper_class_bw              = oper_class.second.band;

        for (auto channel_of_oper_class : oper_class_channels) {

            // Operating classes 128,129,130 use center channel **unlike the other classes**,
            // so convert channel and bandwidth to center channel.
            // For more info, refer to Table E-4 in the 802.11 specification.
            std::vector<uint8_t> beacon_channels;
            if (oper_class_num == 128 || oper_class_num == 129 || oper_class_num == 130) {
                beacon_channels = wireless_utils::center_channel_5g_to_beacon_channels(
                    channel_of_oper_class, oper_class_bw);
            } else {
                beacon_channels.push_back(channel_of_oper_class);
            }

            for (const auto beacon_channel : beacon_channels) {

                // Channel is not supported.
                auto it_ch = radio->channels_list.find(beacon_channel);
                if (it_ch == radio->channels_list.end()) {

                    sChannelPreference pref(
                        oper_class_num,
                        wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                        wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
                    preferences[pref].insert(channel_of_oper_class);
                    break;
                }

                // Bandwidth of a channel is not supported.
                auto &supported_channel_info = it_ch->second;
                auto &supported_bw_list      = supported_channel_info.supported_bw_list;
                auto it_bw =
                    std::find_if(supported_bw_list.begin(), supported_bw_list.end(),
                                 [&](const beerocks_message::sSupportedBandwidth &bw_info) {
                                     return bw_info.bandwidth == oper_class_bw;
                                 });
                if (it_bw == supported_bw_list.end()) {
                    sChannelPreference pref(
                        oper_class_num,
                        wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                        wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
                    preferences[pref].insert(channel_of_oper_class);
                    break;
                }

                // The rest of the checks are relevant only for 5 GHz band.
                if (son::wireless_utils::channels_table_5g.find(beacon_channel) !=
                    son::wireless_utils::channels_table_5g.end()) {

                    // Channel DFS state is "Unavailable".
                    auto overlapping_beacon_channels =
                        son::wireless_utils::get_overlapping_beacon_channels(beacon_channel,
                                                                             oper_class_bw);

                    auto preference_size = preferences.size();
                    for (const auto overlap_ch : overlapping_beacon_channels) {
                        it_ch = radio->channels_list.find(overlap_ch);
                        if (it_ch == radio->channels_list.end()) {
                            LOG(ERROR) << "Overlap channel " << overlap_ch << " is not supported";
                            sChannelPreference pref(
                                oper_class_num,
                                wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                                wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
                            preferences[pref].insert(channel_of_oper_class);
                            break;
                        }

                        auto &overlap_channel_info = it_ch->second;

                        if (overlap_channel_info.dfs_state ==
                            beerocks_message::eDfsState::UNAVAILABLE) {
                            sChannelPreference pref(
                                oper_class_num,
                                wfa_map::cPreferenceOperatingClasses::ePreference::NON_OPERABLE,
                                wfa_map::cPreferenceOperatingClasses::eReasonCode::
                                    OPERATION_DISALLOWED_DUE_TO_RADAR_DETECTION_ON_A_DFS_CHANNEL);
                            preferences[pref].insert(channel_of_oper_class);
                            break;
                        }
                    }

                    // If an unavailable channel has been inserted, skip to the next channel and not
                    // add a valid preference (code below). This is because the checks above are
                    // done in internal for-loop in which the break calls inside it, breaks the
                    // internal loop.
                    if (preference_size != preferences.size()) {
                        break;
                    }
                }

                /**
                 * For now do not insert the real channel preference. It will be uncomment in
                 * a separated Merge Request after testing it. PPM-655.
                 */

                // // Channel is supported and have valid preference.
                // sChannelPreference pref(
                //     oper_class_num,
                //     static_cast<wfa_map::cPreferenceOperatingClasses::ePreference>(
                //         it_bw->multiap_preference),
                //     wfa_map::cPreferenceOperatingClasses::eReasonCode::UNSPECIFIED);
                // preferences[pref].insert(channel_of_oper_class);
            }
        }
    }
    return preferences;
}
