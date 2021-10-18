/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "base_wlan_hal_nl80211.h"

#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_wireless_utils.h>
#include <bwl/nl80211_client_factory.h>

#include <easylogging++.h>

extern "C" {
#include <wpa_ctrl.h>
}

#include <linux/nl80211.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

namespace bwl {
namespace nl80211 {

//////////////////////////////////////////////////////////////////////////////
///////////////////////// Local Module Definitions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

#define BASE_CTRL_PATH "/var/run/"
#define AP_ENABELED_TIMEOUT_SEC 15
#define AP_ENABELED_FIXED_DFS_TIMEOUT_SEC 660

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Functions ////////////////////////////
//////////////////////////////////////////////////////////////////////////////

std::ostream &operator<<(std::ostream &out, const nl80211_fsm_state &value)
{
    switch (value) {
    case nl80211_fsm_state::Delay:
        out << "Delay";
        break;
    case nl80211_fsm_state::Init:
        out << "Init";
        break;
    case nl80211_fsm_state::GetRadioInfo:
        out << "GetRadioInfo";
        break;
    case nl80211_fsm_state::Attach:
        out << "Attach";
        break;
    case nl80211_fsm_state::Operational:
        out << "Operational";
        break;
    case nl80211_fsm_state::Detach:
        out << "Detach";
        break;
    }
    return out;
}

std::ostream &operator<<(std::ostream &out, const nl80211_fsm_event &value)
{
    switch (value) {
    case nl80211_fsm_event::Attach:
        out << "Attach";
        break;
    case nl80211_fsm_event::Detach:
        out << "Detach";
        break;
    }
    return out;
}

static void map_obj_parser(std::stringstream &ss_in, std::list<char> delimiter_list,
                           base_wlan_hal_nl80211::parsed_obj_map_t &map_obj)
{
    if (delimiter_list.empty())
        return;

    std::string str_storage, key;
    bool kv = true; // '1'=key, '0'=val;
    while (std::getline(ss_in, str_storage, delimiter_list.front())) {
        if (delimiter_list.size() == 1) {
            if (kv) {
                key = str_storage; // save key
            } else {
                map_obj[key] = str_storage; // save val
            }
            kv = !kv;

        } else {
            auto delimiter_list_out(delimiter_list);
            delimiter_list_out.erase(delimiter_list_out.begin()); // delete first delimiter
            std::stringstream ss_out(str_storage);
            map_obj_parser(ss_out, delimiter_list_out, map_obj);
        }
    }
}

static void listed_map_obj_parser(std::stringstream &ss_in, std::list<char> delimiter_list,
                                  base_wlan_hal_nl80211::parsed_obj_listed_map_t &listed_map_obj)
{
    if (delimiter_list.empty())
        return;

    std::string str_storage;
    while (std::getline(ss_in, str_storage, delimiter_list.front())) {
        auto delimiter_list_out(delimiter_list);
        delimiter_list_out.erase(delimiter_list_out.begin()); // delete first delimiter
        std::stringstream ss_out(str_storage);
        base_wlan_hal_nl80211::parsed_obj_map_t map_obj;
        map_obj_parser(ss_out, delimiter_list_out, map_obj);
        listed_map_obj.push_back(map_obj);
    }
}

static void map_event_obj_parser(std::string event_str,
                                 base_wlan_hal_nl80211::parsed_obj_map_t &map_obj)
{
    // eliminate event log level from the begining of the event string : "<3>"
    auto idx_start = event_str.find_first_of(">");
    if (idx_start != std::string::npos) {
        idx_start++;
    } else {
        LOG(WARNING) << "empty event! event_string: " << event_str;
    }

    // Parse all the args
    std::stringstream ss(event_str.c_str() + idx_start);
    std::string str_storage;
    bool opcode = false;
    bool mac    = false;
    int arg     = 0;

    while (std::getline(ss, str_storage, ' ')) {
        auto idx = str_storage.find_first_of('=', idx_start);
        if (idx == std::string::npos) {
            if (!opcode) {
                map_obj["_opcode"] = str_storage;
                opcode             = true;
            } else if (!mac && beerocks::net::network_utils::is_valid_mac(str_storage)) {
                map_obj["_mac"] = str_storage;
                mac             = true;
            } else {
                map_obj["_arg" + std::to_string(arg++)] = str_storage;
            }
        } else {
            map_obj[str_storage.substr(0, idx)] = str_storage.substr(idx + 1, std::string::npos);
        }
    }
}

#if 0

static void parsed_obj_debug(base_wlan_hal_nl80211::parsed_obj_map_t &obj)
{
    LOG(TRACE) << "parsed_obj_debug:";
    std::stringstream ss_obj;
    ss_obj << std::endl << "parsed_obj_debug: " << std::endl;
    for (auto element : obj) {
        LOG(TRACE) << "key: " << element.first << ", value: " << element.second;
        ss_obj << "key: " << element.first << ", value: " << element.second << std::endl;
    }

    LOG(DEBUG) << ss_obj.str();
}

static void parsed_obj_debug(base_wlan_hal_nl80211::parsed_obj_listed_map_t &obj)
{
    LOG(TRACE) << "parsed_obj_debug:";
    std::stringstream ss_obj;
    ss_obj << std::endl << "parsed_obj_debug: " << std::endl;
    int element_num = 0;
    for (auto list_element : obj) {
        LOG(TRACE) << "vector element: " << element_num;
        ss_obj << "vector element: " << element_num << std::endl;
        for (auto map_element : list_element) {
            LOG(TRACE) << "key: " << map_element.first << ", value: " << map_element.second;
            ss_obj << "key: " << map_element.first << ", value: " << map_element.second
                   << std::endl;
        }
        element_num++;
    }
    LOG(DEBUG) << ss_obj.str();
}

#endif

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

base_wlan_hal_nl80211::base_wlan_hal_nl80211(HALType type, const std::string &iface_name,
                                             hal_event_cb_t callback, int wpa_ctrl_buffer_size,
                                             const hal_conf_t &hal_conf)
    : base_wlan_hal(type, iface_name, IfaceType::Intel, callback, hal_conf),
      beerocks::beerocks_fsm<nl80211_fsm_state, nl80211_fsm_event>(nl80211_fsm_state::Delay),
      m_nl80211_client(nl80211_client_factory::create_instance()),
      m_wpa_ctrl_buffer_size(wpa_ctrl_buffer_size)
{
    LOG_IF(!m_nl80211_client, FATAL) << "Failed to create nl80211_client instance";
    // Allocate wpa_ctrl buffer
    if (m_wpa_ctrl_buffer_size) {
        m_wpa_ctrl_buffer = std::shared_ptr<char>(new char[m_wpa_ctrl_buffer_size], [](char *obj) {
            if (obj) {
                delete[] obj;
            }
        });
    }

    m_wpa_ctrl_path = hal_conf.wpa_ctrl_path;

    // Initialize the FSM
    fsm_setup();
}

base_wlan_hal_nl80211::~base_wlan_hal_nl80211() { base_wlan_hal_nl80211::detach(); }

bool base_wlan_hal_nl80211::fsm_setup()
{
    config()

        // Setup states:

        //////////////////////////////////////////////////////////////////////////
        ////////////////////////////// State: Delay //////////////////////////////
        //////////////////////////////////////////////////////////////////////////

        .state(nl80211_fsm_state::Delay)

        // On Entry
        .entry([&](const void *args) -> bool {
            m_state_timeout = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            return true;
        })

        // EVENT -> Attach
        .on(nl80211_fsm_event::Attach, nl80211_fsm_state::Init,
            [&](TTransition &transition, const void *args) -> bool {
                return (std::chrono::steady_clock::now() >= m_state_timeout);
            })

        //////////////////////////////////////////////////////////////////////////
        ////////////////////////////// State: Init ///////////////////////////////
        //////////////////////////////////////////////////////////////////////////

        .state(nl80211_fsm_state::Init)

        .entry([&](const void *args) -> bool {
            m_state_timeout = std::chrono::steady_clock::now() + std::chrono::seconds(200);
            return true;
        })

        // Handle "Detach" event
        .on(nl80211_fsm_event::Detach, nl80211_fsm_state::Detach)

        // Handle "Attach" event
        .on(nl80211_fsm_event::Attach,
            {nl80211_fsm_state::Attach, nl80211_fsm_state::Detach, nl80211_fsm_state::GetRadioInfo},
            [&](TTransition &transition, const void *args) -> bool {
                // Allocate and connect the netlink socket
                if (!m_nl80211_sock) {
                    if (!(m_nl80211_sock = std::shared_ptr<struct nl_sock>(
                              nl_socket_alloc(), [](struct nl_sock *obj) {
                                  if (obj) {
                                      nl_socket_free(obj);
                                  }
                              }))) {
                        LOG(ERROR) << "Failed allocating netlink socket!";
                        return false;
                    }

                    // Increase the socket's internal buffer size
                    nl_socket_set_buffer_size(m_nl80211_sock.get(), 8192, 8192);

                    // Connect the socket
                    if (genl_connect(m_nl80211_sock.get()) != 0) {
                        LOG(ERROR) << "Failed connecting netlink socket!";
                        m_nl80211_sock.reset();
                        return false;
                    }

                    // Resolve the generic nl80211 id
                    if ((m_nl80211_id = genl_ctrl_resolve(m_nl80211_sock.get(), "nl80211")) < 0) {
                        LOG(ERROR) << "nl80211 not found!";
                        return false;
                    }

                    // Store the current interface index
                    if ((m_iface_index = if_nametoindex(get_iface_name().c_str())) == 0) {
                        LOG(ERROR) << "Failed reading the index of interface " << get_iface_name()
                                   << ": " << strerror(errno);

                        return false;
                    }
                }

                // Open a control interface to wpa_supplicant/hostapd.
                if ((m_wpa_ctrl_cmd = wpa_ctrl_open(m_wpa_ctrl_path.c_str()))) {
                    if (get_type() != HALType::Station) {
                        transition.change_destination(nl80211_fsm_state::GetRadioInfo);
                    }
                    return true;
                } else {
                    LOG(DEBUG) << "wpa_ctrl_open() failed, ctrl_iface_path: " << m_wpa_ctrl_path;
                }

                // False if timeout not reached yet, and True otherwise (switch state)
                if (std::chrono::steady_clock::now() >= m_state_timeout) {
                    LOG(ERROR) << "Failed attaching to the hostapd control interface of "
                               << m_radio_info.iface_name;

                    return (transition.change_destination(nl80211_fsm_state::Detach));
                }

                // Stay in the current state
                return false;
            })

        //////////////////////////////////////////////////////////////////////////
        ////////////////////////// State: GetRadioInfo ///////////////////////////
        //////////////////////////////////////////////////////////////////////////

        .state(nl80211_fsm_state::GetRadioInfo)

        .entry([&](const void *args) -> bool {
            m_state_timeout =
                std::chrono::steady_clock::now() + std::chrono::seconds(AP_ENABELED_TIMEOUT_SEC);
            return true;
        })

        // Handle "Detach" event
        .on(nl80211_fsm_event::Detach, nl80211_fsm_state::Detach)

        .on(nl80211_fsm_event::Attach, {nl80211_fsm_state::Attach, nl80211_fsm_state::Detach},
            [&](TTransition &transition, const void *args) -> bool {
                // Attempt to read radio info
                if (!refresh_radio_info()) {
                    return (transition.change_destination(nl80211_fsm_state::Detach));
                }

                // Move to the next state
                return true;

                // if (error || (std::chrono::steady_clock::now() >= m_state_timeout)) {
                //     return (transition.change_destination(nl80211_fsm_state::Detach));
                // }

                // // Remain in the current state
                // return false;
            })

        //////////////////////////////////////////////////////////////////////////
        ///////////////////////////// State: Attach //////////////////////////////
        //////////////////////////////////////////////////////////////////////////

        .state(nl80211_fsm_state::Attach)

        // Handle "Detach" event
        .on(nl80211_fsm_event::Detach, nl80211_fsm_state::Detach)

        .on(nl80211_fsm_event::Attach, {nl80211_fsm_state::Operational, nl80211_fsm_state::Delay},
            [&](TTransition &transition, const void *args) -> bool {
                // Open a event interface to wpa_supplicant/hostapd.
                if (!(m_wpa_ctrl_event = wpa_ctrl_open(m_wpa_ctrl_path.c_str()))) {
                    LOG(DEBUG) << "wpa_ctrl_open() failed, ctrl_iface_path: " << m_wpa_ctrl_path;
                    return (transition.change_destination(nl80211_fsm_state::Delay));
                }

                // Get the wpa_supplicant/hostapd event interface file descriptor
                m_fd_ext_events = wpa_ctrl_get_fd((wpa_ctrl *)m_wpa_ctrl_event);

                // Attach to the control interface for events receiving
                int result;
                int try_cnt = 0;
                do {
                    result = wpa_ctrl_attach(
                        m_wpa_ctrl_event); // return values: 0 on success, -1 on failure, -2 on timeout
                } while (result == -2 && ++try_cnt < 3);

                if (result < 0) {
                    // Return with error
                    LOG(ERROR) << "Failed attaching to control interface of "
                               << m_radio_info.iface_name;
                    return (transition.change_destination(nl80211_fsm_state::Delay));
                }

                // Success
                LOG(DEBUG)
                    << "Open and attach an event interface to wpa_supplicant/hostapd - SUCCESS!";
                return true;
            })

        //////////////////////////////////////////////////////////////////////////
        /////////////////////////// State: Operational ///////////////////////////
        //////////////////////////////////////////////////////////////////////////

        .state(nl80211_fsm_state::Operational)

        // Handle "Detach" event
        .on(nl80211_fsm_event::Detach, nl80211_fsm_state::Detach)

        //////////////////////////////////////////////////////////////////////////
        ////////////////////////////// State: Detach /////////////////////////////
        //////////////////////////////////////////////////////////////////////////

        .state(nl80211_fsm_state::Detach)

        .entry([&](const void *args) -> bool {
            LOG(DEBUG) << "nl80211_attach_fsm - Detaching...";

            // Detach from the WPA control interface
            if (m_wpa_ctrl_event) {
                int result;
                int try_cnt = 0;
                do {
                    result = wpa_ctrl_detach(
                        m_wpa_ctrl_event); // return values: 0 on success, -1 on failure, -2 on timeout
                } while (result == -2 && ++try_cnt < 3);

                if (result < 0) {
                    LOG(WARNING) << "can't detach wpa_ctrl_event";
                }
            }

            // Release the nl80211 socket
            if (m_nl80211_sock) {
                m_nl80211_sock.reset();
                m_nl80211_id = 0;
            }

            // Close the events control interface
            wpa_ctrl_close(m_wpa_ctrl_event);
            wpa_ctrl_close(m_wpa_ctrl_cmd);

            m_wpa_ctrl_event = nullptr;
            m_wpa_ctrl_cmd   = nullptr;

            m_fd_ext_events = -1;

            return true;
        })

        // Handle "Attach" event
        .on(nl80211_fsm_event::Attach, nl80211_fsm_state::Delay);

    // Start the FSM
    return (start());
}

HALState base_wlan_hal_nl80211::attach(bool block)
{
    while (true) {

        fire(nl80211_fsm_event::Attach);
        auto attach_state = state();
        if (m_last_attach_state != attach_state) {
            LOG(DEBUG) << "NL80211 FSM " << m_radio_info.iface_name
                       << " Attach State: " << attach_state;
            m_last_attach_state = attach_state;
        }

        switch (attach_state) {
        // Initializing
        case nl80211_fsm_state::Delay:
        case nl80211_fsm_state::Init:
        case nl80211_fsm_state::GetRadioInfo:
        case nl80211_fsm_state::Attach: {
            if (block) {
                // TODO: Delay?
                continue;
            } else {
                return (m_hal_state = HALState::Initializing);
            }
        }

        // Initialization completed
        case nl80211_fsm_state::Operational: {
            return (m_hal_state = HALState::Operational);
        }

        // Initialization failed
        case nl80211_fsm_state::Detach: {
            return (m_hal_state = HALState::Failed);
        }

        // Invalid state
        default: {
            LOG(ERROR) << "Invalid NL80211 Attach State: " << int(attach_state);
        }
        }
    };
}

bool base_wlan_hal_nl80211::detach()
{
    fire(nl80211_fsm_event::Detach);
    return (state() == nl80211_fsm_state::Detach);
}

bool base_wlan_hal_nl80211::set(const std::string &param, const std::string &value, int vap_id)
{
    LOG(TRACE) << __func__ << " - NOT IMPLEMENTED!";
    return true;
}

bool base_wlan_hal_nl80211::ping()
{
    parsed_obj_map_t reply;

    if (!wpa_ctrl_send_msg("PING", reply)) {
        return false;
    }

    return true;
}

bool base_wlan_hal_nl80211::wpa_ctrl_send_msg(const std::string &cmd)
{
    int result;
    int try_cnt = 0;

    if (!m_wpa_ctrl_cmd) {
        LOG(ERROR) << "Control socket not available!";
        return false;
    }

    auto buffer = m_wpa_ctrl_buffer.get();

    auto buff_size_copy = m_wpa_ctrl_buffer_size;
    do {
        result = wpa_ctrl_request(m_wpa_ctrl_cmd, cmd.c_str(), cmd.size(), buffer, &buff_size_copy,
                                  NULL);
    } while (result == -2 && ++try_cnt < 3);

    if (result < 0) {
        LOG(ERROR) << "can't send wpa_ctrl_request";
        LOG(ERROR) << "failed cmd: " << cmd;
        return false;
    }

    if (buff_size_copy >= m_wpa_ctrl_buffer_size) {
        LOG(ERROR) << "wpa_ctrl_request returned reply of size " << buff_size_copy;
        return false;
    }

    buffer[buff_size_copy] =
        0; // the wpa_ctrl does not put null terminator at the and of the string

    if ((!strncmp(buffer, "FAIL", 4)) || (!strncmp(buffer, "UNKNOWN", 7))) {
        LOG(DEBUG) << std::endl << "cmd failed: " << cmd;
        LOG(WARNING) << std::endl << "reply: " << buffer;
        return false;
    }

    return true;
}

bool base_wlan_hal_nl80211::wpa_ctrl_send_msg(const std::string &cmd, parsed_obj_map_t &reply)
{
    if (!wpa_ctrl_send_msg(cmd)) {
        return false;
    }

    if (strncmp(m_wpa_ctrl_buffer.get(), "", 1)) {
        // if reply is not empty
        std::stringstream ss_in(m_wpa_ctrl_buffer.get());
        map_obj_parser(ss_in, {'\n', '='}, reply);
    }

    return true;
}

bool base_wlan_hal_nl80211::wpa_ctrl_send_msg(const std::string &cmd,
                                              parsed_obj_listed_map_t &reply)
{
    if (!wpa_ctrl_send_msg(cmd)) {
        return false;
    }

    if (strncmp(m_wpa_ctrl_buffer.get(), "", 1)) {
        // if reply is not empty
        std::stringstream ss_in(m_wpa_ctrl_buffer.get());
        listed_map_obj_parser(ss_in, {'\n', ' ', '='}, reply);
    }

    return true;
}

bool base_wlan_hal_nl80211::wpa_ctrl_send_msg(const std::string &cmd, char **reply)
{
    if (!reply || !(*reply)) {
        LOG(ERROR) << "Invalid reply pointer!";
        return false;
    }

    if (!wpa_ctrl_send_msg(cmd)) {
        return false;
    }

    *reply = m_wpa_ctrl_buffer.get();

    return true;
}

bool base_wlan_hal_nl80211::process_nl_events()
{
    LOG(ERROR) << __func__ << "not implemented";
    return false;
}

bool base_wlan_hal_nl80211::refresh_radio_info()
{
    parsed_obj_map_t reply;

    if (!wpa_ctrl_send_msg("STATUS", reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    // LOG(DEBUG) << "*** refresh_radio_info ***";
    // parsed_obj_debug(reply);

    // Station HAL
    if (get_type() == HALType::Station) {
        // update radio info struct
        // TODO test the the output
        // m_radio_info.wifi_ctrl_enabled = beerocks::string_utils::stoi(reply["HostapdEnabled"]);
        // m_radio_info.tx_enabled        = beerocks::string_utils::stoi(reply["TxPower"]);
        // m_radio_info.channel           = beerocks::string_utils::stoi(reply["Channel"]);
        if (m_radio_info.channel <= 0) {
            //LOG(ERROR) << "X_LANTIQ_COM_Vendor_Channel not valid: " << radio_info.channel;
            return false;
        } else if (m_radio_info.channel > 14) {
            m_radio_info.is_5ghz = true;
        }

    } else {

        // Unavailable
        m_radio_info.ant_num = 0;

        uint32_t tx_power = 0;
        if (!m_nl80211_client->get_tx_power_limit_dbm(get_iface_name(), tx_power)) {
            LOG(ERROR) << "Failed to get tx power for interface " << get_iface_name();
        }
        m_radio_info.tx_power = tx_power;

        // 0 = 20 or 40 MHz operating Channel width
        // 1 = 80 MHz channel width
        // 2 = 160 MHz channel width
        // 3 = 80+80 MHz channel width
        int vht_oper_chwidth  = 0;
        int secondary_channel = 0;
        nl80211_client::interface_info if_info;
        auto iter = reply.find("vht_oper_chwidth");
        if (iter != reply.end()) {
            vht_oper_chwidth  = beerocks::string_utils::stoi(iter->second);
            secondary_channel = beerocks::string_utils::stoi(iter->second);
        } else if (m_nl80211_client->get_interface_info(get_iface_name(), if_info)) {
            switch (if_info.bandwidth) {
            case 40:
                secondary_channel = 1;
                break;
            case 80:
                vht_oper_chwidth = 1;
                break;
            case 160:
                vht_oper_chwidth = 2;
                break;
            default:
                break;
            }
            m_radio_info.vht_center_freq = if_info.frequency_center1;
        }

        switch (vht_oper_chwidth) {
            // if vht_oper_chwidth is not set it defaults to 0
        case 0:
            if (secondary_channel == 0) {
                m_radio_info.bandwidth = 20;
            } else {
                m_radio_info.bandwidth = 40;
            }
            break;
        case 1:
            m_radio_info.bandwidth = 80;
            break;
        case 2:
            m_radio_info.bandwidth = 160;
            break;
        default:
            LOG(ERROR) << "Unknown vht_oper_chwidth " << vht_oper_chwidth
                       << ". Defaulting bandwidth to 160Mhz.";
            m_radio_info.bandwidth = 160;
        }

        //center freq = 5 GHz + (5 * index)
        iter = reply.find("vht_oper_centr_freq_seg0_idx");
        if (iter != reply.end()) {
            auto freq_idx = beerocks::string_utils::stoi(iter->second);
            if (freq_idx > 0) {
                m_radio_info.vht_center_freq = 5000 + (freq_idx * 5);
            }
        }

        LOG(DEBUG) << "radio " << m_radio_info.iface_name
                   << " bandwidth: " << m_radio_info.bandwidth;

        // State
        auto state = reply["state"];
        if (state == "ENABLED") {
            m_radio_info.wifi_ctrl_enabled = 2; // Assume Operational
            m_radio_info.tx_enabled        = 1;
        }

        m_radio_info.radio_state = radio_state_from_string(state);

        // Channel
        m_radio_info.channel = beerocks::string_utils::stoi(reply["channel"]);

        m_radio_info.is_5ghz =
            (son::wireless_utils::which_freq(m_radio_info.channel) == beerocks::eFreqType::FREQ_5G);

        // If the VAPs map is empty, refresh it as well
        // TODO: update on every refresh?
        if (!m_radio_info.available_vaps.size()) {
            if (!refresh_vaps_info(beerocks::IFACE_RADIO_ID)) {
                return false;
            }
        }
    }

    return true;
} // namespace nl80211

bool base_wlan_hal_nl80211::refresh_vaps_info(int id)
{
    LOG(TRACE) << __func__ << " - id = " << id;

    parsed_obj_map_t reply;

    // Read the radio status
    if (!wpa_ctrl_send_msg("STATUS", reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    auto fill_bss_info = [&](uint16_t vap_id) {
        VAPElement vap_element;

        // Try reading values of the requested VAP
        vap_element.bss  = reply["bss[" + std::to_string(vap_id) + "]"];
        vap_element.mac  = reply["bssid[" + std::to_string(vap_id) + "]"];
        vap_element.ssid = reply["ssid[" + std::to_string(vap_id) + "]"];
        // TODO https://github.com/prplfoundation/prplMesh/issues/1175
        vap_element.fronthaul = true;
        vap_element.backhaul  = false;

        // VAP does not exists
        if (vap_element.mac.empty()) {
            if (m_radio_info.available_vaps.find(vap_id) != m_radio_info.available_vaps.end()) {
                m_radio_info.available_vaps.erase(vap_id);
            }

            return false;
        }

        // Store the VAP element
        LOG(DEBUG) << "Detected VAP ID (" << vap_id << ") - MAC: " << vap_element.mac
                   << ", SSID: " << vap_element.ssid << ", BSS: " << vap_element.bss;

        // Since some of the required information is not exist on the "STATUS" command reply, it
        // was pre-inserted when configured the BSSs. Therefore, not overriding the whole struct at
        // the mapped value of "available_vaps[vap_id]", instead copy the struct members one by one,
        // if possible.

        auto &mapped_vap_element = m_radio_info.available_vaps[vap_id];
        if (mapped_vap_element.bss.empty()) {
            LOG(WARNING) << "BSS " << vap_element.bss << " is not preconfigured!"
                         << "Overriding VAP element.";

            mapped_vap_element = vap_element;
            return true;

        } else if (mapped_vap_element.bss != vap_element.bss) {
            LOG(ERROR) << "bss mismatch! vap_element.bss=" << vap_element.bss
                       << ", mapped_vap_element.bss=" << mapped_vap_element.bss;
            return false;
        } else if (mapped_vap_element.ssid != vap_element.ssid) {
            LOG(DEBUG) << "SSID changed from " << mapped_vap_element.ssid << ", to "
                       << vap_element.ssid << ". Overriding VAP element.";
            mapped_vap_element = vap_element;
            return true;
        }

        // If reached here, assume that the BSS information is already exist on the container,
        // therefore there is no need to update the information except the BSS mac that is not
        // preset.
        mapped_vap_element.mac = vap_element.mac;

        return true;
    };

    // If the ID is the radio ID, read all VAPS.
    if (id == beerocks::IFACE_RADIO_ID) {
        for (uint16_t vap_id = beerocks::IFACE_VAP_ID_MIN; vap_id <= beerocks::IFACE_VAP_ID_MAX;
             vap_id++) {
            if (!fill_bss_info(vap_id)) {
                break;
            }
        }
    } else {
        fill_bss_info(id);
    }

    return true;
}

bool base_wlan_hal_nl80211::process_ext_events()
{
    if (!m_wpa_ctrl_event) {
        LOG(ERROR) << "Invalid WPA Control socket (m_wpa_ctrl_event == nullptr)";
        return false;
    }

    // Check if there are pending events
    int status = wpa_ctrl_pending(m_wpa_ctrl_event);

    // No pending messages
    if (status == 0) {
        LOG(WARNING) << "Process external events called but there are no pending messages...";
        return false;
    } else if (status < 0) {
        LOG(ERROR) << "Invalid WPA Control socket status: " << status << " --> detaching!";
        detach();
        return false;
    }

    auto buffer         = m_wpa_ctrl_buffer.get();
    auto buff_size_copy = m_wpa_ctrl_buffer_size;

    if (wpa_ctrl_recv(m_wpa_ctrl_event, buffer, &buff_size_copy) < 0) {
        LOG(ERROR) << "wpa_ctrl_recv() failed!";
        return false;
    }

    // the wpa_ctrl does not put null termintaor at the and of the string
    buffer[buff_size_copy] = 0;

    LOG(DEBUG) << "event received:" << buffer;

    parsed_obj_map_t event_obj;
    map_event_obj_parser(buffer, event_obj);

    // parsed_obj_debug(event_obj);

    // Process the event
    if (!process_nl80211_event(event_obj)) {
        // LOG(ERROR) << "Failed processing NL80211 event: " << event_obj[WAV_EVENT_KEYLESS_PARAM_OPCODE];
        LOG(ERROR) << "Failed processing NL80211 event: " << event_obj["_opcode"];
        return false;
    }

    return true;
}

std::string base_wlan_hal_nl80211::get_radio_mac()
{
    std::string mac;
    if (!beerocks::net::network_utils::linux_iface_get_mac(m_radio_info.iface_name, mac)) {
        LOG(ERROR) << "Failed to get radio mac from ifname " << m_radio_info.iface_name;
    }
    return mac;
}

void base_wlan_hal_nl80211::send_ctrl_iface_cmd(std::string cmd)
{
    parsed_obj_map_t obj1;
    parsed_obj_listed_map_t obj2;

    auto last_char = cmd.back();

    LOG(DEBUG) << "last char: '" << last_char << "'";

    if (last_char == '1' || last_char == '2') {
        cmd.pop_back();
    }
    cmd = beerocks::string_utils::trimmed_substr(cmd);

    if (last_char == '1') {
        wpa_ctrl_send_msg(cmd, obj1);
    } else if (last_char == '2') {
        wpa_ctrl_send_msg(cmd, obj2);
    } else {
        wpa_ctrl_send_msg(cmd);
    }
}

bool base_wlan_hal_nl80211::send_nl80211_msg(uint8_t command, int flags,
                                             std::function<bool(struct nl_msg *msg)> msg_create,
                                             std::function<bool(struct nl_msg *msg)> msg_handle)
{
    // Netlink Message
    std::shared_ptr<nl_msg> nl_message =
        std::shared_ptr<struct nl_msg>(nlmsg_alloc(), [](struct nl_msg *obj) {
            if (obj) {
                nlmsg_free(obj);
            }
        });
    LOG_IF(!nl_message, FATAL) << "Failed creating netlink message!";

    // Netlink Callback
    std::shared_ptr<nl_cb> nl_callback =
        std::shared_ptr<struct nl_cb>(nl_cb_alloc(NL_CB_DEFAULT), [](struct nl_cb *obj) {
            if (obj) {
                nl_cb_put(obj);
            }
        });
    LOG_IF(!nl_callback, FATAL) << "Failed creating netlink callback!";

    // Create standard callbacks
    int err               = 1;
    static auto nl_err_cb = [](struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) -> int {
        int *ret = (int *)arg;
        *ret     = err->error;
        return NL_STOP;
    };

    static auto nl_finish_cb = [](struct nl_msg *msg, void *arg) -> int {
        int *ret = (int *)arg;
        *ret     = 0;
        return NL_SKIP;
    };

    static auto nl_ack_cb = [](struct nl_msg *msg, void *arg) -> int {
        int *ret = (int *)arg;
        *ret     = 0;
        return NL_STOP;
    };

    // Response handler
    auto nl_handler_cb = [](struct nl_msg *msg, void *arg) -> int {
        // Delegate to the user's response message handling function
        auto msg_handle = static_cast<std::function<bool(struct nl_msg * msg)> *>(arg);
        if (!(*msg_handle)(msg)) {
            LOG(ERROR) << "User's netlink handler function failed!";
        }
        return NL_SKIP;
    };

    // Initialize the netlink message
    if (!genlmsg_put(nl_message.get(), 0, 0, m_nl80211_id, 0, flags, command, 0) ||
        nla_put_u32(nl_message.get(), NL80211_ATTR_IFINDEX, m_iface_index) != 0) {
        LOG(ERROR) << "Failed initializing the netlink message!";
        return false;
    }

    // Call the user's message create function
    if (!msg_create(nl_message.get())) {
        LOG(ERROR) << "User's netlink create function failed!";
        return false;
    }

    // Set the callbacks to handle the events fired by the Netlink library
    nl_cb_err(nl_callback.get(), NL_CB_CUSTOM, nl_err_cb, &err);
    nl_cb_set(nl_callback.get(), NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_cb, &err);
    nl_cb_set(nl_callback.get(), NL_CB_ACK, NL_CB_CUSTOM, nl_ack_cb, &err);
    nl_cb_set(nl_callback.get(), NL_CB_VALID, NL_CB_CUSTOM, nl_handler_cb, &msg_handle);

    // Send the netlink message
    err = nl_send_auto_complete(m_nl80211_sock.get(), nl_message.get());
    if (err < 0) {
        LOG(ERROR) << "nl_send_auto_complete failed: " << err;
        return false;
    }

    // Process the response
    // TODO: Probably should be changed to select/epoll...
    //       The file descriptor can be extracted by calling the
    //       nl_socket_get_fd() function.
    while (err > 0) {
        nl_recvmsgs(m_nl80211_sock.get(), nl_callback.get());
    }

    return true;
}

bool base_wlan_hal_nl80211::nl80211_channel_scan_trigger(
    std::function<bool(struct nl_msg *msg)> msg_create,
    std::function<bool(struct nl_msg *msg)> msg_handle)
{
    // Netlink Message
    std::shared_ptr<nl_msg> nl_message =
        std::shared_ptr<struct nl_msg>(nlmsg_alloc(), [](struct nl_msg *obj) {
            if (obj) {
                nlmsg_free(obj);
            }
        });
    LOG_IF(!nl_message, FATAL) << "Failed creating netlink message!";

    // Netlink Callback
    std::shared_ptr<nl_cb> nl_callback =
        std::shared_ptr<struct nl_cb>(nl_cb_alloc(NL_CB_DEFAULT), [](struct nl_cb *obj) {
            if (obj) {
                nl_cb_put(obj);
            }
        });
    LOG_IF(!nl_callback, FATAL) << "Failed creating netlink callback!";

    int mcid = genl_ctrl_resolve_grp(m_nl80211_sock.get(), "nl80211", "scan");
    nl_socket_add_membership(m_nl80211_sock.get(), mcid);

    // Create standard callbacks
    int err                             = 1;
    int ret                             = 1;
    struct scan_trigger_results results = {.done = 0, .aborted = 0, msg_handle};
    static auto nl_err_cb = [](struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) -> int {
        int *ret = (int *)arg;
        *ret     = err->error;
        return NL_STOP;
    };

    static auto nl_finish_cb = [](struct nl_msg *msg, void *arg) -> int {
        int *ret = (int *)arg;
        *ret     = 0;
        return NL_SKIP;
    };

    static auto nl_ack_cb = [](struct nl_msg *msg, void *arg) -> int {
        int *ret = (int *)arg;
        *ret     = 0;
        return NL_STOP;
    };

    static auto nl_seq_check = [](struct nl_msg *msg, void *arg) -> int { return NL_OK; };

    // Response handler
    auto nl_handler_cb = [](struct nl_msg *msg, void *arg) -> int {
        struct nlmsghdr *nlh                         = nlmsg_hdr(msg);
        struct genlmsghdr *gnlh                      = (genlmsghdr *)nlmsg_data(nlh);
        struct scan_trigger_results *scan_tr_results = (struct scan_trigger_results *)arg;

        if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
            scan_tr_results->done    = 1;
            scan_tr_results->aborted = 1;
        } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
            scan_tr_results->done    = 1;
            scan_tr_results->aborted = 0;
        }

        if (!scan_tr_results->msg_handle(msg)) {
            LOG(ERROR) << "User's netlink handler function failed!";
        }
        return NL_SKIP;
    };

    // Initialize the netlink message
    if (!genlmsg_put(nl_message.get(), 0, 0, m_nl80211_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0) ||
        nla_put_u32(nl_message.get(), NL80211_ATTR_IFINDEX, m_iface_index) != 0) {
        LOG(ERROR) << "Failed initializing the netlink message!";
        return false;
    }

    // Call the user's message create function
    if (!msg_create(nl_message.get())) {
        LOG(ERROR) << "User's netlink create function failed!";
        return false;
    }

    // Add the callback.
    nl_cb_set(nl_callback.get(), NL_CB_VALID, NL_CB_CUSTOM, nl_handler_cb, &results);
    nl_cb_err(nl_callback.get(), NL_CB_CUSTOM, nl_err_cb, &err);
    nl_cb_set(nl_callback.get(), NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_cb, &err);
    nl_cb_set(nl_callback.get(), NL_CB_ACK, NL_CB_CUSTOM, nl_ack_cb, &err);
    nl_cb_set(nl_callback.get(), NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl_seq_check, NULL);

    err = 1;
    ret = nl_send_auto(m_nl80211_sock.get(), nl_message.get());

    // TODO: Probably should be changed to select/epoll...
    while (err > 0)
        ret = nl_recvmsgs(m_nl80211_sock.get(), nl_callback.get());
    if (err < 0) {
        LOG(WARNING) << "nl_recvmsgs err has a value of " << err;
    }
    if (ret < 0) {
        LOG(ERROR) << "nl_recvmsgs returned " << ret << " " << nl_geterror(-ret);
        return false;
    }
    while (!results.done)
        nl_recvmsgs(m_nl80211_sock.get(), nl_callback.get());
    if (results.aborted) {
        LOG(ERROR) << "Scan is aborted";
        return false;
    }

    LOG(DEBUG) << "Scan is done";

    nl_socket_drop_membership(m_nl80211_sock.get(), mcid);

    return true;
}

bool base_wlan_hal_nl80211::get_channel_utilization(uint8_t &channel_utilization)
{
    nl80211_client::SurveyInfo survey_info;
    if (!m_nl80211_client->get_survey_info(get_iface_name(), survey_info)) {
        LOG(ERROR) << "Failed to get survey information for interface " << get_iface_name();
        return false;
    }

    if (!survey_info.get_channel_utilization(channel_utilization)) {
        LOG(ERROR) << "Survey information contains no channel utilization data for interface "
                   << get_iface_name();
        return false;
    }

    return true;
}

} // namespace nl80211
} // namespace bwl
