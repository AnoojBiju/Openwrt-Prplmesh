/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_BASE_WLAN_HAL_DWPALD_H_
#define _BWL_BASE_WLAN_HAL_DWPALD_H_

#include "base_wlan_hal_dwpald_types.h"

#include <bwl/base_wlan_hal.h>
#include <bwl/key_value_parser.h>
#include <bwl/nl80211_client.h>

#include <bcl/beerocks_state_machine.h>

extern "C" {
#include <dwpal.h>
#include <dwpald_client.h>
}

#include <chrono>
#include <memory>

namespace bwl {
namespace dwpal {

enum class dwpal_fsm_state { Delay, Init, GetRadioInfo, AttachVaps, Attach, Operational, Detach };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *dwpal_fsm_state_str(dwpal_fsm_state enum_value) {
    switch (enum_value) {
    case dwpal_fsm_state::Delay:        return "dwpal_fsm_state::Delay";
    case dwpal_fsm_state::Init:         return "dwpal_fsm_state::Init";
    case dwpal_fsm_state::GetRadioInfo: return "dwpal_fsm_state::GetRadioInfo";
    case dwpal_fsm_state::AttachVaps:   return "dwpal_fsm_state::AttachVaps";
    case dwpal_fsm_state::Attach:       return "dwpal_fsm_state::Attach";
    case dwpal_fsm_state::Operational:  return "dwpal_fsm_state::Operational";
    case dwpal_fsm_state::Detach:       return "dwpal_fsm_state::Detach";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, dwpal_fsm_state value) { return out << dwpal_fsm_state_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

enum class dwpal_fsm_event { Attach, Detach };
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *dwpal_fsm_event_str(dwpal_fsm_event enum_value) {
    switch (enum_value) {
    case dwpal_fsm_event::Attach: return "dwpal_fsm_event::Attach";
    case dwpal_fsm_event::Detach: return "dwpal_fsm_event::Detach";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, dwpal_fsm_event value) { return out << dwpal_fsm_event_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

// list of issues that may prevent a client's connection
enum generate_association_event_result : int32_t {
    FAILED_TO_PARSE_DWPAL      = -1,
    SUCCESS                    = 0,
    SKIP_CLIENT_NOT_ASSOCIATED = 1,
};
// Enum AutoPrint generated code snippet begining- DON'T EDIT!
// clang-format off
static const char *generate_association_event_result_str(generate_association_event_result enum_value) {
    switch (enum_value) {
    case FAILED_TO_PARSE_DWPAL:      return "FAILED_TO_PARSE_DWPAL";
    case SUCCESS:                    return "SUCCESS";
    case SKIP_CLIENT_NOT_ASSOCIATED: return "SKIP_CLIENT_NOT_ASSOCIATED";
    }
    static std::string out_str = std::to_string(int(enum_value));
    return out_str.c_str();
}
inline std::ostream &operator<<(std::ostream &out, generate_association_event_result value) { return out << generate_association_event_result_str(value); }
// clang-format on
// Enum AutoPrint generated code snippet end

// Context is created for each VAP and for main radio
static constexpr uint8_t DWPAL_CONTEXTS_MAX_SIZE =
    beerocks::eBeeRocksIfaceIds::IFACE_TOTAL_VAPS + 1;

/*!
 * Base class for the dwpal abstraction layer.
 * Read more about virtual inheritance: https://en.wikipedia.org/wiki/Virtual_inheritance
 */
class base_wlan_hal_dwpal : public virtual base_wlan_hal,
                            protected beerocks::beerocks_fsm<dwpal_fsm_state, dwpal_fsm_event>,
                            public KeyValueParser {

    // Public methods:
public:
    virtual ~base_wlan_hal_dwpal();

    virtual HALState attach(bool block = false) override;
    virtual bool detach() override;
    virtual bool ping() override;
    virtual bool refresh_radio_info() override;
    virtual bool refresh_vaps_info(int id) override;
    virtual bool process_ext_events(int fd = 0) override;
    virtual bool process_nl_events() override;
    virtual std::string get_radio_mac() override;

    /**
     * @brief Gets channel utilization.
     *
     * @see base_wlan_hal::get_channel_utilization
     *
     * This implementation gets channel utilization via sub-command
     * LTQ_NL80211_VENDOR_SUBCMD_GET_PHY_CHAN_STATUS of NL80211_CMD_VENDOR command, issued through
     * DWPAL interface.
     *
     * @param[out] channel_utilization Channel utilization value.
     *
     * @return True on success and false otherwise.
     */
    bool get_channel_utilization(uint8_t &channel_utilization) override;

    /**
     * @brief Get the ext evt write pipe fd
     * @return int 
     */
    int get_ext_evt_write_pfd() { return m_dwpal_event_pfd[1]; }
    int get_nl_evt_write_pfd() { return m_nl_event_pfd[1]; }

    // Process dwpal event
    virtual bool process_dwpal_event(char *buffer, int bufLen, const std::string &opcode) = 0;
    virtual bool process_dwpal_nl_event(struct nl_msg *msg, void *arg = nullptr)          = 0;

    // Protected methods
protected:
    base_wlan_hal_dwpal(HALType type, const std::string &iface_name, hal_event_cb_t callback,
                        const hal_conf_t &hal_conf = {});

    virtual bool dwpald_attach(char *ifname) = 0;

    bool set(const std::string &param, const std::string &value,
             int vap_id = beerocks::IFACE_RADIO_ID);

    bool dwpal_send_cmd(const std::string &cmd, parsed_line_t &reply,
                        int vap_id = beerocks::IFACE_RADIO_ID);

    bool dwpal_send_cmd(const std::string &cmd, parsed_multiline_t &reply,
                        int vap_id = beerocks::IFACE_RADIO_ID);

    // for external process
    bool dwpal_send_cmd(const std::string &cmd, char **reply,
                        int vap_id = beerocks::IFACE_RADIO_ID);

    bool dwpal_send_cmd(const std::string &cmd, int vap_id = beerocks::IFACE_RADIO_ID);
    bool attach_dwpald_interface(int vap_id);

    /**
     * @brief handle set vendor data cmd to netlink
     * @param ifname radio interface name
     * @param nl_cmd netlink set command number
     * @param vendor_data pointer to vendor data buffer
     * @param vendor_data_size size of data
     * @return true on success
     * @return false on failure
     */
    bool dwpal_nl_cmd_set(const std::string &ifname, unsigned int nl_cmd, const void *vendor_data,
                          size_t vendor_data_size);

    /**
     * @brief Get information from the NL using a blocking dwpal API.
     * 
     * @param[in] command Netlink command to send to the NL.
     * @param[in] nl_callback A callback function to run on the NL reply.
     * @param[in,out] callback_args Arguments the callback function expects, can be used for output of information from the reply.
     * @return true on success, otherwise false
     */
    bool dwpal_nl_cmd_send_and_recv(int command, DWPAL_nl80211Callback nl_callback,
                                    void *callback_args);

    bool dwpal_nl_cmd_scan_dump();

    std::unique_ptr<nl80211_client> m_nl80211_client;

    /**
     * Re-usable buffer to hold the response of NL80211_CMD_VENDOR commands
     */
    unsigned char m_nl_buffer[NL_MAX_REPLY_BUFFSIZE] = {'\0'};

    // Private data-members:
private:
    bool get_vap_type(const std::string &ifname, bool &fronthaul, bool &backhaul);

    const uint32_t AP_ENABLED_TIMEOUT_SEC           = 15;
    const uint32_t AP_ENABLED_FIXED_DFS_TIMEOUT_SEC = 660;

    bool fsm_setup();
    bool refresh_vap_info(int vap_id);

    dwpal_fsm_state m_last_attach_state = dwpal_fsm_state::Detach;

    std::chrono::steady_clock::time_point m_state_timeout;

    char m_wpa_ctrl_buffer[HOSTAPD_TO_DWPAL_MSG_LENGTH];
    size_t m_wpa_ctrl_buffer_size = HOSTAPD_TO_DWPAL_MSG_LENGTH;

    int m_nl_get_failed_attempts = 0;

    /**
     * @brief Gets PHY channel status information
     *
     * Sends sub-command LTQ_NL80211_VENDOR_SUBCMD_GET_PHY_CHAN_STATUS of NL80211_CMD_VENDOR
     * command through DWPAL and fills given structure with response obtained.
     *
     * @param status PHY channel status information structure to fill in.
     * @return True on success and false otherwise.
     */
    bool dwpal_get_phy_chan_status(sPhyChanStatus &status);

    /**
     * Store pipe fds ( read + write )
     * dwpald callback context will write into pipe fd [1]
     * dwpald bwl context will read from pipe fd [0]
     * This is in order to process event buffer in bwl context
     * and not in dwpald callback context.
     */
    int m_dwpal_event_pfd[2] = {0};
    int m_nl_event_pfd[2]    = {0};
};

} // namespace dwpal
} // namespace bwl

#endif // _BWL_BASE_WLAN_HAL_DWPALD_H_
