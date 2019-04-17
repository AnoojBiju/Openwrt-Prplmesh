/*
 * INTEL CONFIDENTIAL
 * Copyright 2016 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code ("Material") are owned by Intel Corporation or its
 * suppliers or licensors.  Title to the Material remains with Intel
 * Corporation or its suppliers and licensors.  The Material contains trade
 * secrets and proprietary and confidential information of Intel or its
 * suppliers and licensors.  The Material is protected by worldwide copyright
 * and trade secret laws and treaty provisions. No part of the Material may
 * be used, copied, reproduced, modified, published, uploaded, posted,
 * transmitted, distributed, or disclosed in any way without Intel's prior
 * express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or
 * delivery of the Materials,  either expressly, by implication, inducement,
 * estoppel or otherwise.  Any license under such intellectual property
 * rights must be express and approved by Intel in writing.
 */

#ifndef _BWL_BASE_WLAN_HAL_WAV_H_
#define _BWL_BASE_WLAN_HAL_WAV_H_

#include "../common/base_wlan_hal.h"

#include <beerocks/bcl/beerocks_state_machine.h>

#include <memory>
#include <chrono>
#include <list>
#include <unordered_map>

#define WAV_EVENT_KEYLESS_PARAM_OPCODE  "_opcode"
#define WAV_EVENT_KEYLESS_PARAM_MAC     "_mac"
#define WAV_EVENT_KEYLESS_PARAM_IFACE   "_iface"

// Forward declaration
struct wpa_ctrl;

namespace bwl {
namespace wav {

enum class wav_fsm_state
{
    Delay,
    Init,
    GetRadioInfo,
    Attach,
    Operational,
    Detach
};

enum class wav_fsm_event
{
    Attach,
    Detach
};

typedef std::unordered_map<std::string, std::string> parsed_obj_map_t;
typedef std::list<parsed_obj_map_t> 				 parsed_obj_listed_map_t;

/*!
 * Base class for the wav abstraction layer.
 * Read more about virtual inheritance: https://en.wikipedia.org/wiki/Virtual_inheritance
 */
class base_wlan_hal_wav : public  virtual base_wlan_hal, protected beerocks::beerocks_fsm<wav_fsm_state, wav_fsm_event> {

// Public methods:
public:
 
    virtual ~base_wlan_hal_wav();

    virtual HALState attach(bool block = false) override;
    virtual bool detach() override;
    virtual bool refresh_radio_info() override;
    virtual bool refresh_vaps_info(int id) override;
    virtual bool process_ext_events() override;
    virtual std::string get_radio_mac() override;

// Protected methods
protected:

    base_wlan_hal_wav(HALType type, std::string iface_name, bool acs_enabled, hal_event_cb_t callback, int wpa_ctrl_buffer_size);

    void parsed_obj_debug(parsed_obj_map_t& obj);
    void parsed_obj_debug(parsed_obj_listed_map_t& obj);

    bool wav_obj_read_int(const std::string& key, parsed_obj_map_t& obj, int64_t& value, bool ignore_unknown = false);
    bool wav_obj_read_str(const std::string& key, parsed_obj_map_t& obj, char** value);
    
    // Process WAV event
    virtual bool process_wav_event(parsed_obj_map_t& parsed_obj) = 0;

    bool wpa_ctrl_send_msg(const std::string& cmd, parsed_obj_map_t& reply);
    bool wpa_ctrl_send_msg(const std::string& cmd, parsed_obj_listed_map_t& reply);
    bool wpa_ctrl_send_msg(const std::string& cmd, char** reply); // for external process
    bool wpa_ctrl_send_msg(const std::string& cmd);

    virtual void send_ctrl_iface_cmd(std::string cmd);  // HACK for development, to be removed

// Private data-members:
private:

    const uint32_t AP_ENABELED_TIMEOUT_SEC = 15;
    const uint32_t AP_ENABELED_FIXED_DFS_TIMEOUT_SEC = 660;

    bool fsm_setup();

    wav_fsm_state                           m_last_attach_state = wav_fsm_state::Detach;

    std::chrono::steady_clock::time_point   m_state_timeout;

    struct wpa_ctrl*                        m_wpa_ctrl_cmd = nullptr;
    struct wpa_ctrl*                        m_wpa_ctrl_event = nullptr;

    std::shared_ptr<char>                   m_wpa_ctrl_buffer;
    size_t                                  m_wpa_ctrl_buffer_size = 0;
    
    std::string                             ctrl_path;
};
 
} // namespace bwl
} // namespace wav 

#endif // _BWL_BASE_WLAN_HAL_WAV_H_
