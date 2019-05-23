/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "../include/bpl_cfg.h"
#include "../common/utils/utils.h"
#include "../common/utils/utils_net.h"
#include "mapf/common/logger.h"

using namespace mapf;

using namespace beerocks::bpl;

const char *s_error_strings[] = {FOREACH_ERROR_CODE(GENERATE_ERROR_STRING)};

int bpl_cfg_is_enabled() { return 1; }

int bpl_cfg_is_master() { return 1; }

int bpl_cfg_get_operating_mode() { return BPL_OPER_MODE_GATEWAY; }

int bpl_cfg_is_onboarding() { return 0; }

int bpl_cfg_is_wired_backhaul() { return 0; }

int bpl_cfg_get_rdkb_extensions() { return 0; }

int bpl_cfg_get_band_steering() { return 0; }

int bpl_cfg_get_dfs_reentry() { return 0; }

int bpl_cfg_get_passive_mode() { return 0; }

int bpl_cfg_get_client_roaming() { return 0; }

int bpl_cfg_get_device_info(BPL_DEVICE_INFO *device_info) { return -1; }

int bpl_cfg_get_wifi_params(const char *iface, struct BPL_WLAN_PARAMS *wlan_params)
{
    if (!iface || !wlan_params) {
        return -1;
    }
    wlan_params->enabled        = 1;
    wlan_params->acs            = 1;
    wlan_params->advertise_ssid = 1;
    utils::copy_string(wlan_params->ssid, "test_ssid", BPL_SSID_LEN);
    utils::copy_string(wlan_params->security, "None", BPL_SEC_LEN);

    return 0;
}

int bpl_cfg_get_backhaul_params(int *max_vaps, int *network_enabled, int *prefered_radio_band)
{
    *max_vaps = 0;
    *network_enabled = 0;
    *prefered_radio_band = 0;
    return 0;
}

int bpl_cfg_get_backhaul_vaps(char *backhaul_vaps_buf, const int buf_len)
{
    memset(backhaul_vaps_buf, 0, buf_len);
    return 0;
}

int bpl_cfg_set_wifi_advertise_ssid(const char *iface, int advertise_ssid) { return -1; }

int bpl_cfg_get_beerocks_credentials(const int radio_dir, char ssid[BPL_SSID_LEN],
                                     char pass[BPL_PASS_LEN], char sec[BPL_SEC_LEN])
{
    utils::copy_string(ssid, "test_beerocks_ssid", BPL_SSID_LEN);
    utils::copy_string(sec, "None", BPL_SEC_LEN);
    return 0;
}

int bpl_cfg_set_wifi_credentials(const char iface[BPL_IFNAME_LEN], const char ssid[BPL_SSID_LEN],
                                 const char pass[BPL_PASS_LEN], const char sec[BPL_SEC_LEN])
{
    return -1;
}

int bpl_cfg_set_beerocks_credentials(const int radio_dir, const char ssid[BPL_SSID_LEN],
                                     const char pass[BPL_PASS_LEN], const char sec[BPL_SEC_LEN])
{
    return -1;
}

int bpl_cfg_set_onboarding(int enable) { return -1; }

int bpl_cfg_notify_onboarding_completed(const char ssid[BPL_SSID_LEN],
                                        const char pass[BPL_PASS_LEN], const char sec[BPL_SEC_LEN],
                                        const char iface_name[BPL_IFNAME_LEN], const int success)
{
    return -1;
}

int bpl_cfg_notify_fw_version_mismatch() { return -1; }

int bpl_cfg_notify_error(int code, const char data[BPL_ERROR_STRING_LEN]) { return -1; }

int bpl_cfg_set_wifi_iface_state(const char iface[BPL_IFNAME_LEN], int op) { return -1; }

int bpl_cfg_set_wifi_radio_tx_state(const char iface[BPL_IFNAME_LEN], int enable) { return -1; }

int bpl_cfg_notify_iface_status(const BPL_INTERFACE_STATUS_NOTIFICATION *status_notif)
{
    return -1;
}

int bpl_cfg_get_administrator_credentials(char pass[BPL_PASS_LEN]) { return -1; }
