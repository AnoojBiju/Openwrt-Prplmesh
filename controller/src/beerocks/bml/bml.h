/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BML_H_
#define _BML_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "bml_defs.h"
#ifdef FEATURE_PRE_ASSOCIATION_STEERING
#include "bml_pre_association_steering_defs.h"
#endif

/**
 * @brief Configure Logging Preference for BML for external application.
 * External C application cannot use the beerocks::logging class in order to configure the logging
 * mechanism of the BML library. This API defines the beerocks::logging internally and can be used by
 * external c-applications that link to the BML library to configure the logger.
 * 
 * @param beerocks_conf_dir_path Full path to the directory in which the configuration file is located.
 * @param path_length Length of the provided path string.
 * @param module_name Name of the module that will be used in the log prints.
 * @param module_name_length Length of the provided module name string.
 * @return BML_RET_OK on success.
 */
int bml_configure_external_logging(const char *beerocks_conf_dir_path,
                                   const unsigned int path_length, const char *module_name,
                                   const unsigned int module_name_length);

/**
 * Initialize the BML library and connect to Beerocks.
 *
 * @param [out] ctx BML Context.
 * @param [in] beerocks_conf_path Path to the beerocks configuration filesfolder (e.g. /opt/beerocks)
 * @param [in] user_data Pointer to some arbitrary user data to be 
 * stored within the BML context.
 *
 * @return BML_RET_OK on success.
 */
int bml_connect(BML_CTX *ctx, const char *beerocks_conf_path, void *user_data);

/**
 * Disconnect from Beerocks and purge the BML library context.
 * This operation will prevent any following calls to BML APIs
 * until a new call to bml_connect().
 *
 * @param [in] ctx BML Context.
 *
 * @return BML_RET_OK on success.
 */
int bml_disconnect(BML_CTX ctx);

/* Returns the onboard state of the platform
 * @return 1 Platform is in onboarding state.
 * @return 0 Platform is in operational mode.
 * @return -1 Error.
 */
int bml_onboard_status(BML_CTX ctx);

/* Check whether master is enabled local platform
 * @return 1 Master enabled on local platform.
 * @return 0 Master is not enabled on local platform.
 * @return -1 Error.
 */
int bml_local_master_enabled(BML_CTX ctx);

/**
 * Returns the user data stored within the BML context.
 *
 * @param [in] ctx BML Context.
 *
 * @return Pointer to the user data passed to the bml_connect() function.
 */
void *bml_get_user_data(BML_CTX ctx);

/**
 * Check whether the connection with the beerocks platform is alive and well.
 *
 * @return BML_RET_OK on success.
 */
int bml_ping(BML_CTX ctx);

/**
 * Registers a callback functions for the network map query operation.
 * When calling the bml_nw_map_query() function, a request to send the entire
 * network map will be sent to the beerocks platform. On arrival of the response,
 * the callback function will be called for processing.
 *
 * The function can be called with NULL value to unregister the callback.
 *
 * @param [in] ctx BML Context.
 * @param [in] cb Pointer to the network map query callback.
 *
 * @return BML_RET_OK on success.
 */
int bml_nw_map_register_query_cb(BML_CTX ctx, BML_NW_MAP_QUERY_CB cb);

/**
 * Registers a callback functions for the network map update operation.
 * A network map update occur asynchronously when an update message is received
 * from the beerocks platform. If a callback function is registered, it'll be called.
 *
 * The function can be called with NULL value to unregister the callback.
 *
 * @param [in] ctx BML Context.
 * @param [in] cb Pointer to the network map update callback.
 *
 * @return BML_RET_OK on success.
 */
int bml_nw_map_register_update_cb(BML_CTX ctx, BML_NW_MAP_QUERY_CB cb);

/**
 * Query the beerocks for the latest network map.
 * This function is asynchronous and returns immediatly.
 * When the result is available, and a callback function was registered using the
 * bml_nw_map_register() function, it will be called.
 * 
 * @param [in] ctx BML Context.
 *
 * @return BML_RET_OK on success.
 */
int bml_nw_map_query(BML_CTX ctx);

/**
 * Query prplmesh for radio status for a specific device, blocking.
 * 
 * @param [in] ctx BML Context.
 * 
 * @param [in/out]  BML_DEVICE_DATA .hold both device al_mac and reply data 
 *
 * @return BML_RET_OK on success.
 */
int bml_device_oper_radios_query(BML_CTX ctx, struct BML_DEVICE_DATA *device_data);

/**
 * Registers a callback function to periodic statistics update from 
 * the beerocks platform.
 *
 * The function can be called with NULL value to unregister the callback.
 *
 * @param [in] ctx BML Context.
 * @param [in] cb Pointer to the statistics update callback.
 *
 * @return BML_RET_OK on success.
 */
int bml_stat_register_cb(BML_CTX ctx, BML_STATS_UPDATE_CB cb);

/**
 * Registers a callback function to events from 
 * the beerocks platform.
 *
 * The function can be called with NULL value to unregister the callback.
 *
 * @param [in] ctx BML Context.
 * @param [in] cb Pointer to the event callback.
 *
 * @return BML_RET_OK on success.
 */
int bml_event_register_cb(BML_CTX ctx, BML_EVENT_CB cb);

/**
 * Adds the Wi-Fi credentials tor the beerocks network.
 *
 * @param [in] ctx BML Context.
 * @param [in] al_mac The agent mac adress.
 * @param [in] ssid[BML_NODE_SSID_LEN] The SSID for the network. SSID array length must be equal to BML_NODE_SSID_LEN.
 * @param [in] network_key[BML_NODE_PASS_LEN] The WPA2 passphrase for the network. Pass array length must be equal to BML_NODE_PASS_LEN.
 * @param [in] bands Can be 24g, 5g, 24g-5g.
 * @param [in] bss_type BSS, can be fronthaul, backhaul, fronthaul-backhaul.
 * @param [in] add_sae Add SAE authentication type (WPA3). Must be set with a network_key.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_wifi_credentials(BML_CTX ctx, const char *al_mac, const char *ssid,
                             const char *network_key, const char *bands, const char *bss_type,
                             bool add_sae);
/**
 * Removes the Wi-Fi credentials for the client with AL-MAC
 *
 * @param [in] ctx BML Context.
 * @param [in] al_mac client AL-MAC address
 *
 * @return BML_RET_OK on success.
 */
int bml_clear_wifi_credentials(BML_CTX ctx, const char *al_mac);

/**
 * Updates the Wi-Fi credentials for the client with AL-MAC
 *
 * @param [in] ctx BML Context.
 *
 * @return BML_RET_OK on success.
 */
int bml_update_wifi_credentials(BML_CTX ctx);

/**
 * Get Wi-Fi credentials (SSID and security) for the beerocks network.
 *
 * NOTE: If the system is in "onboarding" state, the function will return 
 *       BML_RET_OP_FAILED.
 *
 * @param [in] ctx BML Context.
 * @param [in] vap_id ID of the requested VAP (0 for main VAP).
 * @param [out] ssid[BML_NODE_SSID_LEN] The SSID for the network. ssid array length must be equal to BML_NODE_SSID_LEN
 * @param [out] pass[BML_NODE_PASS_LEN] The WPA2 passphrase for the network.  pass array length must be equal to BML_NODE_PASS_LEN
 * @param [out] sec Wi-Fi security/encryption (BML_WLAN_SEC_*).
 *
 * @return BML_RET_OK on success.
 */
int bml_get_wifi_credentials(BML_CTX ctx, int vap_id, char *ssid, char *pass, int *sec);

/* Get the onboard state of the platform
 * @param [in] ctx BML Context.
 * @param [out] enable = 1 (onboarding enabled), disabled = 0 (onboarding disabled).
 * @return BML_RET_OK on success.
 */
int bml_get_onboarding_state(BML_CTX ctx, int *enable);

/* Set the onboard state of the platform
 * @param [in] ctx BML Context.
 * @param [in] enable, set to 1 for onboarding enabled, set to 0 for onboarding disabled.
 * @return BML_RET_OK on success.
 */
int bml_set_onboarding_state(BML_CTX ctx, int enable);

/* Do WPS onboarding of a specific iface
 * @param [in] ctx BML Context.
 * @param [in] iface, interface name, if empty, all interfaces.
 * @return BML_RET_OK on success.
 */
int bml_wps_onboarding(BML_CTX ctx, const char *iface);

/**
 * Get administrator credentials (admin user password).
 *
 * @param [in] ctx BML Context.
 * @param [out] user_password[BML_NODE_USER_PASS_LEN] The password of the administrator user
 *
 * @return BML_RET_OK on success.
 */

int bml_get_administrator_credentials(BML_CTX ctx, char *user_password);

/**
 * Enables or disables beerocks roaming.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_client_roaming(BML_CTX ctx, int enable);

/**
 * Returns beerocks roaming mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_client_roaming(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks 11k feature support.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_client_roaming_11k_support(BML_CTX ctx, int enable);

/**
 * Returns beerocks 11k feature support.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_client_roaming_11k_support(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks legacy (forced) client roaming.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_legacy_client_roaming(BML_CTX ctx, int enable);

/**
 * Returns beerocks legacy client roaming mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_legacy_client_roaming(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks client roaming based on maximum signal strength.
 * When disabled, client roaming will be done based on maximum client throuput.
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_client_roaming_prefer_signal_strength(BML_CTX ctx, int enable);

/**
 * Returns beerocks client roaming prefer signal strength configuration.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result: 0 - disabled, 1 - enable.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_client_roaming_prefer_signal_strength(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks client band steering.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_client_band_steering(BML_CTX ctx, int enable);

/**
 * Returns beerocks client band steering mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_client_band_steering(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks ire roaming.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_ire_roaming(BML_CTX ctx, int enable);

/**
 * Returns beerocks ire roaming mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_ire_roaming(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks load_balancer.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_load_balancer(BML_CTX ctx, int enable);

/**
 * Returns beerocks load_balancer mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_load_balancer(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks service_fairness.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_service_fairness(BML_CTX ctx, int enable);

/**
 * Returns beerocks service_fairness mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_service_fairness(BML_CTX ctx, int *res);

/**
 * Enables or disables beerocks DFS reentry feature.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_dfs_reentry(BML_CTX ctx, int enable);

/**
 * Returns beerocks DFS reentry feature.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_dfs_reentry(BML_CTX ctx, int *res);

/**
 * Enables or disables certification mode.
 *
 * @param [in] ctx BML Context.
 * @param [in] enable 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_certification_mode(BML_CTX ctx, int enable);

/**
 * Returns certification mode enable.
 *
 * @param [in] ctx BML Context.
 * @param [in] res A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_certification_mode(BML_CTX ctx, int *res);

/**
 * Set beerocks modules log level.
 *
 * @param [in] ctx BML Context.
 * @param [in] module_name A module name - master/slave/monitor/platform/all.
 * @param [in] log_level A log level - 'i'-info, 'd'-debug, 'e'-error, 'f'-fatal, 't'-trace, 'w'-warning, 'a'-all.
 * @param [in] on On/Off state.
 * @param [in] mac The required mac.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_log_level(BML_CTX ctx, const char *module_name, const char *log_level, uint8_t on,
                      const char *mac);

/**
 * Returns strings representation of the beerocks master & slave versions.
 * The version is of type X.Y.Z (or NULL in case of an error).
 *
 * @param [in] ctx BML Context.
 * @param [out] version The BEEROCKS MASTER VERSION.
 * @param [out] version The BEEROCKS SLAVE VERSION.
 * 
 * @return BML_RET_OK on success.
 */
int bml_get_master_slave_versions(BML_CTX ctx, char *master_version, char *slave_version);

/**
 * Use provided easylogging context.
 *
 * @param [in] log_ctx Pointer to an easylogging context.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_local_log_context(void *log_ctx);

/**
 * Returns a string representation of the bml version.
 * The version is of type X.Y.Z.
 */
const char *bml_get_bml_version();

/**
 * Updates global resrected channels for the 
 * beerocks network.
 *
 * @param [in] ctx BML Context.
 * @param [in] restricted_channels[BML_NODE_RESTRICTED_CHANNELS_LEN] The restricted_channels for the system. restricted_channels array length must be equal to BML_NODE_RESTRICTED_CHANNELS_LEN
 *
 * @return BML_RET_OK on success.
 */
int bml_set_global_restricted_channels(BML_CTX ctx, const uint8_t *restricted_channels,
                                       uint8_t size);

/**
 * Updates global resrected channels for the 
 * beerocks network.
 *
 * @param [in] ctx BML Context.
 * @param [in/out] restricted_channels[BML_NODE_RESTRICTED_CHANNELS_LEN] The restricted_channels for the system. restricted_channels array length must be equal to BML_NODE_RESTRICTED_CHANNELS_LEN
 *
 * @return BML_RET_OK on success.
 */
int bml_get_global_restricted_channels(BML_CTX ctx, uint8_t *restricted_channels);

/**
 * Updates Slave resrected channels for the 
 * beerocks network.
 *
 * @param [in] ctx BML Context.
 * @param [in] restricted_channels[BML_NODE_RESTRICTED_CHANNELS_LEN] The restricted_channels for a slave. restricted_channels array length must be equal to BML_NODE_SSID_LEN
 * @param [in] mac The required mac.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_slave_restricted_channels(BML_CTX ctx, const uint8_t *restricted_channels,
                                      const char *mac, uint8_t size);

/**
 * Updates Slave resrected channels for the 
 * beerocks network.
 *
 * @param [in] ctx BML Context.
 * @param [in/out] restricted_channels[BML_NODE_RESTRICTED_CHANNELS_LEN] The restricted_channels for a slave. restricted_channels array length must be equal to BML_NODE_SSID_LEN
 * @param [in] mac The required mac.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_slave_restricted_channels(BML_CTX ctx, uint8_t *restricted_channels, const char *mac);

/**
 * Trigger Topology Discovery Task.
 *
 * @param [in] ctx BML Context.
 * @param [in] al_mac al_mac of the platform. 
 *
 * @return BML_RET_OK on success.
 */
int bml_trigger_topology_discovery(BML_CTX ctx, const char *al_mac);

/**
 * Trigger the On-Demand Channel-Selection.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio. 
 * @param [in] bandwidth Channel Bandwidth
 * @param [in] csa_count Channel-Switch-Announcement beacon count. 
 * 
 * @return BML_RET_OK on success.
 */
int bml_channel_selection(BML_CTX ctx, const char *radio_mac, uint8_t channel, uint8_t bandwidth,
                          uint8_t csa_count);

/**
 * Set the dynamic channel pool, used by the Auto Channel Selection flow.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio. 
 * @param [in] channel_pool channel pool for the Channel Selection .
 * @param [in] channel_pool_size size of the channel pool.
 * 
 * @return BML_RET_OK on success.
 */
int bml_set_selection_channel_pool(BML_CTX ctx, const char *radio_mac, unsigned int *channel_pool,
                                   int channel_pool_size);

/**
 * Get the dynamic channel pool, used by the Auto Channel Selection flow.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio. 
 * @param [out] channel_pool Empty, pre-initialized channel pool for the Channel Selection.
 * @param [int/out] channel_pool_size Max size of the channel pool, initilized with the max size of the channel pool.
 * 
 * @return BML_RET_OK on success.
 */
int bml_get_selection_channel_pool(BML_CTX ctx, const char *radio_mac, unsigned int *channel_pool,
                                   int *channel_pool_size);

/**
 * Set a VAP information list.
 *
 * @param [in] ctx BML Context.
 * @param [in] vap_list Array of BML_VAP_INFO elements. 
 * @param [in] vaps_num Number of elements in vap_list.
 * 
 * @return BML_RET_OK on success.
 */
int bml_set_vap_list_credentials(BML_CTX ctx, struct BML_VAP_INFO *vap_list,
                                 const uint8_t vaps_num);

/**
 * Get a VAP information list.
 *
 * @param [in] ctx BML Context.
 * @param [out] vap_list User allocated array of BML_VAP_INFO elements.
 * @param [in/out] vaps_num Number of elements in vap_list.
 * 
 * @return BML_RET_OK on success.
 */
int bml_get_vap_list_credentials(BML_CTX ctx, struct BML_VAP_INFO *vap_list, uint8_t *vaps_num);

/**
 * Enables or disables beerocks DCS continuous scans.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio
 * @param [in] enable Value of 1 to enable or 0 to disable.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_dcs_continuous_scan_enable(BML_CTX ctx, const char *radio_mac, int enable);

/**
 * Sends unassoc sta link metrics query to agents
 *
 * @param [in] sta_mac is mac address of unassociated sta
 * @param [in] opclass is operating class
 * @param [in] channel is channel from the operating class
 *
 * @return 0 on success.
 */
int bml_send_unassoc_sta_rcpi_query(BML_CTX ctx, const char *sta_mac, int16_t opclass,
                                    int16_t channel);
/**
 * Fetch unassoc sta link metric query result
 *
 * @param [in] sta_mac is mac address of unassociated sta
 * @param [in] sta_info has link metric data result
 *
 * @return 0 on success.
 */
int bml_get_unassoc_sta_rcpi_query_result(BML_CTX ctx, const char *sta_mac,
                                          struct BML_UNASSOC_STA_LINK_METRIC *sta_info);

/**
 * get DCS continuous scans param.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio
 * @param [out] enable A reference for the result to be stored in.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_dcs_continuous_scan_enable(BML_CTX ctx, const char *radio_mac, int *enable);

/**
 * set DCS continuous scan params.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio
 * @param [in] dwell_time Set the dwell time in miliseconds.
 * @param [in] interval_time Set the interval time in seconds.
 * @param [in] channel_pool Set the channel pool for the DCS.
 * @param [in] channel_pool_size Set the DCS channel pool size.
 *
 * @return BML_RET_OK on success.
 */
int bml_set_dcs_continuous_scan_params(BML_CTX ctx, const char *radio_mac, int dwell_time,
                                       int interval_time, unsigned int *channel_pool,
                                       int channel_pool_size);

/**
 * get DCS continuous scan params.
 *
 * @param [in] ctx BML Context.
 * @param [in] radio_mac Radio MAC of selected radio
 * @param [out] dwell_time Get the dwell time in miliseconds.
 * @param [out] interval_time Get the interval time in seconds.
 * @param [out] channel_pool Get the channel pool for the DCS.
 * @param [out] channel_pool_size Get the DCS channel pool size.
 *
 * @return BML_RET_OK on success.
 */
int bml_get_dcs_continuous_scan_params(BML_CTX ctx, const char *radio_mac, int *output_dwell_time,
                                       int *output_interval_time, unsigned int *output_channel_pool,
                                       int *output_channel_pool_size);

/**
 * get DCS continuous scan params.
 *
 * @param [in] ctx                      BML Context.
 * @param [in] radio_mac                radio MAC of selected radio
 * @param [out] output_results          Returning results.
 * @param [in/out] output_results_size  Max requested results & actual returning results.
 * @param [out] output_result_status    Get the status of the returned results
 * @param [in] is_single_scan           Flag indicating if the params belong to a single scan or not
 * 
 * @return BML_RET_OK on success.
 */
int bml_get_dcs_scan_results(BML_CTX ctx, const char *radio_mac,
                             struct BML_NEIGHBOR_AP *output_results,
                             unsigned int *output_results_size, unsigned char *output_result_status,
                             bool is_single_scan);

/**
 * Start a single DCS scan with parameters.
 *
 * @param [in] ctx                  BML Context.
 * @param [in] radio_mac            radio MAC of selected radio
 * @param [in] dwell_time_ms        Set the dwell time in miliseconds.
 * @param [in] channel_pool         Set the channel pool for the DCS.
 * @param [in] channel_pool_size    Set the DCS channel pool size.
 *
 * @return BML_RET_OK on success.
 */
int bml_start_dcs_single_scan(BML_CTX ctx, const char *radio_mac, int dwell_time_ms,
                              int channel_pool_size, unsigned int *channel_pool);

/**
 * Get client list.
 *
 * @param [in] ctx BML Context.
 * @param [in,out] client_list List of MAC addresses sepereted by a comma.
 * @param [in,out] client_list_size Size of client list.
 * @return BML_RET_OK on success.
 */
int bml_client_get_client_list(BML_CTX ctx, char *client_list, unsigned int *client_list_size);

/**
     * Add a station to the unassociated stations 
     * @param [in] ctx BML Context.
     * @param [in] mac_address address of the station
     * @param [in] desired channel
     * @param [in] agent_mac_address  MAcAddress of the agent to be monitoring the station, if empty, all agents are selected
     * 
     * @return BML_RET_OK on success.
     */
int bml_add_unassociated_station_stats(BML_CTX ctx, const char *mac_address,
                                       const char *channel_string, const char *agent_mac_address);

/**
     * Remove a station from the unassociated stations 
     * @param [in] ctx BML Context.
     * @param [in] mac_address address of the station
     * @param [in] agent_mac_address  MAcAddress of the monitoring agent, if empty, all connected agents are selected
     * 
     * @return BML_RET_OK on success,BML_RET_OP_FAILED is station does not exist or any other issue.
     */
int bml_remove_unassociated_station_stats(BML_CTX ctx, const char *mac_address,
                                          const char *agent_mac_address);

/**
 * Get unassociated station stats as a string
 *
 * @param [in] ctx BML Context.
 * @param [in] stats_results pointer where to sopy the results
 * @param [in] stats_results_size buffer size. It wil return the numbetr of Char that has been written including the "\0"
 * @return BML_RET_OK on success.
 */
int bml_get_unassociated_station_stats(BML_CTX ctx, char *stats_results,
                                       unsigned int *stats_results_size);

/**
 * Set client configuration.
 *
 * @param [in] ctx BML Context.
 * @param [in] sta_mac MAC address of a station.
 * @param [in] client_config Client configuration to be set.
 * @return BML_RET_OK on success.
 */
int bml_client_set_client(BML_CTX ctx, const char *sta_mac,
                          const struct BML_CLIENT_CONFIG *client_config);

/**
 * Get client info.
 *
 * @param [in] ctx BML Context.
 * @param [in] sta_mac MAC address of a station.
 * @param [in,out] client Client information.
 * @return BML_RET_OK on success.
 */
int bml_client_get_client(BML_CTX ctx, const char *sta_mac, struct BML_CLIENT *client);

/**
 * @brief Delete client persistent DB info.
 *
 * @param [in] ctx BML Context.
 * @param [in] sta_mac MAC address of a station.
 * @return BML_RET_OK on success, BML_RET_OP_FAILED on failure.
 */
int bml_client_clear_client(BML_CTX ctx, const char *sta_mac);

#ifdef FEATURE_PRE_ASSOCIATION_STEERING

/*
* A steering group defines a group members of which can have steering done
* between them.
* To remove a group configuration call this function with ap_cfgs as NULL, and length as 0.
* @param[in] ctx BML Context.
* @param[in] steeringGroupIndex  Wifi Steering Group index
* @param[in] ap_cfgs             Array of AP Configurations
* @param[in] length              The number of AP Configuration in the array. Cannot be above 3.
*
* @return BML_RET_OK on success.
*
*/
int bml_pre_association_steering_set_group(BML_CTX ctx, uint32_t steeringGroupIndex,
                                           struct BML_STEERING_AP_CONFIG *ap_cfgs,
                                           unsigned int length);

/*
* Call this function to add/modify/remove per-client configuration config of client_mac.
* In order to remove a client configuration call with NULL as "config" parameter 
* or set config.snrProbeHWM to 0.
* @param[in] steeringGroupIndex   Wifi Steering Group index
* @param[in] bssid                AP bssid.
* @param[in] client_mac           The Client's MAC address.
* @param[in] config               The client configuration
* @param[in] ctx BML Context.
* @return BML_RET_OK on success.
*
*/
int bml_pre_association_steering_client_set(BML_CTX ctx, uint32_t steeringGroupIndex,
                                            const BML_MAC_ADDR bssid, const BML_MAC_ADDR client_mac,
                                            struct BML_STEERING_CLIENT_CONFIG *config);

/*
* Callback registration function.
* Call this function to register/unregister the callback function.
* @param[in] ctx BML Context.
* @param[in] pCB pointer to callback function or NULL to unregister.
* @return BML_RET_OK on success.
*/
int bml_pre_association_steering_event_register(BML_CTX ctx, BML_EVENT_CB pCB);

/** 
* On demand measure.
*
* @param[in] ctx BML Context.
* @param[in] steeringGroupIndex  Wifi Steering Group index
* @param[in] bssid               AP bssid.
* @param[in] client_mac          The Client's MAC address.
*
* @return BML_RET_OK on success.
*
*/
int bml_pre_association_steering_client_measure(BML_CTX ctx, unsigned int steeringGroupIndex,
                                                const BML_MAC_ADDR bssid,
                                                const BML_MAC_ADDR client_mac);

/**Initiate a Client Disconnect.
 *
 * This is used to kick off a client, for steering purposes.
 * @param[in]  ctx BML Context.
 * @param[in]  steeringgroupIndex  Wifi Steering Group index
 * @param[in]  bssid               AP bssid. 
 * @param[in]  client_mac          The Client's MAC address
 * @param[in]  type                Disconnect Type
 * @param[in]  reason              Reason code to provide in deauth/disassoc frame.
 *
 * @return BML_RET_OK on success.
 */
int bml_pre_association_steering_client_disconnect(BML_CTX ctx, unsigned int steeringGroupIndex,
                                                   const BML_MAC_ADDR bssid,
                                                   const BML_MAC_ADDR client_mac,
                                                   BML_DISCONNECT_TYPE type, unsigned int reason);

#endif /* FEATURE_PRE_ASSOCIATION_STEERING */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _BML_H_ */
