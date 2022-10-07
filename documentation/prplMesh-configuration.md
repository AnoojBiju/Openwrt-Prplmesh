# Introduction

prplMesh can be configured through different options.
Depending on the platform, those options are set in different ways (see [Platform-specific files](#Platform-specific-files)).

For most platforms, changes in options are only taken into account after prplMesh is restarted.

To change settings at runtime without restarting prplMesh, see also [Configuration via NBAPI](https://gitlab.com/prpl-foundation/prplmesh/prplMesh/-/wikis/prplMesh-Northbound-API#configuration-via-nbapi)

## All options

For each platform, a default configuration file is provided.

Some optional options are not included in default configuration files, and instead have default values within prplMesh.
When a platform-specific configuration file specifies a value for a option, it overrides the default value used by prplMesh.

The tables in the sections below outlines all the existing options, across all platforms.

### Global configuration options

In the following table, "default" means default value used within prplMesh if it's not provided by the platform.

| Option                                       | Type    | Required | Default         | Description                                                                                                                                           |
|----------------------------------------------|---------|----------|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| management_mode                              | string  | yes      | *none*          | Multi-AP mode (Agent, Controller, Controller+Agent).                                                                                                  |
| operating_mode                               | string  | yes      | *none*          | Legacy option used together with management_mode `Not-Multi-AP.`, will be removed in the future.                                                      |
| onboarding                                   | bool    | no       | *none*          | The current prplMesh onboarding state. prplMesh doesn't currently set it.                                                                             |
| rdkb_extensions                              | bool    | no       | 0               | If set to 1, enable the rdk-b extensions. Requires BEEROCKS_RDKB to be set at compile-time.                                                           |
| band_steering                                | bool    | no       | 0               | If set to 1, enable client band steering (used by the optimal path feature).                                                                          |
| client_roaming                               | bool    | no       | 0               | If set to 1, enable client roaming (used by the optimal path feature).                                                                                |
| roaming_hysteresis_percent_bonus             | integer | no       | 10              | Roaming hysteresis bonus percentage (see optimal path feature).                                                                                       |
| dfs_reentry                                  | bool    | no       | 1               | If set to 1, enable DFS re-entry (see channel selection task).                                                                                        |
| best_channel_rank_th                         | integer | no       | 0               | Threshold for the best channel rank (see channel selection task).                                                                                     |
| mem_only_psk                                 | bool    | yes      | *none*          | If set to 1, store the PSK in-memory (see hostapd's 'mem_only_psk' option).                                                                           |
| backhaul_band                                | bool    | yes      | *none*          | The preferred band for wireless backhaul. Supported values: '2.4GHz', '5GHz', 'auto'.                                                                 |
| backhaul_wire_iface                          | string  | yes      | *none*          | The network interface to use for wired backhaul.                                                                                                      |
| certification_mode                           | bool    | yes      | *none*          | If set to 1, enable certification-specific features or behavior (e.g. enable UCC listener).                                                           |
| stop_on_failure_attempts                     | bool    | no       | 1               | If a problem occurs, the number of times to retry before the agent is stopped completely. Set to 0 to disable.                                        |
| persistent_db                                | bool    | no       | 0               | If set to 1, enable the persistent database (stores clients in a database). Requires a platform that supports it.                                     |
| clients_persistent_db_max_size               | integer | no       | 256             | Maximum number of clients to store in the persistent DB.                                                                                              |
| max_timelife_delay_minutes                   | integer | no       | 525600 (1 year) | Maximum lifetime (in minutes) of clients in the persistent DB.                                                                                        |
| unfriendly_device_max_timelife_delay_minutes | integer | no       | 1440 (1 day)    | Maximum lifetime (in minutes) of "unfriendly" clients in the persistent DB.                                                                           |
| persistent_db_aging_interval_sec             | integer | no       | 3600 (1 hour)   | Interval (in seconds) to run the persistent DB aging mechanism.                                                                                       |
| zwdfs_flag                                   | integer | no       | 0               | BITWIZE of On-Radar, On-Selection, Pre-CAC which affect the the "zero wait" DFS feature.                                                              |
| steering_disassoc_timer_msec                 | integer | no       | 200             | Client steering disassociation timer.                                                                                                                 |
| link_metrics_request_interval_sec            | integer | no       | 60              | Interval for periodic link metrics requests from all agents (set to 0 to disable).                                                                    |
| clients_measurement_mode                     | integer | no       | 1               | Client measurements mode. `0` disables, `1` enables the measurements for all clients.`2` enables measurements only for clients selected for steering. |
| mandatory_interfaces                         | string  | no       | *empty*         | Comma-separated list of wireless interfaces that prplMesh should use. If empty, try to use all of them.                                               |
| unsuccessful_assoc_report_policy             | bool    | no       | 1               | If set to 1, enable reporting for unsuccessful associations.                                                                                          |
| unsuccessful_assoc_max_reporting_rate        | int     | no       | 30              | Maximum rate for reporting unsuccessful association in attempts per minute.                                                                           |
| rssi_measurements_timeout                    | int     | no       | 10000           | rssi measurements timeout in msec, used by the optimal path task                                                                                      |
| beacon_measurements_timeout                  | int     | no       | 6000            | 11k beacon measurements timeout in msec, used by the optimal path task                                                                                |
| optimal_path_prefer_signal_strength          | bool    | no       | false           | used by optimal_path_task; chooses best BSS based on `rssi` if prefer_signal_strength is TRUE, `phy_rate` otherwise                                   |
| client_11k_roaming                           | bool    | no       | true            | used by optimal_path_task; used to compute new BSS for the STA based on 11k measurements by STA                                                       |
| load_balancing                               | bool    | no       | false           | used by load_balancer_task (exit early if false); load_balancer_task will use (currently TODO) client_steering_task to move a STA between agents      |
| health_check_enabled                         | bool    | no       | false           | used by controller to start / stop the health_check_task                                                                                              |
| diagnostics_measurements                     | bool    | no       | true            | used by controller to start / stop statistics_polling_task                                                                                            |
| diagnostics_measurements_polling_rate_sec    | int     | no       | 10              | used by statistics_polling_task as interval for sending beerocks_message::cACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST to known agents            |
| channel_select_task_enabled                  | bool    | no       | true            | used by controller to start / stop channel_select_task                                                                                                |
| dfs_task_enabled                             | bool    | no       | true            | used by controller to start / stop dynamic_channel_selection_task_r2                                                                                  |

### NBAPI control options for controller tasks

NBAPI exposes a subset of these options that are related to the execution of controller tasks.

These options are loaded from UCI; the default values are set by the controller if UCI does not hold these options.
They are warm-applicable, meaning new values set through the NBAPI are taken into account by the controller without a restart; because of the inter-dependencies betweeen these options though, care is advised when changing them.

BPL is used to persistently store changes to these options.


The following table presents these options, see also [Configuration via NBAPI](https://gitlab.com/prpl-foundation/prplmesh/prplMesh/-/wikis/prplMesh-Northbound-API#configuration-via-nbapi).

| Option                                    | NBAPI Name                         | Type | Default | Used by                                                                                                                                      |
|-------------------------------------------|------------------------------------|------|---------|----------------------------------------------------------------------------------------------------------------------------------------------|
| dfs_reentry                               | DFSReentry                         | bool | true    | channel_selection_task; currently does nothing as the task never goes to the state where this flag is checked                                |
| roaming_hysteresis_percent_bonus          | SteeringCurrentBonus               | int  | 10      | optimal_path_task; applies bonus to current BSS {phy_rate or rssi}; choice of parameter is based on prefer_signal_strength flag              |
| optimal_path_prefer_signal_strength       | OptimalPathPreferSignalStrenght    | bool | false   | optimal_path_task; chooses best BSS based on `rssi` if prefer_signal_strength is TRUE, `phy_rate` otherwise                                  |
| steering_disassoc_timer_msec              | SteeringDisassociationTimer        | int  | 200     | client_steering_task; used to format the 1905 Client Steering Request packet sent to the steering source agent                               |
| link_metrics_request_interval_sec         | LinkMetricsRequestInterval         | int  | 60      | agent_monitoring_task: interval for AP Metrics; AND link_metrics_task: period of 1905 Link Metric Query                                      |
| band_steering                             | BandSteeringEnabled                | bool | false   | channel_selection_task and optimal_path_task;                                                                                                |
| client_roaming                            | ClientRoamingEnabled               | bool | false   | optimal_path_task                                                                                                                            |
| client_11k_roaming                        | Client_11kRoaming                  | bool | true    | optimal_path_task; used to compute new BSS for the STA based on 11k measurements by STA                                                      |
| load_balancing                            | LoadBalancingEnabled               | bool | false   | load_balancer_task (exit early if false); load_balancer_task will use (TODO) client_steering_task to move a STA to a less busy agent         |
| health_check_enabled                      | HealthCheckTask                    | bool | false   | controller to start / stop the health_check_task                                                                                             |
| diagnostics_measurements                  | StatisticsPollingTask              | bool | true    | controller to start / stop statistics_polling_task                                                                                           |
| diagnostics_measurements_polling_rate_sec | StatisticsPollingRateSec           | int  | 10      | statistics_polling_task as interval for sending beerocks_message::cACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST to known agents           |
| channel_select_task_enabled               | ChannelSelectionTaskEnabled        | bool | true    | controller to start / stop channel_select_task                                                                                               |
| dfs_task_enabled                          | DynamicChannelSelectionTaskEnabled | bool | true    | controller to start / stop dynamic_channel_selection_task_r2                                                                                 |

### A short overview of controller tasks

Thanks to the code modularity, it is possible to dynamically enable/disable certain controller features that are implemented by controller tasks.
The long-term goal is to expose an API that allows performing the same operations by an external entity, and have the controller act as an 1905 adaptation layer.

PPM-2155 implements the API that allows configuring the controller features.
Below is a short overview of controller tasks that are either completely or partially disabled by flags exposed by this API.

##### Association handling task:

On-demand
Uses beerocks messages, fills new station 11k capability by asking for a beacon measurement report, asks the station for a RSSI measurement.
Because of its low complexity, this task is not worth disabling.

Settings consumed by this tasks :
   if (settings_client_11k_roaming) : request 11k beacon measurement report from STA and fill STA 11k capabilities based on content of the response or absence thereof.
   if (settings_client_band_steering && settings_client_optimal_path_roaming ) : request an RSSI measurement from STA with a beerocks_message::cACTION_CONTROL_CLIENT_RX_RSSI_MEASUREMENT_REQUEST.


##### Channel selection task

Periodic
Settings consumed by this task :
    settings_dfs_reentry : consumed by this task; in a dead loop of the FSM : missing the event to enter the loop; this flag controls band steering the clients away from the 5GHz AP in order to perform a DFS clear on that AP, before moving the clients back.
    settings_client_band_steering : second flag, along with dfs_reentry, that enables/disables steering clients away from 5GHz AP.
    settings_ire_roaming : start a ire_network_optimization_task when this flag is set.


##### Client steering task

On-demand
Settings consumed by this task :
    m_steer_restricted : not strictly a setting, a runtime flag for the client steering task; perform the steering but do not update statistics except for steer attempt stats. Only set to true in one call, from channel_selection_task, when steering STAs away from 5GHz, before a DFS clear.


##### Dynamic channel selection task

Periodic
Complex FSM, two state variables with their own FSMs, plus two operation queues, that are used to feed the two FSMs; the two queues are filled by beerocks messages (BML library); some are available in the beerocks_cli, others not.
No settings from database, no task spawn; see PPM-2155 for an attempt to illustrate the FSM of this task


##### IRE Network Optimization

On-demand
Iterates over the Extender hierarchy and spawns optimal_path_tasks for each IRE; (wait 30sec between each spawn).

Launched by Channel selection task if (database.settings_ire_roaming())
Launched by a beerocks_cli command


##### Link metric task

Periodic
Periodic task launched by the controller, hidden behind (database.config.management_mode != BPL_MGMT_MODE_NOT_MULTIAP).

Sends a 1905 Link Metric Query to all agents registered in the database with an interval of (database.config.link_metrics_request_interval_seconds [seconds).

Also, processes the 1905 Link Metric Responses and stores the reported stats in the database.


##### Load balancer task

On-demand
Started by two beerocks messages, ACTION_CLI_LOAD_BALANCER_TASK, sent by beerocks_cli , and ACTION_CONTROL_HOSTAP_LOAD_MEASUREMENT_NOTIFICATION, sent by an Agent.
Eventually (code is commented out under a TODO) would use the client_steering_task to move a STA from a more busy AgentA to a less busy AgentB; will need to check the flag steering_enabled before creating the client_steering_task.

Note: the task is attached to an Agent, identified by its 1905 AL MAC, let's call it AgentOrigin. The ACTION_CONTROL_HOSTAP_LOAD_MEASUREMENT_NOTIFICATION is sent by AgentOrigin when ChannelLoad or StaCount cross a configured threshold,
i.e. the agent is under a big load.
The load_balancer_task finds the busiest AgentA and least busy AgentB among the children of AgentOrigin, i.e., in the subtree rooted on AgentOrigin. It then 'would' attempt to steer a STA of AgentA to AgentB (when the code would be un-commented).
The total number of devices (agents and stations) in the subtree rooted on AgentOrigin stays the same in this case.


##### Network health check task

On-demand
Started by controller under the database.settings_health_check flag.
Removes agents from the DB, that were last seen more than 120sec ago (delta between timestamp of current task iteration and last_seen timestamp in the database).
Removes STAs from the DB that were last seen more than 140sec ago after attempting to update the last_seen with a beerocks_message::cACTION_CONTROL_ARP_QUERY_REQUEST / beerocks_message::ACTION_CONTROL_ARP_QUERY_RESPONSE sequence.


##### Optimal path task

On-demand
If !(settings_client_band_steering && settings_client_optimal_path_roaming && settings_client_11k_roaming || settings_ire_roaming) exits early. First three options are checked if launched for a STA. Last option, ire_roaming, is checked if the task is launched for an Agent.

Launched by channel_selection_task || ire_network_optimization_task || beerocks_cli command | association_handling_task.

In channel_selection_task, it should currently not be triggered since the FSM loop that launches this task is not activated.

Association_handling_task systematically launches this task for a Client that doesn't have the handoff flag set (the flag is set by the steering / btm_request tasks for stations that are currently being steered).

Setting consumed:
    settings_client_optimal_path_roaming_prefer_signal_strength: choosing between "RSSI" or "Estimated Phy Rate" choice for best parent; ("RSSI" is based on an 11k beacon measurement report if the station supports it, on measurements from the Agent APs otherwise).


##### Statistics polling task

Periodic
Launched by controller (settings_diagnostics_measurements) or via a beerocks_cli command.
Every `diagnostics_measurements_polling_rate_sec` seconds sends a beerocks_message::cACTION_CONTROL_HOSTAP_STATS_MEASUREMENT_REQUEST to each agent.


##### Topology task

Periodic
Launched by the controller. Handles the 1905 topology notification and pushes STA_CONNECTED event for DHCP task, client steering task, and btm request task.
Starts the association handling task.


### Radio-specific configuration options (UCI only).

In addition to the global configuration options, prplMesh needs to have one configuration section per radio.
The available options of the radio sections are described in the table that follows.

Again, "default" means default value used within prplMesh if it's not provided by the platform.

| Option                  | Type   | Required | Default | Description                                                                                                                        |
| ----------------------- | ------ | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| hostap_iface            | string | yes      | *none*  | One of the (AP) interface name of the radio. For MaxLinear devices, this must be the "radio interface" (i.e. the dummy interface). |
| sta_iface               | string | yes      | *none*  | The station interface to use for this radio.                                                                                       |
| hostap_iface_steer_vaps | string | yes      | *none*  | The interfaces (VAP) that the client can be steered to. If empty, clients can be steered to any VAP (see optimal path task).       |

## Platform-specific files

### Linux builds (dummy)

For the "dummy" variant, the prplMesh options are set in the `prplmesh_platform_db` file.

This file is composed of key and values, separated by an equal sign (`=`).
Trailing whitespace and whitespace at the beginning of a line is removed.
When a number sign (`#`) is encountered, everything that follows until the end of the line is ignored (it can thus be used to include comments in the file).

A default version of the file is included in this repository: `framework/platform/bpl/platform_db/prplmesh_platform_db`).

The following variables are specific to Linux builds:
| Option                                    | Type   | Required | Default | Description                                   |
| ----------------------------------------- | ------ | -------- | ------- | --------------------------------------------- |
| hostapd_ctrl_path_<interface_name>        | string | yes      | *none*  | Path to the hostapd's control sockets.        |
| wpa_supplicant_ctrl_path_<interface_name> | string | yes      | *none*  | Path to the wpa_supplicant's control sockets. |

### RDK-B builds

For RDK-B, a `prplmesh_db` file is used.

Unlike for dummy builds, this file is configured at build time using CMAKE options.

The default version is in `framework/platform/bpl/db/uci/prplmesh_db.in`.

The format of this file is the same format as for OpenWrt's UCI options (see prplWrt builds below).

### prplWrt builds

For prplWrt, the [standard UCI system](https://openwrt.org/docs/guide-user/base-system/uci) is used.

A default configuration file also exists, and it's stored [alongside the prplMesh package in the prpl feed](https://gitlab.com/prpl-foundation/prplwrt/feed-prpl/-/blob/prplwrt/prplmesh/files/etc/uci-defaults/prplmesh).
