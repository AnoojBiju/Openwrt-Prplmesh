/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BPL_ERR_H_
#define _BPL_ERR_H_

#include <ostream>

namespace beerocks {
namespace bpl {

/****************************************************************************/
/******************************* Definitions ********************************/
/****************************************************************************/

/* Beerocks Error Definitions */
#define BPL_ERROR_STRING_LEN 256 /* Maximal length of BPL error string */

// Helper MACROs for Enum/String generation
#define GENERATE_ERROR_ENUM(ENUM) ENUM,
#define GENERATE_ERROR_STRING(STRING) "BPL_ERR_" #STRING,

/* Beerocks Error Codes */
// Error codes ENUM
enum class eErrorCode {
    /* 00 */ NONE,
    /* 01 */ UNKNOWN,
    /* 02 */ OPERATION_NOT_SUPPORTED,
    /* 03 */ BH_READING_DATA_FROM_THE_BRIDGE,
    /* 04 */ BH_TIMEOUT_ATTACHING_TO_WPA_SUPPLICANT,
    /* 05 */ BH_SCAN_FAILED_TO_INITIATE_SCAN,
    /* 06 */ BH_SCAN_TIMEOUT,
    /* 07 */ BH_SCAN_EXCEEDED_MAXIMUM_FAILED_SCAN_ATTEMPTS,
    /* 08 */ BH_CONNECTING_TO_MASTER,
    /* 09 */ BH_ASSOCIATE_4ADDR_TIMEOUT,
    /* 10 */ BH_ASSOCIATE_4ADDR_FAILURE,
    /* 11 */ BH_ROAMING,
    /* 12 */ BH_DISCONNECTED,
    /* 13 */ BH_WPA_SUPPLICANT_TERMINATED,
    /* 14 */ BH_SLAVE_SOCKET_DISCONNECTED,
    /* 15 */ BH_STOPPED,
    /* 16 */ SLAVE_CONNECTING_TO_BACKHAUL_MANAGER,
    /* 17 */ SLAVE_INVALID_MASTER_SOCKET,
    /* 18 */ SLAVE_FAILED_CONNECT_TO_PLATFORM_MANAGER,
    /* 19 */ SLAVE_PLATFORM_MANAGER_REGISTER_TIMEOUT,
    /* 20 */ SLAVE_SLAVE_BACKHAUL_MANAGER_DISCONNECTED,
    /* 21 */ SLAVE_STOPPED,
    /* 22 */ AP_MANAGER_START,
    /* 23 */ AP_MANAGER_DISCONNECTED,
    /* 24 */ AP_MANAGER_HOSTAP_DISABLED,
    /* 25 */ AP_MANAGER_ATTACH_FAIL,
    /* 26 */ AP_MANAGER_SUDDEN_DETACH,
    /* 27 */ AP_MANAGER_HAL_DISCONNECTED,
    /* 28 */ AP_MANAGER_CAC_TIMEOUT,
    /* 29 */ MONITOR_DISCONNECTED,
    /* 30 */ MONITOR_HOSTAP_DISABLED,
    /* 31 */ MONITOR_ATTACH_FAIL,
    /* 32 */ MONITOR_SUDDEN_DETACH,
    /* 33 */ MONITOR_HAL_DISCONNECTED,
    /* 34 */ MONITOR_REPORT_PROCESS_FAIL,
    /* 35 */ CONFIG_PLATFORM_REPORTED_INVALID_CONFIGURATION,
    /* 36 */ CONFIG_NO_VALID_BACKHAUL_INTERFACE,
    /* 37 */ WATCHDOG_PROCESS_STUCK,
    /* 38 */ WATCHDOG_PROCESS_ZOMBIE,
    /* 39 */ LAST,
};

} // namespace bpl
} // namespace beerocks

#endif /* _BPL_ERR_H_ */
