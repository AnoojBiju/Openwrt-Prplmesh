/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef BPL_CFG_UCI_H_
#define BPL_CFG_UCI_H_

#ifdef BEEROCKS_OPENWRT

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef BEEROCKS_UGW
#define restrict __restrict
#include <libsafec/safe_str_lib.h>
#else
#define sscanf_s sscanf
#define strncpy_s(a, b, c, d) strncpy(a, c, d)
#endif

#undef snprintf_s
#define snprintf_s snprintf

#ifndef u_int_32
#define u_int_32 unsigned int
#endif

#ifndef _cplusplus
#include <stdbool.h>
#endif

#define CRIT(fmt, args...) LOGF_LOG_CRIT(fmt, ##args)
#define ERROR(fmt, args...) LOGF_LOG_ERROR(fmt, ##args)
#define WARN(fmt, args...) LOGF_LOG_WARN(fmt, ##args)
#define INFO(fmt, args...) LOGF_LOG_INFO(fmt, ##args)
#define DEBUG(fmt, args...) LOGF_LOG_DEBUG(fmt, ##args)

#define MAX_UCI_BUF_LEN 64

enum paramType { TYPE_RADIO = 0, TYPE_VAP };

#elif BEEROCKS_RDKB

#include <slibc/stdio.h>
#include <slibc/string.h>

extern "C" {
#include <uci_wrapper.h>
}

#endif

#define RETURN_ERR_PARSE -3
#define RETURN_ERR_NOT_FOUND -2
#define RETURN_ERR -1
#define RETURN_OK 0

namespace beerocks {
namespace bpl {

int cfg_uci_get(char *path, char *value, size_t length);
int cfg_uci_get_wireless_bool(enum paramType type, const char *interface_name, const char param[],
                              bool *value);

int cfg_uci_get_wireless_from_ifname(enum paramType type, const char *interface_name,
                                     const char param[], char *value);

} // namespace bpl
} // namespace beerocks

#endif // BPL_CFG_UCI_H
