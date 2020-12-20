/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "bpl_cfg_uci.h"
#include "../../common/utils/utils.h"

#include <mapf/common/utils.h>

#include <string>

extern "C" {
#include <uci.h>
}

#define LOGF_LOG_CRIT(args...) PRINTF("CRIT", ##args)
#define LOGF_LOG_ERROR(args...) PRINTF("ERROR", ##args)
#define LOGF_LOG_WARN(args...) PRINTF("WARN", ##args)
#define LOGF_LOG_INFO(args...) PRINTF("INFO", ##args)
#define LOGF_LOG_DEBUG(args...) PRINTF("DEBUG", ##args)

#define PRINTF(LEVEL, fmt, args...) printf(LEVEL ":{%s, %d}:" fmt, __func__, __LINE__, ##args)

namespace beerocks {
namespace bpl {

int cfg_uci_get(char *path, char *value, size_t length)
{
    struct uci_ptr ptr;
    struct uci_context *cont = uci_alloc_context();

    if (!cont)
        return RETURN_ERR;

    if (uci_lookup_ptr(cont, &ptr, path, true) != UCI_OK || !ptr.o) {
        uci_free_context(cont);
        return RETURN_ERR;
    }

    strncpy_s(value, length, ptr.o->v.string, length - 1);

    uci_free_context(cont);

    return RETURN_OK;
}

int cfg_uci_get_wireless_int(enum paramType type, const char *interface_name, const char param[],
                             int *value)
{
    int status;
    char val[MAX_UCI_BUF_LEN] = "";

    status = cfg_uci_get_wireless_from_ifname(type, interface_name, param, val);
    if (status == RETURN_ERR)
        return RETURN_ERR;

    status = sscanf_s(val, "%d", value);
    if (status != 1)
        return RETURN_ERR;

    return RETURN_OK;
}

int cfg_uci_get_wireless_from_ifname(enum paramType type, const char *interface_name,
                                     const char param[], char *value)
{
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        ERROR("%s, uci alloc context failed!\n", __FUNCTION__);
        return RETURN_ERR;
    }

    char lookup_str[MAX_UCI_BUF_LEN] = "wireless";
    struct uci_ptr ptr;
    if ((uci_lookup_ptr(ctx, &ptr, lookup_str, true) != UCI_OK)) {
        ERROR("%s, uci lookup failed!\n", __FUNCTION__);
        uci_free_context(ctx);
        return RETURN_ERR;
    }

    if (!ptr.p) {
        ERROR("%s, returned pointer is null\n", __FUNCTION__);
        uci_free_context(ctx);
        return RETURN_ERR;
    }

    bool is_section_found = false;
    struct uci_package *p = ptr.p;
    struct uci_element *e = nullptr;
    struct uci_element *n = nullptr;
    struct uci_section *s = nullptr;
    // Iterate over all wireless sections in the UCI DB
    uci_foreach_element(&p->sections, e)
    {
        s = uci_to_section(e);

        if (strncmp(s->type, "wifi-iface", MAX_UCI_BUF_LEN))
            continue;

        // Iterate over all the options in the section
        uci_foreach_element(&s->options, n)
        {
            struct uci_option *o = uci_to_option(n);

            if (o->type != UCI_TYPE_STRING)
                continue;

            if (strncmp(n->name, "ifname", MAX_UCI_BUF_LEN))
                continue;

            if (strncmp(interface_name, o->v.string, MAX_UCI_BUF_LEN))
                continue;

            // We reached the section containing the requested ifname
            is_section_found = true;
            break;
        }

        if (is_section_found) {
            break;
        }
    }

    //if interface not found in wireless
    if (!is_section_found) {
        ERROR("%s, interface(%s) not found", __FUNCTION__, interface_name);
        uci_free_context(ctx);
        return RETURN_ERR;
    }

    if (type == TYPE_RADIO) {
        // create path to the param in the device: wireless.<device>.param
        bool device_option_exist = false;
        std::string path_str;

        uci_foreach_element(&s->options, n)
        {
            struct uci_option *o = uci_to_option(n);

            if (strncmp(n->name, "device", MAX_UCI_BUF_LEN) == 0 && o->type == UCI_TYPE_STRING) {
                path_str =
                    std::string("wireless." + std::string(o->v.string) + "." + std::string(param));
                device_option_exist = true;
                break;
            }
        }
        uci_free_context(ctx);

        if (!device_option_exist) {
            // radio not found
            ERROR("%s device option not found\n", __func__);
            return RETURN_ERR;
        }

        char path[MAX_UCI_BUF_LEN] = "";
        mapf::utils::copy_string(path, path_str.c_str(), MAX_UCI_BUF_LEN);

        cfg_uci_get(path, value, MAX_UCI_BUF_LEN);

        return RETURN_OK;

    } else { //* type == TYPE_VAP *
        // read the value from the selected section
        // get param in the selected section
        uci_foreach_element(&s->options, n)
        {
            struct uci_option *o = uci_to_option(n);
            // if param is found in options
            if (strncmp(n->name, param, MAX_UCI_BUF_LEN) == 0 && o->type == UCI_TYPE_STRING) {
                strncpy_s(value, MAX_UCI_BUF_LEN, o->v.string, MAX_UCI_BUF_LEN - 1);
                uci_free_context(ctx);
                return RETURN_OK;
            }
        }

        // param not found in option
        ERROR("%s, interface(%s) found but param(%s) isn't configured\n", __FUNCTION__,
              interface_name, param);
        uci_free_context(ctx);
        return RETURN_ERR;
    }
}

int cfg_uci_get_wireless_bool(enum paramType type, const char *interface_name, const char param[],
                              bool *value)
{
    int res = 0;

    int status = cfg_uci_get_wireless_int(type, interface_name, param, &res);
    if (status == RETURN_ERR)
        return RETURN_ERR;

    *value = (res != 0) ? true : false;

    return RETURN_OK;
}

} // namespace bpl
} // namespace beerocks
