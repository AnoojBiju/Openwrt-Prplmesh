/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "utils_wlan_hal_whm.h"
#include <easylogging++.h>

namespace bwl {
namespace whm {

eRadioState utils_wlan_hal_whm::radio_state_from_string(const std::string &state)
{
    if (state == "Down") {
        return eRadioState::DISABLED;
    } else if (state == "Up") {
        return eRadioState::ENABLED;
    } else {
        return eRadioState::UNKNOWN;
    }
}

const std::map<std::string, WiFiSec> utils_wlan_hal_whm::security_type_table = {
    {"INVALID", WiFiSec::Invalid},
    {"None", WiFiSec::None},
    {"WEP-64", WiFiSec::WEP_64},
    {"WEP-128", WiFiSec::WEP_128},
    {"WPA-Personal", WiFiSec::WPA_PSK},
    {"WPA2-Personal", WiFiSec::WPA2_PSK},
    {"WPA-WPA2-Personal", WiFiSec::WPA_WPA2_PSK},
    {"WPA2-WPA3-Personal", WiFiSec::WPA2_WP3_PSK},
    {"WPA3-Personal", WiFiSec::WPA3_PSK},
};

std::string utils_wlan_hal_whm::security_type_to_string(const WiFiSec &security_type)
{
    for (const auto &map_it : security_type_table) {
        if (map_it.second == security_type) {
            return map_it.first;
        }
    }
    return "INVALID";
}

WiFiSec utils_wlan_hal_whm::security_type_from_string(const std::string &security_type)
{
    auto map_it = security_type_table.find(security_type);
    return map_it == security_type_table.end() ? WiFiSec::Invalid : map_it->second;
}

static const uint8_t sBase64Table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool utils_wlan_hal_whm::base64_decode(std::vector<uint8_t> &decoded_output,
                                       const std::string &base64_input)
{
    decoded_output.clear();
    uint8_t dtable[256] = {0x80};
    dtable['=']         = 0;
    size_t i            = 0;
    for (i = 0; i < sizeof(sBase64Table) - 1; i++) {
        dtable[sBase64Table[i]] = (uint8_t)i;
    }

    size_t count   = 0;
    size_t srcSize = base64_input.length();
    for (i = 0; i < srcSize; i++) {
        if (dtable[(uint8_t)base64_input[i]] != 0x80) {
            count++;
        }
    }

    if ((count == 0) || count % 4) {
        return false;
    }

    size_t outputLength = (count / 4) * 3;
    decoded_output.resize(outputLength);

    uint8_t *pos = &decoded_output[0];
    count        = 0;
    uint8_t block[4];
    size_t pad = 0;
    for (i = 0; i < srcSize; i++) {
        uint8_t tmp = dtable[(uint8_t)base64_input[i]];
        if (tmp == 0x80) {
            continue;
        }

        if (base64_input[i] == '=') {
            pad++;
        }
        block[count] = tmp;
        count++;
        if (count == 4) {
            *pos = (block[0] << 2) | (block[1] >> 4);
            pos++;
            *pos = (block[1] << 4) | (block[2] >> 2);
            pos++;
            *pos = (block[2] << 6) | block[3];
            pos++;
            count = 0;
            if (pad) {
                if (pad == 1) {
                    pos--;
                } else if (pad == 2) {
                    pos -= 2;
                } else {
                    /* Invalid padding */
                    LOG(ERROR) << "Invalid padding";
                    return false;
                }
                break;
            }
        }
    }
    return true;
}

} // namespace whm
} // namespace bwl
