/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "wbapi_utils.h"

namespace beerocks {
namespace wbapi {

beerocks::eWiFiBandwidth wbapi_utils::bandwith_from_string(const std::string &band)
{
    if (band == "160MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_160;
    } else if (band == "80MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_80;
    } else if (band == "40MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_40;
    } else if (band == "20MHz") {
        return beerocks::eWiFiBandwidth::BANDWIDTH_20;
    } else {
        return beerocks::eWiFiBandwidth::BANDWIDTH_UNKNOWN;
    }
}

beerocks::eFreqType wbapi_utils::band_to_freq(const std::string &band)
{
    if (band == "2.4GHz") {
        return beerocks::eFreqType::FREQ_24G;
    } else if (band == "5GHz") {
        return beerocks::eFreqType::FREQ_5G;
    } else {
        LOG(ERROR) << "not Supported FreqBand value";
        return beerocks::eFreqType::FREQ_UNKNOWN;
    }
}

std::string wbapi_utils::security_mode_to_string(const WSC::eWscAuth &security_mode)
{
    std::string sec_mode = "None";
    if (security_mode == WSC::eWscAuth::WSC_AUTH_WPA2PSK ||
        security_mode == WSC::eWscAuth::WSC_AUTH_WPA2) {
        sec_mode = "WPA2-Personal";
    } else if (security_mode == WSC::eWscAuth::WSC_AUTH_WPAPSK ||
               security_mode == WSC::eWscAuth::WSC_AUTH_WPA) {
        sec_mode = "WPA-Personal";
    }
    return sec_mode;
}

WSC::eWscAuth wbapi_utils::security_mode_from_string(const std::string &security_mode)
{
    WSC::eWscAuth sec_mode = WSC::eWscAuth::WSC_AUTH_OPEN;
    if (security_mode == "WPA-Personal") {
        sec_mode = WSC::eWscAuth::WSC_AUTH_WPA;
    } else if (security_mode == "WPA2-Personal") {
        sec_mode = WSC::eWscAuth::WSC_AUTH_WPA2;
    }
    return sec_mode;
}

std::string wbapi_utils::encryption_type_to_string(const WSC::eWscEncr &encryption_type)
{
    std::string encrypt_mode = "Default";
    if (encryption_type == WSC::eWscEncr::WSC_ENCR_AES) {
        encrypt_mode = "AES";
    } else if (encryption_type == WSC::eWscEncr::WSC_ENCR_TKIP) {
        encrypt_mode = "TKIP";
    }
    return encrypt_mode;
}

WSC::eWscEncr wbapi_utils::encryption_type_from_string(const std::string &encryption_type)
{
    WSC::eWscEncr encrypt_mode = WSC::eWscEncr::WSC_ENCR_NONE;
    if (encryption_type == "AES") {
        encrypt_mode = WSC::eWscEncr::WSC_ENCR_AES;
    } else if (encryption_type == "TKIP") {
        encrypt_mode = WSC::eWscEncr::WSC_ENCR_TKIP;
    }
    return encrypt_mode;
}

int wbapi_utils::get_object_id(const std::string &object_path)
{
    size_t pos_start = 0;
    size_t pos_end;
    std::string delimiter = ".";
    size_t delim_len      = delimiter.length();
    std::string token;

    while ((pos_end = object_path.find(delimiter, pos_start)) != std::string::npos) {
        token     = object_path.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
    }

    return stoi(token);
}

} // namespace wbapi
} // namespace beerocks
