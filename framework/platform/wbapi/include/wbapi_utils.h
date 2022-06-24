/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _WBAPI_UTILS_H_
#define _WBAPI_UTILS_H_

#include <bcl/beerocks_defines.h>
#include <easylogging++.h>
#include <tlvf/WSC/eWscAuth.h>
#include <tlvf/WSC/eWscEncr.h>

namespace beerocks {
namespace wbapi {

class wbapi_utils {

public:
    /**
     * @brief Converts a string-based bandwith to beerocks::eWiFiBandwidth.
     */
    static beerocks::eWiFiBandwidth bandwith_from_string(const std::string &band);

    /**
     * @brief Converts a string-based bandwith to beerocks::eFreqType.
     */
    static beerocks::eFreqType band_to_freq(const std::string &band);

    /**
     * @brief Converts WSC::eWscAuth ecurity mode to string.
     */
    static std::string security_mode_to_string(const WSC::eWscAuth &security_mode);

    /**
     * @brief Converts a string-based security mode to WSC::eWscAuth.
     */
    static WSC::eWscAuth security_mode_from_string(const std::string &security_mode);

    /**
     * @brief Converts a beerocks::eFreqType encryption type to string.
     */
    static std::string encryption_type_to_string(const WSC::eWscEncr &encryption_type);

    /**
     * @brief Converts a string-based encryption type to WSC::eWscEncr.
     */
    static WSC::eWscEncr encryption_type_from_string(const std::string &encryption_type);

    /**
     * @brief get amxc var object id from the object path.
     */
    static int get_object_id(const std::string &object_path);
};

} // namespace wbapi
} // namespace beerocks

#endif // _WBAPI_UTILS_H_
