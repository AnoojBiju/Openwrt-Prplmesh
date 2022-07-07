/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */
#ifndef __BWL_NL80211_CLIENT_WHM_H__
#define __BWL_NL80211_CLIENT_WHM_H__

#include <bwl/nl80211_client.h>

namespace bwl {

/**
 * @brief NL80211 client whm implementation.
 *
 * This class is used by the whm flavor of the BWL library.
 */
class nl80211_client_whm : public nl80211_client {

public:
    /**
     * @brief Gets a list with the names of existing wireless VAP interfaces.
     *
     * @param[out] interfaces List with the names of wireless interfaces.
     *
     * @return True on success and false otherwise.
     */
    bool get_interfaces(std::vector<std::string> &interfaces) override;

    /**
     * @brief Gets interface information.
     *
     * Interface information contains, among others, the MAC address and SSID of the given network
     * interface.
     *
     * @param[in] interface_name Interface name, either radio or Virtual AP (VAP).
     * @param[out] interface_info Interface information.
     *
     * @return True on success and false otherwise.
     */
    virtual bool get_interface_info(const std::string &interface_name,
                                    interface_info &interface_info) override;
    /**
     * @brief Gets radio information.
     *
     * Radio information contains HT/VHT capabilities and the list of supported channels.
     *
     * @param[in] interface_name Interface name, either radio or Virtual AP (VAP).
     * @param[out] radio_info Radio information.
     *
     * @return True on success and false otherwise.
     */
    virtual bool get_radio_info(const std::string &interface_name, radio_info &radio_info) override;

    /**
     * @brief Gets station information.
     *
     * Fills station information with whm data.
     *
     * @param[in] interface_name Virtual AP (VAP) interface name.
     * @param[in] sta_mac_address MAC address of a station connected to the local interface.
     * @param[out] sta_info Station information.
     *
     * @return True on success and false otherwise.
     */
    bool get_sta_info(const std::string &interface_name, const sMacAddr &sta_mac_address,
                      sta_info &sta_info) override;

    /**
     * @brief Gets whm survey information.
     *
     * @see nl80211_client::get_survey_info
     *
     * This implementation returns fixed survey info for the first 8 2.4GHz channels.
     */
    bool get_survey_info(const std::string &interface_name, SurveyInfo &survey_info) override;

    /**
     * @brief Set the tx power limit
     *
     * Set tx power limit for a radio
     *
     * @param[in] interface_name radio interface name.
     * @param[in] limit tx power limit in dBm to set
     * @return true success and false otherwise
     */
    bool set_tx_power_limit(const std::string &interface_name, uint32_t limit) override;

    /**
     * @brief Get the tx power
     *
     * @param[in] interface_name radio interface name.
     * @param[out] power tx power in dBm.
     * @return true success and false otherwise
     */
    bool get_tx_power_dbm(const std::string &interface_name, uint32_t &power) override;

    bool channel_scan_abort(const std::string &interface_name) override;
};

} // namespace bwl

#endif
