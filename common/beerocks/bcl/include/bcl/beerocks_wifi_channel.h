/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_WIFI_CHANNELS_H_
#define _BEEROCKS_WIFI_CHANNELS_H_

#include <iostream>

namespace beerocks {

/**
 * @brief A WifiChannel represents a channel of 2.4ghz, 5ghz or 6ghz band, which comprise
 * of a channel number, center frequency, bandwidth, etc.
 */
class WifiChannel {
public:
    /**
     * @brief Construct a new empty Wifi Channel object
     */
    WifiChannel();

    /**
     * @brief Construct a new Wifi Channel object
     * 
     * @param channel the primary channel
     * @param center_frequency the center frequency
     * @param bandwidth the bandwidth of the channel
     * @param m_ext_above_secondary true if the secondary channel is above the primary one. otherwise, false
     */
    explicit WifiChannel(uint8_t channel, uint16_t center_frequency, eWiFiBandwidth bandwidth,
                         bool m_ext_above_secondary = false);

    /**
     * @brief Construct a new Wifi Channel object
     * 
     * @param channel the primary channel
     * @param freq_type the frequency type of the channel - 2.4GHz, 5GHz, or 6GHz.
     * @param bandwidth the bandwidth of the channel
     * @param m_ext_above_secondary true if the secondary channel is above the primary one. otherwise, false
     */
    explicit WifiChannel(uint8_t channel, eFreqType freq_type, eWiFiBandwidth bandwidth,
                         bool m_ext_above_secondary = false);

    /**
    * @brief Construct a new Wifi Channel object from an existed WifiChannel object
    * 
    * @param wc an already existed wifiChannel object
    */
    WifiChannel(const WifiChannel &wc);

    /**
    * @brief Copies the content of the current wifiChannel
    * 
    * @param wc the wifiChannel object from which the values will be copied
    * @return Current WifiChannel object
    */
    WifiChannel &operator=(const WifiChannel &wc);

    /**
     * @brief Get the channel number
     * 
     * @return unsigned int 
     */
    uint8_t get_channel() const;

    /**
     * @brief Set a new channel.
     * 
     * After calling this method, the center frequency will be updated respectfully.
     * 
     * @param channel the new channel to be set
     */
    void set_channel(uint8_t channel);

    /**
     * @brief Get the center frequency
     * 
     * @return unsigned int 
     */
    uint16_t get_center_frequency() const;

    /**
     * @brief Get the center frequency of a 160MHz bandwidth of a 6ghz band
     * 
     * @return the center frequency of a 160MHz bandwidth of a 6ghz band
     * otherwise, return 0.
     */
    uint16_t get_center_frequency_2() const;

    /**
     * @brief Get the bandwidth object
     * 
     * @return eWiFiBandwidth 
     */
    eWiFiBandwidth get_bandwidth() const;

    /**
     * @brief Set the bandwidth of the object
     * 
     * After calling this method, the center frequency will be updated respectfully.
     * @param bw 
     */
    void set_bandwidth(eWiFiBandwidth bw);

    /**
     * @brief Get the freq type object
     * 
     * @return eFreqType 
     */
    eFreqType get_freq_type() const;

    /**
     * @brief Get the channel extion above primary object
     * 
     * @return
     * 1  - means the secondary channel will be 20mghz above primary channel,
     * 0  - means the secondary channel is same as primary channel
     * -1 - means the secondary channel will be 20mghz below primary channel
     */
    int get_ext_above_primary() const;

    /**
     * @brief Get the ext above secondary object
     * 
     * @note Before this class was created, prplmesh used both m_channel_ext_above_primary
     * and m_ext_above_secondary variables.
     * This difference between them shall be investigated.
     * 
     * @return true if the secondary is above
     * @return false otherwise 
     */
    bool get_ext_above_secondary() const;

    /**
     * @brief check if the channel is an empty
     * 
     * @details A WifiChannel object is empty when using the default constructor.
     * @return true if empty.
     * @return false therwise.
     */
    bool is_empty() const;

    /**
     * @brief check if the channel is a DFS channel.
     * 
     * A DFS channel can only be of 5ghz band.
     * 
     * @return true if the band type is 5ghz and the channel is a DFS channel
     * @return false otherwise
     */
    bool is_dfs_channel() const;

    /**
     * @brief Get the tx power
     * 
     * @return tx power
     */
    uint8_t get_tx_power() const;

    /**
     * @brief Set the tx power
     * 
     * @param tx_power 
     */
    void set_tx_power(uint8_t tx_power);

    /**
     * @brief Get the radar affected 
     * 
     * @return radar affected value 
     */
    uint8_t get_radar_affected() const;

    /**
     * @brief Set the radar affected
     * 
     * @param radar_affected 
     */
    void set_radar_affected(uint8_t radar_affected);

    friend std::ostream &operator<<(std::ostream &out, const WifiChannel &wifi_channel);

private:
    void initialize_empty_wifi_channel_members();
    void initialize_wifi_channel_members(uint8_t channel, eFreqType freq_type,
                                         uint16_t center_frequency, uint16_t center_frequency_2,
                                         eWiFiBandwidth m_bandwidth, bool m_ext_above_secondary);
    bool are_params_valid(uint8_t channel, eFreqType freq_type, uint16_t center_frequency,
                          eWiFiBandwidth m_bandwidth);

    /**
     * @brief channel number
     */
    uint8_t m_channel;
    /**
     * @brief channel's center frequency.
     * The center frequency value is different from frequency
     * value when the bandwidth is above 20mghz.
     */
    uint16_t m_center_frequency;
    /**
     * @brief relavent only for 6ghz band and when the bandwidth is ether 160MHz or 80+80MHz.
     * Otherwise, equal to 0.
     * The Center Frequency 2 field indicates the center frequency of the
     * 160 MHz channel in the 6 GHz band.
     * If the  bandwidth is 80+80 MHz, then it indicates the center frequency of the secondary 80 MHz
     * @note: The center_frequency_2 name is derived from hostapd's variable name cf2, a.k.a center_frequency2.
     * hostapd has both cf1 and cf2 variables.
     */
    uint16_t m_center_frequency_2;
    /**
     * @brief channel's bandwidth
     */
    eWiFiBandwidth m_bandwidth;
    /**
     * @brief channel's frequency type. a.k.a band type
     */
    eFreqType m_freq_type;
    /**
     * @brief Indicate whether the channel is a DFS channel. This is
     * only relavent for 5ghz band.
     */
    bool m_is_dfs;
    /**
     * @brief Is channel extention (the secondary channel) above the primary channel
     * When the bandwidth is above 20mghz, a secondary channel is used.
     * positive value means the secondary channel will be above primary channel
     * zero value means the secondary channel is same as primary channel
     * negative value means the secondary channel will be below primary channel
     */
    int m_ext_above_primary;
    /**
     * @brief Before this class was created, prplmesh used both m_channel_ext_above_primary
     * and m_ext_above_secondary variables.
     * This difference between them shall be investigated.
     */
    bool m_ext_above_secondary;

    uint8_t m_tx_power;

    uint8_t m_radar_affected;
};

} // namespace beerocks

#endif // _BEEROCKS_WIFI_CHANNELS_H_
