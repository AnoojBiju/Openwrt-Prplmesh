/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_TYPES_H_
#define _TLVF_TYPES_H_

#include <easylogging++.h>
#include <iomanip>
#include <sstream>
#include <tlvf/common/sMacAddr.h>

namespace tlvf {
/**
 * @brief convert integer to hexadecimal string
 *
 * @param integer integer to convert
 * @param number_of_digits  represent how much digits the number should have, so the function will
 *                          pad the number with zeroes from left, if necessary.
 *                          for example: int_to_hex_string(255, 4) -> "00ff"
 * @return std::string hexadecimal representation of 'integer'
 */
std::string int_to_hex_string(const unsigned int integer, const uint8_t number_of_digits);

/**
 * @brief Converts a mac address to a human-readable formatted string
 *
 * @param mac_address mac address to convert (uint8_t array)
 * @return std::string of the format xx:xx:xx:xx:xx:xx
 */
std::string mac_to_string(const uint8_t *mac_address);

/**
 * @brief Converts a mac address to a human-readable formatted string
 *
 * @param mac_address mac address to convert (sMacAddr)
 * @return std::string of the format xx:xx:xx:xx:xx:xx
 */

std::string mac_to_string(const sMacAddr &mac);

/**
 * @brief Concerts a string to binary mac address (6 bytes buffer)
 *
 * The string may be in one of the following formats (X is an upper or lower case hex digit):
 * @li XX:XX:XX:XX:XX:XX
 * @li 0xXXXXXXXXXX
 * @li XXXXXXXXXX
 *
 * @param[OUT] buf output buffer (has to be 6 bytes long)
 * @param[IN] mac string to convert
 * @return false if conversion failed - @a buf is reset to 0 in this case
 */
bool mac_from_string(uint8_t *buf, const std::string &mac);

/**
 * @brief Converts a string representing a MAC address to sMacAddr
 *
 * The string may be in one of the following formats (X is an upper or lower case hex digit):
 * @li XX:XX:XX:XX:XX:XX
 * @li 0xXXXXXXXXXX
 * @li XXXXXXXXXX
 *
 * @param mac mac std::string to convert
 * @return sMacAddr converted mac address
 */
sMacAddr mac_from_string(const std::string &mac);
} // namespace tlvf

inline std::ostream &operator<<(std::ostream &os, const sMacAddr &addr)
{
    return os << tlvf::mac_to_string(addr);
}

inline el::base::MessageBuilder &operator<<(el::base::MessageBuilder &log, const sMacAddr &addr)
{
    return log << tlvf::mac_to_string(addr);
}

inline bool operator==(sMacAddr const &lhs, sMacAddr const &rhs)
{
    return (0 == std::memcmp(lhs.oct, rhs.oct, sizeof(sMacAddr)));
}

inline bool operator!=(sMacAddr const &lhs, sMacAddr const &rhs) { return !(rhs == lhs); }

namespace std {
template <> struct hash<sMacAddr> {
    size_t operator()(const sMacAddr &m) const
    {
        uint64_t value_to_hash = 0;
        for (size_t byte = 0; byte < sizeof(m.oct); byte++) {
            value_to_hash <<= 8;
            value_to_hash += m.oct[byte];
        }
        return hash<std::uint64_t>()(value_to_hash);
    }
};
} // namespace std

#endif
