/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BPL_CFG_PRIVATE_H_
#define _BPL_CFG_PRIVATE_H_

#include <bcl/son/son_wireless_utils.h>

#include <stdint.h>
#include <string>

#define RETURN_OK 0
#define RETURN_ERR -1

namespace beerocks {
namespace bpl {

/*
 * @brief Returns the value of a configuration parameter given its name.
 *
 * @param[in] name Name of the configuration parameter.
 * @param[out] value Value of the configuration parameter.
 * @return true on success and false otherwise.
 */
bool cfg_get_param(const std::string &name, std::string &value);

/**
 * @brief Gets all parameters in configuration file for which name the given predicate evaluates to
 * true.
 *
 * @param[out] parameters Parameters read from configuration file.
 * @param[in] filter Unary predicate to filter parameter names. Set to nullptr for no filter.
 * @return true on success and false otherwise.
 */
bool cfg_get_params(std::unordered_map<std::string, std::string> &parameters,
                    std::function<bool(const std::string &name)> filter = nullptr);

/**
 * @brief Saves given parameters into configuration file.
 *
 * @param[in] parameters Parameters to write to configuration file.
 * @return true on success and false otherwise.
 */
bool cfg_set_params(const std::unordered_map<std::string, std::string> &parameters);

} // namespace bpl
} // namespace beerocks

#endif /* _BPL_CFG_PRIVATE_H_ */
