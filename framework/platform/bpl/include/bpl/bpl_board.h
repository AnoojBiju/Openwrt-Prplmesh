/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BPL_BOARD_H_
#define _BPL_BOARD_H_

#include "bpl.h"

#include <string>

namespace beerocks {
namespace bpl {

/****************************************************************************/
/******************************* Definitions ********************************/
/****************************************************************************/

struct sBoardInfo {
    std::string manufacturer;
    std::string manufacturer_model;
};

/****************************************************************************/
/******************************** Functions *********************************/
/****************************************************************************/

/**
 * @brief Get board info parameters.
 *
 * @param [out] board_info structure only with manufacturer and model name parameters.
 * @return Returns true in case of success.
 */
bool get_board_info(sBoardInfo &board_info);

} // namespace bpl
} // namespace beerocks

#endif // _BPL_BOARD_H_
