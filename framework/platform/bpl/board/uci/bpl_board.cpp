/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2021 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl/bpl_board.h>

namespace beerocks {
namespace bpl {

bool get_board_info(sBoardInfo &board_info)
{
    board_info.manufacturer       = "prplFoundation";
    board_info.manufacturer_model = "Ubuntu";
    return true;
}

} // namespace bpl
} // namespace beerocks
