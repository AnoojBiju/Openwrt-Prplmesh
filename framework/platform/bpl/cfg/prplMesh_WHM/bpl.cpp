/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bpl/bpl.h>

#include <mapf/common/logger.h>

#include "bpl_cfg_pwhm.h"

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace beerocks {
namespace bpl {

beerocks::wbapi::AmbiorixClient m_ambiorix_cl;

int bpl_init()
{

    LOG_IF(!m_ambiorix_cl.connect(), FATAL) << "Unable to connect to the ambiorix backend!";

    return RETURN_OK;
}

void bpl_close()
{
    // Do nothing
}

} // namespace bpl
} // namespace beerocks
