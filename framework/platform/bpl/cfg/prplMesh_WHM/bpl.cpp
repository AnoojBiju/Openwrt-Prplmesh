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

std::shared_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl = nullptr;

int bpl_init()
{
    m_ambiorix_cl = std::make_shared<beerocks::wbapi::AmbiorixClient>();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client object!";

    LOG_IF(!m_ambiorix_cl->connect(AMBIORIX_WBAPI_BACKEND_PATH, AMBIORIX_WBAPI_BUS_URI), FATAL)
        << "Unable to connect to the ambiorix backend!";

    return RETURN_OK;
}

void bpl_close()
{
    // Do nothing
}

} // namespace bpl
} // namespace beerocks
