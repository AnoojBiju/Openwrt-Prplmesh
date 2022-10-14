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

#include "ambiorix_client_factory.h"

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace beerocks {
namespace bpl {

std::unique_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl = nullptr;

int bpl_init()
{
    m_ambiorix_cl = beerocks::wbapi::AmbiorixClientFactory::create_instance();
    LOG_IF(!m_ambiorix_cl, FATAL) << "Unable to create ambiorix client object!";

    return RETURN_OK;
}

void bpl_close()
{
    // Do nothing
}

} // namespace bpl
} // namespace beerocks
