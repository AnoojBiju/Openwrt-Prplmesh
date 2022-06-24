/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BPL_CFG_PRIVATE_H_
#define _BPL_CFG_PRIVATE_H_

#include <stdint.h>
#include <string>

#include "ambiorix_client.h"
#include "wbapi_utils.h"

#define RETURN_OK 0
#define RETURN_ERR -1

namespace beerocks {
namespace bpl {

extern std::shared_ptr<beerocks::wbapi::AmbiorixClient> m_ambiorix_cl;

} // namespace bpl
} // namespace beerocks

#endif /* _BPL_CFG_PRIVATE_H_ */
