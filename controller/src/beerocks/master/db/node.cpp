/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "node.h"

#include <easylogging++.h>

using namespace beerocks;
using namespace son;

node::node(beerocks::eType type_, const std::string &mac_)
    : mac(mac_), capabilities(&m_sta_24ghz_capabilities) // deafult value
{
    type                           = type_;
    m_sta_6ghz_capabilities.valid  = false;
    m_sta_5ghz_capabilities.valid  = false;
    m_sta_24ghz_capabilities.valid = false;
}

void node::clear_node_stats_info() { stats_info = std::make_shared<sta_stats_params>(); }

beerocks::eType node::get_type() { return type; }

bool node::set_type(beerocks::eType type_)
{
    //only allow TYPE_CLIENT to TYPE_IRE_BACKHAUL change
    if (type_ == type) {
        return true;
    } else if ((type == beerocks::TYPE_CLIENT) && (type_ == beerocks::TYPE_IRE_BACKHAUL)) {
        type = type_;
        return true;
    } else {
        LOG(ERROR) << "Not expected to happen: node = " << mac << ", old type = " << int(type)
                   << ", new type = " << int(type_);
    }
    return false;
}
