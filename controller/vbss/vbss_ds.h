//
//Copyright (c) 2022 CableLabs for prplMesh All rights reserved.
//

#ifndef PRPLMESH_VBSS_DS_H
#define PRPLMESH_VBSS_DS_H
#include <array>
#include <linux/if_ether.h>
#include <stdint.h>
namespace vbss {
using ruid = uint8_t[6];
using vbss_id = std::array<uint8_t, ETH_ALEN>;
} //namespace vbss

#endif //PRPLMESH_VBSS_DS_H
