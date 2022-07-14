///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_WFA_MAP_TLVTRIGGERCHANNELSWITCHANNOUNCEMENT_H_
#define _TLVF_WFA_MAP_TLVTRIGGERCHANNELSWITCHANNOUNCEMENT_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/wfa_map/eVirtualBssSubtype.h"
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {


class TriggerChannelSwitchAnnouncement : public BaseClass
{
    public:
        TriggerChannelSwitchAnnouncement(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit TriggerChannelSwitchAnnouncement(std::shared_ptr<BaseClass> base, bool parse = false);
        ~TriggerChannelSwitchAnnouncement();

        const eTlvTypeMap& type();
        const uint16_t& length();
        const eVirtualBssSubtype& subtype();
        uint8_t& csa_channel();
        uint8_t& opclass();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eVirtualBssSubtype* m_subtype = nullptr;
        uint8_t* m_csa_channel = nullptr;
        uint8_t* m_opclass = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTRIGGERCHANNELSWITCHANNOUNCEMENT_H_
