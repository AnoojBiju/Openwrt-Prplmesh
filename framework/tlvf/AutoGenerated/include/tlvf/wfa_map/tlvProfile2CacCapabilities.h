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

#ifndef _TLVF_WFA_MAP_TLVPROFILE2CACCAPABILITIES_H_
#define _TLVF_WFA_MAP_TLVPROFILE2CACCAPABILITIES_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <tuple>
#include <vector>
#include "tlvf/common/sMacAddr.h"

namespace wfa_map {

class cCacRadios;
class cCacTypes;
class cCacCapabilitiesOperatingClasses;
class cChannel;

class tlvProfile2CacCapabilities : public BaseClass
{
    public:
        tlvProfile2CacCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvProfile2CacCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvProfile2CacCapabilities();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint16_t& country_code();
        uint8_t& number_of_cac_radios();
        std::tuple<bool, cCacRadios&> cac_radios(size_t idx);
        std::shared_ptr<cCacRadios> create_cac_radios();
        bool add_cac_radios(std::shared_ptr<cCacRadios> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint16_t* m_country_code = nullptr;
        uint8_t* m_number_of_cac_radios = nullptr;
        cCacRadios* m_cac_radios = nullptr;
        size_t m_cac_radios_idx__ = 0;
        std::vector<std::shared_ptr<cCacRadios>> m_cac_radios_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cCacRadios : public BaseClass
{
    public:
        cCacRadios(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cCacRadios(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cCacRadios();

        sMacAddr& radio_uid();
        uint8_t& number_of_cac_type_supported();
        std::tuple<bool, cCacTypes&> cac_types(size_t idx);
        std::shared_ptr<cCacTypes> create_cac_types();
        bool add_cac_types(std::shared_ptr<cCacTypes> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        sMacAddr* m_radio_uid = nullptr;
        uint8_t* m_number_of_cac_type_supported = nullptr;
        cCacTypes* m_cac_types = nullptr;
        size_t m_cac_types_idx__ = 0;
        std::vector<std::shared_ptr<cCacTypes>> m_cac_types_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cCacTypes : public BaseClass
{
    public:
        cCacTypes(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cCacTypes(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cCacTypes();

        enum eCacMethod: uint8_t {
            CAC_METHOD_CONTINUES_CAC = 0x0,
            CAC_METHOD_CONTINUES_CAC_WITH_DEDICATED_RADIO = 0x1,
            CAC_METHOD_MIMO_SLICED_REDUCED = 0x2,
            CAC_METHOD_TIME_SLICED_CAC = 0x3,
        };
        
        eCacMethod& cac_method();
        uint16_t* duration(size_t idx = 0);
        uint8_t& number_of_operating_classes();
        std::tuple<bool, cCacCapabilitiesOperatingClasses&> operating_classes(size_t idx);
        std::shared_ptr<cCacCapabilitiesOperatingClasses> create_operating_classes();
        bool add_operating_classes(std::shared_ptr<cCacCapabilitiesOperatingClasses> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eCacMethod* m_cac_method = nullptr;
        uint16_t* m_duration = nullptr;
        size_t m_duration_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_number_of_operating_classes = nullptr;
        cCacCapabilitiesOperatingClasses* m_operating_classes = nullptr;
        size_t m_operating_classes_idx__ = 0;
        std::vector<std::shared_ptr<cCacCapabilitiesOperatingClasses>> m_operating_classes_vector;
        bool m_lock_allocation__ = false;
};

class cCacCapabilitiesOperatingClasses : public BaseClass
{
    public:
        cCacCapabilitiesOperatingClasses(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cCacCapabilitiesOperatingClasses(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cCacCapabilitiesOperatingClasses();

        uint8_t& operating_class();
        uint8_t& number_of_channels();
        std::tuple<bool, cChannel&> channels(size_t idx);
        std::shared_ptr<cChannel> create_channels();
        bool add_channels(std::shared_ptr<cChannel> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_operating_class = nullptr;
        uint8_t* m_number_of_channels = nullptr;
        cChannel* m_channels = nullptr;
        size_t m_channels_idx__ = 0;
        std::vector<std::shared_ptr<cChannel>> m_channels_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cChannel : public BaseClass
{
    public:
        cChannel(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cChannel(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cChannel();

        uint8_t& channel();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_channel = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVPROFILE2CACCAPABILITIES_H_
