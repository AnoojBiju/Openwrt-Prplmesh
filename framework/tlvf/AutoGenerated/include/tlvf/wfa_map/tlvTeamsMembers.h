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

#ifndef _TLVF_WFA_MAP_TLVTEAMSMEMBERS_H_
#define _TLVF_WFA_MAP_TLVTEAMSMEMBERS_H_

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
#include <ostream>
#include <asm/byteorder.h>

namespace wfa_map {

class cTeamProfile;
class cDevProfile;
class cCompanyName;

class tlvTeamsMembers : public BaseClass
{
    public:
        tlvTeamsMembers(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTeamsMembers(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTeamsMembers();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& team_id();
        std::tuple<bool, cTeamProfile&> team_profile(size_t idx);
        std::shared_ptr<cTeamProfile> create_team_profile();
        bool add_team_profile(std::shared_ptr<cTeamProfile> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_team_id = nullptr;
        cTeamProfile* m_team_profile = nullptr;
        size_t m_team_profile_idx__ = 0;
        std::vector<std::shared_ptr<cTeamProfile>> m_team_profile_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cTeamProfile : public BaseClass
{
    public:
        cTeamProfile(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cTeamProfile(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cTeamProfile();

        std::string team_name_str();
        char* team_name(size_t length = 0);
        bool set_team_name(const std::string& str);
        bool set_team_name(const char buffer[], size_t size);
        uint8_t& num_of_dev();
        std::tuple<bool, cDevProfile&> dev_profile(size_t idx);
        std::shared_ptr<cDevProfile> create_dev_profile();
        bool add_dev_profile(std::shared_ptr<cDevProfile> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        char* m_team_name = nullptr;
        size_t m_team_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_of_dev = nullptr;
        cDevProfile* m_dev_profile = nullptr;
        size_t m_dev_profile_idx__ = 0;
        std::vector<std::shared_ptr<cDevProfile>> m_dev_profile_vector;
        bool m_lock_allocation__ = false;
};

class cDevProfile : public BaseClass
{
    public:
        cDevProfile(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDevProfile(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDevProfile();

        enum eWorkLocation {
            ISRAEL = 0x0,
            INDIA = 0x1,
            EUROPE = 0x2,
            USA = 0x3,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eWorkLocation_str(eWorkLocation enum_value) {
            switch (enum_value) {
            case ISRAEL: return "ISRAEL";
            case INDIA:  return "INDIA";
            case EUROPE: return "EUROPE";
            case USA:    return "USA";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eWorkLocation value) { return out << eWorkLocation_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        typedef struct sDevProfile {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            eWorkLocation work_location : 2;
            uint8_t years_of_experience : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t years_of_experience : 6;
            eWorkLocation work_location : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sDevProfile;
        
        uint8_t& dev_name_len();
        std::string dev_name_str();
        char* dev_name(size_t length = 0);
        bool set_dev_name(const std::string& str);
        bool set_dev_name(const char buffer[], size_t size);
        bool alloc_dev_name(size_t count = 1);
        sDevProfile& work_exp();
        uint8_t& age();
        uint8_t& prev_comp_list_len();
        std::tuple<bool, cCompanyName&> previous_companies(size_t idx);
        std::shared_ptr<cCompanyName> create_previous_companies();
        bool add_previous_companies(std::shared_ptr<cCompanyName> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_dev_name_len = nullptr;
        char* m_dev_name = nullptr;
        size_t m_dev_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sDevProfile* m_work_exp = nullptr;
        uint8_t* m_age = nullptr;
        uint8_t* m_prev_comp_list_len = nullptr;
        cCompanyName* m_previous_companies = nullptr;
        size_t m_previous_companies_idx__ = 0;
        std::vector<std::shared_ptr<cCompanyName>> m_previous_companies_vector;
        bool m_lock_allocation__ = false;
};

class cCompanyName : public BaseClass
{
    public:
        cCompanyName(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cCompanyName(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cCompanyName();

        uint8_t& comp_name_len();
        std::string comp_name_str();
        char* comp_name(size_t length = 0);
        bool set_comp_name(const std::string& str);
        bool set_comp_name(const char buffer[], size_t size);
        bool alloc_comp_name(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_comp_name_len = nullptr;
        char* m_comp_name = nullptr;
        size_t m_comp_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTEAMSMEMBERS_H_
