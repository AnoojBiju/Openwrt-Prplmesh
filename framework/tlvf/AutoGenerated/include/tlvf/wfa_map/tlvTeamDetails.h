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

#ifndef _TLVF_WFA_MAP_TLVTEAMDETAILS_H_
#define _TLVF_WFA_MAP_TLVTEAMDETAILS_H_

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
#include <asm/byteorder.h>

namespace wfa_map {

class cTeamInfo;
class cDeveloper;

class tlvTeamDetails : public BaseClass
{
    public:
        tlvTeamDetails(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTeamDetails(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTeamDetails();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& team_list_length();
        std::tuple<bool, cTeamInfo&> team_list(size_t idx);
        std::shared_ptr<cTeamInfo> create_team_list();
        bool add_team_list(std::shared_ptr<cTeamInfo> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_team_list_length = nullptr;
        cTeamInfo* m_team_list = nullptr;
        size_t m_team_list_idx__ = 0;
        std::vector<std::shared_ptr<cTeamInfo>> m_team_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cTeamInfo : public BaseClass
{
    public:
        cTeamInfo(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cTeamInfo(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cTeamInfo();

        std::string team_name_str();
        char* team_name(size_t length = 0);
        bool set_team_name(const std::string& str);
        bool set_team_name(const char buffer[], size_t size);
        std::string scrum_master_str();
        char* scrum_master(size_t length = 0);
        bool set_scrum_master(const std::string& str);
        bool set_scrum_master(const char buffer[], size_t size);
        uint8_t& no_of_developer();
        std::tuple<bool, cDeveloper&> developer_list(size_t idx);
        std::shared_ptr<cDeveloper> create_developer_list();
        bool add_developer_list(std::shared_ptr<cDeveloper> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        char* m_team_name = nullptr;
        size_t m_team_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
        char* m_scrum_master = nullptr;
        size_t m_scrum_master_idx__ = 0;
        uint8_t* m_no_of_developer = nullptr;
        cDeveloper* m_developer_list = nullptr;
        size_t m_developer_list_idx__ = 0;
        std::vector<std::shared_ptr<cDeveloper>> m_developer_list_vector;
        bool m_lock_allocation__ = false;
};

class cDeveloper : public BaseClass
{
    public:
        cDeveloper(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDeveloper(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDeveloper();

        typedef struct sExp_and_loc {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t loc : 2;
            uint8_t exp : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t exp : 6;
            uint8_t loc : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sExp_and_loc;
        
        uint8_t& name_len();
        std::string name_str();
        char* name(size_t length = 0);
        bool set_name(const std::string& str);
        bool set_name(const char buffer[], size_t size);
        bool alloc_name(size_t count = 1);
        uint8_t& num_of_mr();
        sExp_and_loc& exp_and_loc();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_name_len = nullptr;
        char* m_name = nullptr;
        size_t m_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_num_of_mr = nullptr;
        sExp_and_loc* m_exp_and_loc = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTEAMDETAILS_H_
