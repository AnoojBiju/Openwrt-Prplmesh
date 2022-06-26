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

#ifndef _TLVF_WFA_MAP_TLVTEAMMEMBERS_H_
#define _TLVF_WFA_MAP_TLVTEAMMEMBERS_H_

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

class cTeamDetails;
class cDeveloperDetails;
class cPreviousCompanyDetails;

class tlvTeamMembers : public BaseClass
{
    public:
        tlvTeamMembers(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvTeamMembers(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvTeamMembers();

        const eTlvTypeMap& type();
        const uint16_t& length();
        uint8_t& team_list_length();
        std::tuple<bool, cTeamDetails&> team_details_list(size_t idx);
        std::shared_ptr<cTeamDetails> create_team_details_list();
        bool add_team_details_list(std::shared_ptr<cTeamDetails> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_team_list_length = nullptr;
        cTeamDetails* m_team_details_list = nullptr;
        size_t m_team_details_list_idx__ = 0;
        std::vector<std::shared_ptr<cTeamDetails>> m_team_details_list_vector;
        bool m_lock_allocation__ = false;
        int m_lock_order_counter__ = 0;
};

class cTeamDetails : public BaseClass
{
    public:
        cTeamDetails(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cTeamDetails(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cTeamDetails();

        std::string team_name_str();
        char* team_name(size_t length = 0);
        bool set_team_name(const std::string& str);
        bool set_team_name(const char buffer[], size_t size);
        uint8_t& developer_list_length();
        std::tuple<bool, cDeveloperDetails&> developer_details_list(size_t idx);
        std::shared_ptr<cDeveloperDetails> create_developer_details_list();
        bool add_developer_details_list(std::shared_ptr<cDeveloperDetails> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        char* m_team_name = nullptr;
        size_t m_team_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
        uint8_t* m_developer_list_length = nullptr;
        cDeveloperDetails* m_developer_details_list = nullptr;
        size_t m_developer_details_list_idx__ = 0;
        std::vector<std::shared_ptr<cDeveloperDetails>> m_developer_details_list_vector;
        bool m_lock_allocation__ = false;
};

class cDeveloperDetails : public BaseClass
{
    public:
        cDeveloperDetails(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDeveloperDetails(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDeveloperDetails();

        enum eCountryCode {
            ISRAEL = 0x0,
            INDIA = 0x1,
            EUROPE = 0x2,
            USA = 0x3,
        };
        
        typedef struct sValue {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            eCountryCode working_location : 2;
            uint8_t years_of_experience : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t years_of_experience : 6;
            eCountryCode working_location : 2;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sValue;
        
        uint8_t& developer_name_length();
        std::string developer_name_str();
        char* developer_name(size_t length = 0);
        bool set_developer_name(const std::string& str);
        bool set_developer_name(const char buffer[], size_t size);
        bool alloc_developer_name(size_t count = 1);
        sValue& value();
        uint8_t& age();
        uint8_t& previous_company_name_list_length();
        std::tuple<bool, cPreviousCompanyDetails&> previous_company_details_list(size_t idx);
        std::shared_ptr<cPreviousCompanyDetails> create_previous_company_details_list();
        bool add_previous_company_details_list(std::shared_ptr<cPreviousCompanyDetails> ptr);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_developer_name_length = nullptr;
        char* m_developer_name = nullptr;
        size_t m_developer_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
        sValue* m_value = nullptr;
        uint8_t* m_age = nullptr;
        uint8_t* m_previous_company_name_list_length = nullptr;
        cPreviousCompanyDetails* m_previous_company_details_list = nullptr;
        size_t m_previous_company_details_list_idx__ = 0;
        std::vector<std::shared_ptr<cPreviousCompanyDetails>> m_previous_company_details_list_vector;
        bool m_lock_allocation__ = false;
};

class cPreviousCompanyDetails : public BaseClass
{
    public:
        cPreviousCompanyDetails(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cPreviousCompanyDetails(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cPreviousCompanyDetails();

        uint8_t& company_name_length();
        std::string company_name_str();
        char* company_name(size_t length = 0);
        bool set_company_name(const std::string& str);
        bool set_company_name(const char buffer[], size_t size);
        bool alloc_company_name(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        uint8_t* m_company_name_length = nullptr;
        char* m_company_name = nullptr;
        size_t m_company_name_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVTEAMMEMBERS_H_
