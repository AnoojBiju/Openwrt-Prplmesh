#include "tlv_team_members.h"
using namespace std;

uint8_t build_cmdu(uint8_t *buffer, size_t len)
{
    CmduMessageTx msg = CmduMessageTx(buffer, len);
    msg.create(0, ieee1905_1::eMessageType::TEAM_MEMBERS);

    auto tlv = msg.addClass<tlvTeamMembers>();

    //Decalring static values which are going to be
    //passed as inputs to the TLV Team Members
    string PrplMesh = "PrplMesh_Chennai";
    string Driver   = "Driver";
    string Badhri   = "Badhri";
    string Cisco    = "Cisco";
    string ISRO     = "ISRO";
    string Raghav   = "Raghav";
    string Senthil  = "Senthil";
    string Elxsi    = "Tata_Elxsi";

    //Team 1 Details

    auto team = tlv->create_team_details_list();
    team->set_team_name(PrplMesh);

    //Creating Developers List
    auto developer_profile = team->create_developer_details_list();
    developer_profile->set_developer_name(Badhri);
    developer_profile->value().working_location = wfa_map::cDeveloperDetails::eCountryCode::INDIA;
    developer_profile->value().years_of_experience = 1;

    //Creating Developer's Previous Companies List
    auto developer_previous_companies = developer_profile->create_previous_company_details_list();
    developer_previous_companies->set_company_name(Cisco);
    developer_profile->add_previous_company_details_list(developer_previous_companies);
    developer_previous_companies = developer_profile->create_previous_company_details_list();
    developer_previous_companies->set_company_name(ISRO);
    developer_profile->add_previous_company_details_list(developer_previous_companies);

    developer_profile->age() = 22;
    team->add_developer_details_list(developer_profile);

    //Adding one more developer to the same team
    developer_profile = team->create_developer_details_list();
    developer_profile->set_developer_name(Raghav);
    developer_profile->value().working_location = wfa_map::cDeveloperDetails::eCountryCode::INDIA;
    developer_profile->value().years_of_experience = 1;

    //Creating Second Developer's previous company list
    developer_previous_companies = developer_profile->create_previous_company_details_list();
    developer_previous_companies->set_company_name(Elxsi);
    developer_profile->add_previous_company_details_list(developer_previous_companies);

    developer_profile->age() = 21;
    team->add_developer_details_list(developer_profile);

    //Finalising Team 1
    tlv->add_team_details_list(team);

    //Team 2 Details

    team = tlv->create_team_details_list();
    team->set_team_name(Driver);

    developer_profile = team->create_developer_details_list();
    developer_profile->set_developer_name(Senthil);
    developer_profile->value().working_location = wfa_map::cDeveloperDetails::eCountryCode::ISRAEL;
    developer_profile->value().years_of_experience = 17;

    developer_previous_companies = developer_profile->create_previous_company_details_list();
    developer_previous_companies->set_company_name(Cisco);
    developer_profile->add_previous_company_details_list(developer_previous_companies);
    developer_previous_companies = developer_profile->create_previous_company_details_list();
    developer_previous_companies->set_company_name(Elxsi);
    developer_profile->add_previous_company_details_list(developer_previous_companies);

    developer_profile->age() = 38;
    team->add_developer_details_list(developer_profile);
    tlv->add_team_details_list(team);

    msg.finalize();

    return msg.getMessageLength();
}

void parse_and_print_cmdu(uint8_t *buffer, size_t len)
{
    CmduMessageRx parsed_msg(buffer, len);
    parsed_msg.parse();
    auto tlv_rx = parsed_msg.getClass<tlvTeamMembers>();
    LOG(DEBUG) << "Received TLV Length: " << tlv_rx->getLen();

    for (int i = 0; i < tlv_rx->team_list_length(); i++) {
        auto &team_rx = std::get<1>(tlv_rx->team_details_list(i));
        LOG(DEBUG) << "Team ID: " << i + 1;
        LOG(DEBUG) << "Team Name: " << team_rx.team_name_str();
        LOG(DEBUG) << "Number of Developers: " << team_rx.developer_list_length();

        for (int j = 0; j < team_rx.developer_list_length(); j++) {
            auto &developer_profile_rx = std::get<1>(team_rx.developer_details_list(j));
            LOG(DEBUG) << "Developer Name: " << developer_profile_rx.developer_name_str();
            LOG(DEBUG) << "Age: " << developer_profile_rx.age();
            LOG(DEBUG) << "Number of Previous Companies: "
                       << developer_profile_rx.previous_company_name_list_length();

            for (int k = 0; k < developer_profile_rx.previous_company_name_list_length(); k++) {
                auto &previous_companies_rx =
                    std::get<1>(developer_profile_rx.previous_company_details_list(k));
                LOG(DEBUG) << "Company Name: " << previous_companies_rx.company_name_str();
            }
            if (developer_profile_rx.value().years_of_experience > 1) {
                LOG(DEBUG) << "Work Experience: "
                           << developer_profile_rx.value().years_of_experience << " years";
            } else {
                LOG(DEBUG) << "Work Experience: "
                           << developer_profile_rx.value().years_of_experience << " year";
            }
            if (developer_profile_rx.value().working_location == 0) {
                LOG(DEBUG) << "Working Location: ISRAEL";
            } else if (developer_profile_rx.value().working_location == 1) {
                LOG(DEBUG) << "Working Location: INDIA";
            } else if (developer_profile_rx.value().working_location == 2) {
                LOG(DEBUG) << "Working Location: EUROPE";
            } else if (developer_profile_rx.value().working_location == 3) {
                LOG(DEBUG) << "Working Location: USA";
            } else {
                LOG(DEBUG) << "Invalid Working Location";
            }
        }
    }
}
