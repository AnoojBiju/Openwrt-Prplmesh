#include "tasks/bml_task.h"
#include <beerocks/tlvf/beerocks_message_1905_vs.h>
#include <beerocks/tlvf/beerocks_message_bml.h>
#include <beerocks/tlvf/beerocks_message_cli.h>
#include <easylogging++.h>
#include <tlvf/wfa_map/tlvTeamsMember.h>

using namespace beerocks;

int build_cmdu()
{
    const int NUM_OF_DEVELOPERS = 2;
    uint8_t tx_buffer[message::MESSAGE_BUFFER_LENGTH];
    ieee1905_1::CmduMessageTx tx_message(tx_buffer, message::MESSAGE_BUFFER_LENGTH);
    auto cmduHeader = tx_message.create(0, ieee1905_1::eMessageType::TEAM_MEMBERS_MESSAGE);

    std::vector<std::string> names             = {"yoni", "adam"};
    std::vector<std::uint8_t> ages             = {28, 30};
    std::vector<std::string> previousCompanies = {"CompanyA", "CompanyB"};

    //create TLV, and fill TLV's developers team with abritrary data;
    auto tlvTeamsMembers = tx_message.addClass<wfa_map::tlvTeamsMember>();
    auto team            = tlvTeamsMembers->create_teams();
    team->name_str()     = "Yoni's Team";
    if (!team) {
        LOG(ERROR) << "Creating team failed";
        return -1;
    }
    for (int i = 0; i < NUM_OF_DEVELOPERS; i++) {
        auto developer = team->create_developers();
        if (!developer) {
            LOG(ERROR) << "Creating team failed";
            return -1;
        }
        developer->name_str()             = names[i];
        developer->age()                  = ages[i];
        developer->misc().workingLocation = 0;
        developer->misc().yearsOfExperice = 10;
        auto previousCompany              = developer->create_previousCompanies();
        if (!previousCompany) {
            LOG(ERROR) << "Creating previous company failed";
            return -1;
        }
        previousCompany->name_str() = previousCompanies[i];
    }
    tx_message.finalize();

    /*
    tx_message is ready. for send use the appropriate API from
    the appropriate module.
    e.g. to send from ap_manager, use ApManager::send_cmdu(...),
    to send from backhaul_manager, use BackhaulManager::send_cmdu(...).
    */

    return 0;
}

int parse_and_print_cmdu(uint8_t *rx_buf, size_t buf_len)
{
    std::unordered_map<uint8_t, std::string> workingLocationMap = {
        {0, "Israel"}, {1, "India"}, {2, "Europe"}, {3, "USA"}};

    ieee1905_1::CmduMessageRx rx_message(rx_buf, buf_len);
    rx_message.parse();
    auto teamsMembers = rx_message.getClass<wfa_map::tlvTeamsMember>();
    size_t numOfTeams = teamsMembers->teams_length();

    //loop on all teams, and for each team, print it's content
    for (size_t i = 0; i < numOfTeams; i++) {
        auto team = std::get<1>(teamsMembers->teams(i));
        std::cout << "Team No. " << i + 1 << ":" << std::endl;
        size_t numOfDevelopers = team.numOfDevelopers();
        for (size_t j = 0; j < numOfDevelopers; j++) {
            auto developer = std::get<1>(team.developers(j));
            std::cout << "\tDeveloper No. " << j + 1 << ":" << std::endl;
            std::cout << "\t\tName:" << developer.name_str() << "\n"
                      << "\t\tAge: " << developer.age() << "\n"
                      << "\t\tWorking Location: "
                      << workingLocationMap[developer.misc().workingLocation] << "\n"
                      << "\t\tYears of Experience: " << developer.misc().yearsOfExperice << "\n"
                      << "\t\tPrevious Companies: " << std::endl;
            size_t numOfPreviousCompanies = developer.previousCompaniesLength();
            for (size_t k = 0; k < numOfPreviousCompanies; k++) {
                auto previousCompany = std::get<1>(developer.previousCompanies(k));
                std::cout << "\t\t\t" << previousCompany.name_str() << std::endl;
            }
        }
    }

    return 0;
}
