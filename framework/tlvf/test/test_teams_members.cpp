#include "test_teams_members.h"

void test_teams_members_parse(uint8_t *rx_buffer, size_t size)
{
    CmduMessageRx received_message(rx_buffer, size);
    received_message.parse();
    auto tlv_rx = received_message.getClass<tlvTeamsMembers>();
    LOG(DEBUG) << "rx:" << tlv_rx << "size:" << size;
    LOG(DEBUG) << "rx:len" << tlv_rx->getLen();

    for (int i = 0; i < tlv_rx->team_id(); i++) {
        auto &team_profile_rx = std::get<1>(tlv_rx->team_profile(i));
        LOG(DEBUG) << "team_name:" << team_profile_rx.team_name();
        LOG(DEBUG) << "num_of_dev:" << team_profile_rx.num_of_dev();
        for (int j = 0; j < team_profile_rx.num_of_dev(); j++) {
            auto &dev_profile_rx = std::get<1>(team_profile_rx.dev_profile(j));
            LOG(DEBUG) << "dev_name:" << dev_profile_rx.dev_name();
            LOG(DEBUG) << "num_of_prev_comp:" << dev_profile_rx.prev_comp_list_len();
            LOG(DEBUG) << "work-exp:" << dev_profile_rx.work_exp().years_of_experience;
            LOG(DEBUG) << "work-location:" << dev_profile_rx.work_exp().work_location;
            LOG(DEBUG) << "age:" << dev_profile_rx.age();
            for (int k = 0; k < dev_profile_rx.prev_comp_list_len(); k++) {
                auto &prev_companies_rx = std::get<1>(dev_profile_rx.previous_companies(k));
                LOG(DEBUG) << "company_name:" << prev_companies_rx.comp_name();
            }
        }
    }
}

uint8_t test_teams_members_build(uint8_t *tx_buffer, size_t len)
{
    CmduMessageTx msg = CmduMessageTx(tx_buffer, len);
    msg.create(0, ieee1905_1::eMessageType::TEAMS_MEMBERS);

    auto tlv          = msg.addClass<tlvTeamsMembers>();
    auto team_profile = tlv->create_team_profile();
    team_profile->set_team_name("PRPLMESH-BLR");

    auto dev_profile = team_profile->create_dev_profile();
    dev_profile->set_dev_name("Hemanth");
    dev_profile->work_exp().work_location       = wfa_map::cDevProfile::eWorkLocation::INDIA;
    dev_profile->work_exp().years_of_experience = 7;

    auto dev_prev_companies = dev_profile->create_previous_companies();
    dev_prev_companies->set_comp_name("TATA ELXSI");
    dev_profile->add_previous_companies(dev_prev_companies);
    dev_prev_companies = dev_profile->create_previous_companies();
    dev_prev_companies->set_comp_name("GESL");
    dev_profile->add_previous_companies(dev_prev_companies);
    dev_profile->age() = 29;
    team_profile->add_dev_profile(dev_profile);
    tlv->add_team_profile(team_profile);

    team_profile = tlv->create_team_profile();
    team_profile->set_team_name("PRPLMESH-ISRAEL");

    dev_profile = team_profile->create_dev_profile();
    dev_profile->set_dev_name("Moran");
    dev_profile->age()                          = 35;
    dev_profile->work_exp().work_location       = wfa_map::cDevProfile::eWorkLocation::ISRAEL;
    dev_profile->work_exp().years_of_experience = 12;

    dev_prev_companies = dev_profile->create_previous_companies();
    dev_prev_companies->set_comp_name("INTEL");
    dev_profile->add_previous_companies(dev_prev_companies);
    dev_prev_companies = dev_profile->create_previous_companies();
    dev_prev_companies->set_comp_name("TATA-ELXSI");
    dev_profile->add_previous_companies(dev_prev_companies);
    team_profile->add_dev_profile(dev_profile);
    tlv->add_team_profile(team_profile);
    msg.finalize();

    return msg.getMessageLength();
}
