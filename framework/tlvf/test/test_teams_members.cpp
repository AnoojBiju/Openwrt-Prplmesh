#include "test_teams_members.h"
#include "tlvf/CmduMessageRx.h"
#include "tlvf/CmduMessageTx.h"
#include "tlvf/tlvftypes.h"

#include "tlvf/CmduMessageRx.h"
#include "tlvf/CmduMessageTx.h"
#include "tlvf/tlvftypes.h"
#include <cstring>
#include <iostream>
#include <sstream>

#include "test_teams_members.h"
#include "tlvf/WSC/configData.h"
#include "tlvf/WSC/m1.h"
#include "tlvf/WSC/m2.h"
#include "tlvf/ieee_1905_1/tlv1905NeighborDevice.h"
#include "tlvf/ieee_1905_1/tlvLinkMetricQuery.h"
#include "tlvf/ieee_1905_1/tlvMacAddress.h"
#include "tlvf/ieee_1905_1/tlvNon1905neighborDeviceList.h"
#include "tlvf/ieee_1905_1/tlvUnknown.h"
#include "tlvf/ieee_1905_1/tlvVendorSpecific.h"
#include "tlvf/ieee_1905_1/tlvWsc.h"
#include "tlvf/wfa_map/tlvApCapability.h"
#include "tlvf/wfa_map/tlvProfile2ChannelScanResult.h"
#include "tlvf/wfa_map/tlvTeamsMembers.h"
#include <mapf/common/encryption.h>
#include <mapf/common/err.h>
#include <mapf/common/logger.h>
#include <mapf/common/utils.h>
#include <tlvf/test/tlvVarList.h>
#include <tlvf/tlvftypes.h>
#include <tlvf/wfa_map/tlvApCapability.h>

#include <algorithm>
#include <iterator>
#include <stdio.h>

using namespace ieee1905_1;
using namespace wfa_map;

using namespace mapf;

void test_teams_members_parse(uint8_t *rx_buffer, size_t size)
{
    CmduMessageRx received_message(rx_buffer, size);
    received_message.parse();
    auto tlv_rx = received_message.getClass<tlvTeamsMembers>();
    LOG(DEBUG) << "rx:" << tlv_rx << "size:" << size;
    LOG(DEBUG) << "rx:len" << tlv_rx->getLen();
    auto team_id_rx = tlv_rx->team_id();
    //LOG(DEBUG) << "num_team_id:" << team_id_rx->num_team_id();

    //for (int i = 0; i < team_id_rx->num_team_id(); i++) {
    for (int i = 0; i < team_id_rx; i++) {
        auto &team_details_rx = std::get<1>(tlv_rx->team_details(i));
        LOG(DEBUG) << "team_name:" << team_details_rx.team_name();
        LOG(DEBUG) << "num_dev:" << team_details_rx.num_dev();
        for (int j = 0; j < team_details_rx.num_dev(); j++) {
            auto &dev_details_rx = std::get<1>(team_details_rx.dev_details(j));
            LOG(DEBUG) << "dev_name:" << dev_details_rx.dev_name();
            LOG(DEBUG) << "num_prev_comp:" << dev_details_rx.prev_comp_list_len();
            LOG(DEBUG) << "work-exp:" << dev_details_rx.work_exp().years_of_experience;
            LOG(DEBUG) << "work-location:" << dev_details_rx.work_exp().work_location;
            LOG(DEBUG) << "age:" << dev_details_rx.age();
            for (int k = 0; k < dev_details_rx.prev_comp_list_len(); k++) {
                auto &prev_companies_rx = std::get<1>(dev_details_rx.previous_companies(k));
                LOG(DEBUG) << "company_name:" << prev_companies_rx.comp_name();
            }
        }
    }
}

uint8_t test_teams_members_build(uint8_t *tx_buffer, size_t len)
{
    CmduMessageTx msg = CmduMessageTx(tx_buffer, len);
    msg.create(0, ieee1905_1::eMessageType::TEAMS_MEMBERS);
    //tlv
    auto tlv = msg.addClass<tlvTeamsMembers>();

    //create team id
    //auto team_id      = tlv->create_team_id();
    //auto team_details = team_id->create_team_details();
    auto team_details = tlv->create_team_details();
    team_details->set_team_name("PRPLMESH-BLR");
    //create dev
    auto dev_details = team_details->create_dev_details();
    dev_details->set_dev_name("Anant");
    dev_details->work_exp().work_location       = wfa_map::cDevDetails::eWorkLocation::INDIA;
    dev_details->work_exp().years_of_experience = 9;
    //create prev_comp_list
    auto dev_prev_companies = dev_details->create_previous_companies();
    dev_prev_companies->set_comp_name("INTEL");
    dev_details->add_previous_companies(dev_prev_companies);
    dev_prev_companies = dev_details->create_previous_companies();
    dev_prev_companies->set_comp_name("GESL");
    dev_details->add_previous_companies(dev_prev_companies);
    dev_details->age() = 33;
    team_details->add_dev_details(dev_details);
    tlv->add_team_details(team_details);

    //create team-id-1
    //team_details = team_id->create_team_details();
    team_details = tlv->create_team_details();
    team_details->set_team_name("PRPLMESH-ISL");
    //create dev1
    dev_details = team_details->create_dev_details();
    dev_details->set_dev_name("Moran");
    dev_details->age()                          = 33;
    dev_details->work_exp().work_location       = wfa_map::cDevDetails::eWorkLocation::ISRAEL;
    dev_details->work_exp().years_of_experience = 9;
    //create prev_comp_list1
    dev_prev_companies = dev_details->create_previous_companies();
    dev_prev_companies->set_comp_name("INTEL");
    dev_details->add_previous_companies(dev_prev_companies);
    dev_prev_companies = dev_details->create_previous_companies();
    dev_prev_companies->set_comp_name("INFI");
    dev_details->add_previous_companies(dev_prev_companies);
    team_details->add_dev_details(dev_details);
    //team_id->add_team_details(team_details);
    tlv->add_team_details(team_details);
    //tlv->add_team_id(team_id);
    msg.finalize();

    return msg.getMessageLength();
}
