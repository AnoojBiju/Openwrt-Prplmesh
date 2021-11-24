/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "test_teams_members.h"
#include "tlvf/CmduMessageRx.h"
#include "tlvf/CmduMessageTx.h"
#include "tlvf/tlvftypes.h"

#include <cstring>
#include <iostream>
#include <sstream>

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
#include <tlvf/test/tlvVarList.h>
#include <tlvf/tlvftypes.h>

#include <mapf/common/encryption.h>
#include <mapf/common/err.h>
#include <mapf/common/logger.h>
#include <mapf/common/utils.h>
#include <tlvf/wfa_map/tlvApCapability.h>

#include <algorithm>
#include <iterator>
#include <stdio.h>

using namespace ieee1905_1;
using namespace wfa_map;

using namespace mapf;

int test_int_len_list()
{
    int errors = 0;
    uint8_t tx_buffer[1024];
    const uint8_t gTlvMacAddress[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    MAPF_INFO(__FUNCTION__ << " start");
    memset(tx_buffer, 0, sizeof(tx_buffer));
    {
        auto tlv = tlvMacAddress(tx_buffer, sizeof(tx_buffer), false);
        tlvf::mac_from_array(gTlvMacAddress, tlv.mac());
        tlv.class_swap(); //finalize
        LOG(DEBUG) << "TX: " << std::endl << utils::dump_buffer(tx_buffer, tlv.getLen());
    }

    uint8_t rx_buffer[sizeof(tx_buffer)];
    memcpy(rx_buffer, tx_buffer, sizeof(rx_buffer));
    {
        auto tlv = tlvMacAddress(tx_buffer, sizeof(tx_buffer), true);
        auto mac = tlv.mac();
        if (!std::equal(mac.oct, mac.oct + 6, gTlvMacAddress)) {
            MAPF_ERR("MAC address in received TLV does not match expected result");
            errors++;
        }
        LOG(DEBUG) << "RX: " << std::endl << utils::dump_buffer(rx_buffer, tlv.getLen());
    }

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

int test_complex_list()
{
    int errors                     = 0;
    const int complex_list_entries = 3;
    uint8_t tx_buffer[4096];

    MAPF_INFO(__FUNCTION__ << " start");

    //START BUILDING THE MESSAGE HERE
    memset(tx_buffer, 0, sizeof(tx_buffer));

    //creating cmdu message class and setting the header
    CmduMessageTx msg = CmduMessageTx(tx_buffer, sizeof(tx_buffer));
    //create method initializes the buffer and returns shared pointer to the message header
    auto header = msg.create(0, eMessageType::BACKHAUL_STEERING_REQUEST_MESSAGE);
    header->flags().last_fragment_indicator = 1;
    header->flags().relay_indicator         = 1;

    auto fourthTlv    = msg.addClass<tlvTestVarList>();
    fourthTlv->var0() = 0xa0;
    if (!fourthTlv->alloc_simple_list(2)) {
        MAPF_ERR("Failed to allocate simple list");
        errors++;
    }
    *(fourthTlv->simple_list(0)) = 0x0bb0;
    *(fourthTlv->simple_list(1)) = 0x0bb1;

    if (true == fourthTlv->set_test_string("1234567890")) {
        LOG(ERROR) << "FAIL test maximum size string";
        errors++;
    }
    // test allocation of correct length (less then max)
    if (false == fourthTlv->set_test_string("1234567")) {
        LOG(ERROR) << "FAIL test normal size string";
        errors++;
    }

    // test additional set of correct length (less then max)
    if (true == fourthTlv->set_test_string("1234567")) {
        LOG(ERROR) << "FAIL test normal size string set twice";
        errors++;
    }

    for (int i = 0; i < complex_list_entries; i++) {
        auto cmplx    = fourthTlv->create_complex_list();
        cmplx->var1() = 0xbbbbaaaa;
        cmplx->alloc_list(3);
        *(cmplx->list(0)) = 0xc0;
        *(cmplx->list(1)) = 0xc1;
        *(cmplx->list(2)) = 0xc2;
        if (!fourthTlv->add_complex_list(cmplx)) {
            LOG(ERROR) << "Failed to add complex list";
            errors++;
        }
        //test multiple add (should Fail!)
        if (fourthTlv->add_complex_list(cmplx)) {
            LOG(ERROR) << "Could add complex list a second time";
            errors++;
        }
    }

    fourthTlv->var2() = 0xabababab;
    auto cmplx        = fourthTlv->create_var1();
    cmplx->var1()     = 0xb11b;
    cmplx->set_unknown_length_list_inner("prplMesh");
    if (!fourthTlv->add_var1(cmplx)) {
        LOG(ERROR) << "Failed to add var1";
        errors++;
    }
    // Test multiple add - should fail
    if (fourthTlv->add_var1(cmplx)) {
        LOG(ERROR) << "Could add var1 a second time";
        errors++;
    }

    cmplx         = fourthTlv->create_var3();
    cmplx->var1() = 0xb11b;
    if (!fourthTlv->add_var3(cmplx)) {
        LOG(ERROR) << "Failed to add var3";
        errors++;
    }

    LOG(DEBUG) << "TLV 4 length " << fourthTlv->length();

    LOG(DEBUG) << "Finalize";
    //MANDATORY - swaps to little indian.
    if (!msg.finalize()) {
        LOG(ERROR) << "Finalize step failed";
        errors++;
    }

    LOG(DEBUG) << "TX: " << std::endl << utils::dump_buffer(tx_buffer, msg.getMessageLength());

    uint8_t recv_buffer[sizeof(tx_buffer)];
    memcpy(recv_buffer, tx_buffer, sizeof(recv_buffer));

    CmduMessageRx received_message(recv_buffer, sizeof(recv_buffer));
    received_message.parse();

    auto tlv4 = received_message.getClass<tlvUnknown>()->class_cast<tlvTestVarList>();
    if (tlv4 == nullptr) {
        MAPF_ERR("TLV4 is NULL");
        return ++errors;
    }
    if (tlv4->test_string_str().compare("1234567")) {
        MAPF_ERR("FAIL, expected  \"1234567\", received " << tlv4->test_string_str());
        errors++;
    }
    if (tlv4->complex_list_length() != complex_list_entries) {
        MAPF_ERR("Invalid complex list num of entries" << tlv4->complex_list_length());
        return ++errors;
    }
    for (int i = 0; i < complex_list_entries; i++) {
        auto cmplx = std::get<1>(tlv4->complex_list(i));
        if (cmplx.var1() != 0xbbbbaaaa) {
            MAPF_ERR("wrong value for cmplx->var1 " << std::hex << cmplx.var1());
            errors++;
        }
    }

    if (tlv4->var1()->var1() != 0xb11b) {
        MAPF_ERR("Unexpected var1 value " << tlv4->var1()->var1());
        errors++;
    }

    if (tlv4->var2() != 0xabababab) {
        MAPF_ERR("Unexpected var2 value " << tlv4->var2());
        errors++;
    }

    auto str = std::string(tlv4->var1()->unknown_length_list_inner(),
                           tlv4->var1()->unknown_length_list_inner_length());
    if (str.compare("prplMesh")) {
        MAPF_ERR("unknown length list failure - expected \"prplMesh\", received " << str);
        errors++;
    }

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

bool add_encrypted_settings(tlvWsc &tlv, uint8_t *keywrapkey, WSC::m2::config &m2_cfg)
{
    // Encrypted settings
    // Encrypted settings are the ConfigData + IV. First create the ConfigData,
    // Then copy it to the encrypted data, add an IV and encrypt.
    // Finally, add HMAC
    uint8_t buf[1024];
    WSC::configData::config cfg;
    cfg.ssid         = "test_ssid";
    cfg.auth_type    = WSC::eWscAuth::WSC_AUTH_WPA2;
    cfg.encr_type    = WSC::eWscEncr::WSC_ENCR_AES;
    cfg.network_key  = "test1234";
    auto config_data = WSC::configData::create(cfg, buf, sizeof(buf));
    if (!config_data) {
        LOG(ERROR) << "Failed to create configData";
        return false;
    }

    LOG(DEBUG) << "WSC config_data:" << std::endl
               << "     ssid: " << config_data->ssid() << std::endl
               << "     authentication_type: " << int(config_data->auth_type()) << std::endl
               << "     network_key: " << config_data->network_key() << std::endl
               << "     encryption_type: " << int(config_data->encr_type()) << std::endl;
    config_data->finalize();

    int datalen                  = config_data->getMessageLength();
    int cipherlen                = datalen + 16;
    uint8_t encrypted[cipherlen] = {0};
    std::copy_n(config_data->getMessageBuff(), datalen, encrypted);
    if (!mapf::encryption::aes_encrypt(keywrapkey, m2_cfg.iv, encrypted, datalen, encrypted,
                                       cipherlen)) {
        LOG(ERROR) << "aes encrypt";
        return false;
    }
    m2_cfg.encrypted_settings = std::vector<uint8_t>(encrypted, encrypted + cipherlen);
    // Allocate maximum allowed length for the payload, so it can accommodate variable length
    // data inside the internal TLV list.
    // On finalize(), the buffer is shrunk back to its real size.
    size_t payload_length = tlv.getBuffRemainingBytes();
    tlv.alloc_payload(payload_length);
    auto m2 = WSC::m2::create(tlv, m2_cfg);
    if (!m2) {
        LOG(ERROR) << "create m2";
        return false;
    }
    // Finalize m2 since it needs to be in network byte order for global authentication
    m2->finalize();
    std::fill(m2->authenticator(), m2->authenticator() + WSC::eWscLengths::WSC_AUTHENTICATOR_LENGTH,
              0xbb);

    LOG(DEBUG) << "encrypted settings length: "
               << m2->encrypted_settings().encrypted_settings_length();
    LOG(DEBUG) << "encrypted settings buffer: " << std::endl
               << utils::dump_buffer((uint8_t *)m2->encrypted_settings().encrypted_settings(),
                                     m2->encrypted_settings().encrypted_settings_length());

    LOG(DEBUG) << "authenticator buffer: " << std::endl
               << utils::dump_buffer((uint8_t *)m2->authenticator(),
                                     WSC::eWscLengths::WSC_AUTHENTICATOR_LENGTH);

    return true;
}

bool parse_encrypted_settings(std::shared_ptr<tlvWsc> tlv, uint8_t *keywrapkey, uint8_t *iv)
{
    if (!tlv) {
        LOG(ERROR) << "tlv is nullptr!";
        return false;
    }
    auto m2 = WSC::m2::parse(*tlv);
    if (!m2) {
        LOG(ERROR) << "Not an M2!";
        return false;
    }
    auto encrypted_settings = m2->encrypted_settings();
    LOG(DEBUG) << "type: " << encrypted_settings.type();
    LOG(DEBUG) << "encrypted settings length: " << encrypted_settings.getLen();
    LOG(DEBUG) << "encrypted settings buffer: " << std::endl
               << utils::dump_buffer((uint8_t *)encrypted_settings.encrypted_settings(),
                                     encrypted_settings.encrypted_settings_length());
    int dlen = encrypted_settings.encrypted_settings_length() + 16;
    uint8_t buf[dlen];
    mapf::encryption::aes_decrypt(keywrapkey, iv,
                                  (uint8_t *)encrypted_settings.encrypted_settings(),
                                  encrypted_settings.encrypted_settings_length(), buf, dlen);
    LOG(DEBUG) << "configData buffer: " << std::hex << ptrdiff_t(buf) << std::endl
               << utils::dump_buffer(buf, dlen);
    auto config_data = WSC::configData::parse(buf, dlen);
    if (!config_data) {
        LOG(ERROR) << "Failed to parse config data";
        return false;
    }

    LOG(DEBUG) << "WSC config_data:" << std::endl
               << "     ssid: " << config_data->ssid() << std::endl
               << "     authentication_type: " << int(config_data->auth_type()) << std::endl
               << "     encryption_type: " << int(config_data->encr_type()) << std::endl
               << "     network_key: " << config_data->network_key() << std::endl;
    LOG(DEBUG) << "authenticator buffer: " << std::endl
               << utils::dump_buffer((uint8_t *)m2->authenticator(),
                                     WSC::eWscLengths::WSC_AUTHENTICATOR_LENGTH);
    return true;
}

int test_parser()
{
    int errors = 0;
    uint8_t tx_buffer[4096];
    //creating cmdu message class and setting the header
    CmduMessageTx msg = CmduMessageTx(tx_buffer, sizeof(tx_buffer));

    //create method initializes the buffer and returns shared pointer to the message header
    auto header = msg.create(0, eMessageType::BACKHAUL_STEERING_REQUEST_MESSAGE);
    header->flags().last_fragment_indicator = 1;
    header->flags().relay_indicator         = 1;

    auto tlv1 = msg.addClass<tlvNon1905neighborDeviceList>();
    auto tlv2 = msg.addClass<tlvLinkMetricQuery>();
    auto tlv3 = msg.addClass<tlvWsc>();
    auto tlv4 = msg.addClass<tlvTestVarList>();
    tlv4->add_var1(tlv4->create_var1());

    LOG(DEBUG) << "Finalize";
    if (msg.finalize()) {
        LOG(ERROR)
            << "Finalize should fail since the last tlv of the CMDU is not fully initialized";
        errors++;
    }

    tlv4->add_var3(tlv4->create_var3());
    LOG(DEBUG) << "Finalize";
    if (!msg.finalize()) {
        LOG(ERROR) << "Finalize step failed";
        errors++;
    }

    LOG(DEBUG) << "TX: " << std::endl << utils::dump_buffer(tx_buffer, msg.getMessageLength());

    uint8_t recv_buffer[sizeof(tx_buffer)];
    memcpy(recv_buffer, tx_buffer, sizeof(recv_buffer));

    CmduMessageRx received_message(recv_buffer, sizeof(recv_buffer));
    received_message.parse();
    auto tlv4_ = received_message.getClass<tlvUnknown>();
    if (!tlv4_) {
        LOG(ERROR) << "getClass<tlvUnknown> failed";
        errors++;
    }
    auto tlv3_ = received_message.getClass<tlvWsc>();
    if (!tlv3_) {
        LOG(ERROR) << "getClass<tlvWsc> failed";
        errors++;
    }
    auto tlv2_ = received_message.getClass<tlvLinkMetricQuery>();
    if (!tlv2_) {
        LOG(ERROR) << "getClass<tlvLinkMetricQuery> failed";
        errors++;
    }
    auto tlv1_ = received_message.getClass<tlvNon1905neighborDeviceList>();
    if (!tlv1_) {
        LOG(ERROR) << "getClass<tlvNon1905neighborDeviceList> failed";
        errors++;
    }

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

int test_all()
{
    int errors = 0;
    uint8_t tx_buffer[4096];

    MAPF_INFO(__FUNCTION__ << " start");
    //START BUILDING THE MESSAGE HERE
    memset(tx_buffer, 0, sizeof(tx_buffer));

    //creating cmdu message class and setting the header
    CmduMessageTx msg = CmduMessageTx(tx_buffer, sizeof(tx_buffer));

    //create method initializes the buffer and returns shared pointer to the message header
    auto header = msg.create(0, eMessageType::BACKHAUL_STEERING_REQUEST_MESSAGE);
    header->flags().last_fragment_indicator = 1;
    header->flags().relay_indicator         = 1;

    //NOTE: I used random TLVs for the example, don't expect a standard IEEE1905 message
    MAPF_DBG("CLASS SIZE: " << sizeof(tlvNon1905neighborDeviceList));
    auto firstTlv           = msg.addClass<tlvNon1905neighborDeviceList>();
    bool allocation_succeed = firstTlv->alloc_mac_non_1905_device(
        3); //3 mac addresses for the example, can be any number, only limited by the buffer size
    mapf_assert(
        allocation_succeed ==
        true); //false is returned in case that there isn't enough space on the buffer for the allocation

    auto first_mac = firstTlv->mac_non_1905_device(
        0); //get the first mac address struct in this tlv. returns a <bool,sMacAddr&> collection.
    bool isExist = std::get<0>(
        first_mac); //checking the first parameter, boolean, if the address in this index exists
    if (isExist) {
        auto &address =
            std::get<1>(first_mac); //knowing that the address exists, get the address struct
        address.oct[0] = 0x00;
        address.oct[1] = 0x01;
        address.oct[2] = 0x02;
        address.oct[3] = 0x03;
        address.oct[4] = 0x04;
        address.oct[5] = 0x05;
        MAPF_DBG("WRITE 1 : " << (int)address.oct[3]);
    }

    auto second_mac = firstTlv->mac_non_1905_device(
        1); //get the second mac address struct in this tlv. returns a bool-sMacAddr& collection.
    isExist = std::get<0>(
        second_mac); //checking the first parameter, boolean, if the address in this index exists
    if (isExist) {
        auto &address =
            std::get<1>(second_mac); //knowing that the address exists, get the address struct
        address.oct[0] = 0x05;
        address.oct[1] = 0x05;
        address.oct[2] = 0x05;
        address.oct[3] = 0x05;
        address.oct[4] = 0x05;
        address.oct[5] = 0x05;
        MAPF_DBG("WRITE 2 : " << (int)address.oct[3]);
    }

    auto third_mac = firstTlv->mac_non_1905_device(
        2); //get the third mac address struct in this tlv. returns a bool-sMacAddr& collection.
    isExist = std::get<0>(
        third_mac); //checking the first parameter, boolean, if the address in this index exists
    if (isExist) {
        auto &address =
            std::get<1>(third_mac); //knowing that the address exists, get the address struct
        address.oct[0] = 0xFF;
        address.oct[1] = 0xFF;
        address.oct[2] = 0xFF;
        address.oct[3] = 0xFF;
        address.oct[4] = 0xFF;
        address.oct[5] = 0xFF;

        // Remove "unused variable" warning
        (void)address;
    }

    MAPF_DBG("TLV LENGTH START: " << firstTlv->length());
    auto secondTlv = msg.addClass<tlvLinkMetricQuery>(); // another tlv for the example
    secondTlv->link_metrics_type() = eLinkMetricsType::RX_LINK_METRICS_ONLY;

    LOG(DEBUG) << "Start WSC M2";
    auto thirdTlv = msg.addClass<tlvWsc>();

    /**
     * @brief Diffie helman key exchange
     *
     */
    uint8_t key1[192];
    uint8_t key2[192];
    unsigned key1_length = sizeof(key1);
    unsigned key2_length = sizeof(key2);
    std::fill(key1, key1 + key1_length, 1);
    std::fill(key2, key2 + key2_length, 2);
    mapf::encryption::diffie_hellman m1;
    mapf::encryption::diffie_hellman m2;
    // diffie-helman key-exchange
    m1.compute_key(key1, key1_length, m2.pubkey(), m2.pubkey_length());
    m2.compute_key(key2, key2_length, m1.pubkey(), m1.pubkey_length());
    key1_length    = sizeof(key1);
    uint8_t mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t authkey[32];
    uint8_t keywrapkey[16];
    WSC::m2::config cfg;
    cfg.msg_type            = WSC::eWscMessageType::WSC_MSG_TYPE_M2;
    cfg.manufacturer        = "prplMesh";
    cfg.model_name          = "Ubuntu";
    cfg.model_number        = "18.04";
    cfg.serial_number       = "prpl12345";
    cfg.primary_dev_type_id = WSC::WSC_DEV_NETWORK_INFRA_GATEWAY;
    cfg.device_name         = "prplmesh-controller";
    cfg.encr_type_flags     = uint16_t(WSC::eWscEncr::WSC_ENCR_NONE);
    cfg.auth_type_flags     = WSC::eWscAuth::WSC_AUTH_OPEN;
    cfg.bands               = WSC::WSC_RF_BAND_2GHZ;
    mapf::encryption::create_iv(cfg.iv, sizeof(cfg.iv));
    wps_calculate_keys(m1, key1, key1_length, m1.nonce(), mac, m2.nonce(), authkey, keywrapkey);
    if (!add_encrypted_settings(*thirdTlv, keywrapkey, cfg)) {
        MAPF_ERR("add encrypted settings failed");
        return false;
    }
    LOG(DEBUG) << "Done (WSC M2)";
    MAPF_DBG("TLV LENGTH WSC M2: " << thirdTlv->length());

    auto mactlv                     = msg.addClass<tlvMacAddress>();
    const uint8_t gTlvMacAddress[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    tlvf::mac_from_array(gTlvMacAddress, mactlv->mac());

    MAPF_DBG("TLV LENGHT MAC: " << mactlv->length());

    auto fourthTlv     = msg.addClass<tlvTestVarList>();
    fourthTlv->var0()  = 0xa0;
    allocation_succeed = fourthTlv->alloc_simple_list(2);
    mapf_assert(allocation_succeed);
    *(fourthTlv->simple_list(0)) = 0x0bb0;
    *(fourthTlv->simple_list(1)) = 0x0bb1;

    if (fourthTlv->alloc_simple_list(7)) {
        LOG(ERROR) << "Allocation succeeded despite list max length overflow!";
        errors++;
    }

    auto cmplx = fourthTlv->create_complex_list();
    cmplx->alloc_list(3);
    *(cmplx->list(0)) = 0xc0;
    *(cmplx->list(1)) = 0xc1;
    *(cmplx->list(2)) = 0xc2;
    cmplx->var1()     = 0xd00d;
    cmplx->alloc_list();
    *(cmplx->list(3)) = 0xc3;
    cmplx->alloc_list();
    *(cmplx->list(4)) = 0xc4;
    cmplx->alloc_list();
    *(cmplx->list(5)) = 0xc5;
    if (!fourthTlv->add_complex_list(cmplx)) { //first entry
        LOG(ERROR) << "Failed to add complex list";
        errors++;
    }

    // TODO the complex list doesn't work at the moment if it has more than one element
    // Cfr. #137
    cmplx         = fourthTlv->create_complex_list();
    cmplx->var1() = 0xa11ad11d;
    if (!fourthTlv->add_complex_list(cmplx)) { //second entry
        LOG(ERROR) << "Failed to add complex list";
        errors++;
    }
    if (fourthTlv->add_complex_list(cmplx)) {
        LOG(ERROR) << "Could add complex list a second time";
        errors++;
    }
    cmplx         = fourthTlv->create_var1();
    cmplx->var1() = 0xeeee;
    if (!fourthTlv->add_var1(cmplx)) {
        LOG(ERROR) << "Failed to add var1";
        errors++;
    }
    if (fourthTlv->add_var1(cmplx)) {
        LOG(ERROR) << "Could add var1 a second time";
        errors++;
    }

    cmplx         = fourthTlv->create_var3();
    cmplx->var1() = 0xeeee;

    if (!fourthTlv->add_var3(cmplx)) {
        LOG(ERROR) << "Failed to add var3";
        errors++;
    }
    if (fourthTlv->add_var3(cmplx)) {
        LOG(ERROR) << "Could add var3 a second time";
        errors++;
    }

    LOG(DEBUG) << "TLV 4 length " << fourthTlv->length();
    auto unknown    = fourthTlv->create_unknown_length_list();
    unknown->var1() = 0xbbbbaaaa;
    fourthTlv->add_unknown_length_list(unknown);
    LOG(DEBUG) << "Unknown list size: " << unknown->getLen();
    LOG(DEBUG) << "Total unknown Length: " << fourthTlv->unknown_length_list_length();
    LOG(DEBUG) << "TLV 4 length " << fourthTlv->length();

    LOG(DEBUG) << "Total Message length=" << int(msg.getMessageLength());

    LOG(DEBUG) << "Finalize";
    //MANDATORY - swaps to little indian.
    if (!msg.finalize()) {
        LOG(ERROR) << "Finalize step failed";
        errors++;
    }

    LOG(DEBUG) << "TX: " << std::endl << utils::dump_buffer(tx_buffer, msg.getMessageLength());

    uint8_t recv_buffer[sizeof(tx_buffer)];
    memcpy(recv_buffer, tx_buffer, sizeof(recv_buffer));

    CmduMessageRx received_message(recv_buffer, sizeof(recv_buffer));
    received_message.parse();

    auto tlv1 = received_message.getClass<tlvNon1905neighborDeviceList>();
    if (tlv1 != nullptr) {
        MAPF_DBG("LENGTH AFTER INIT: " << tlv1->length());
        //tlv1->alloc_mac_non_1905_device(3);

        auto mac2 = tlv1->mac_non_1905_device(
            2); //get the second mac address struct in this tlv. returns a bool-sMacAddr& collection.
        isExist = std::get<0>(
            mac2); //checking the first parameter, boolean, if the address in this index exists
        if (isExist) {
            auto address =
                std::get<1>(mac2); //knowing that the address exists, get the address struct
                                   /*       address.oct[0] = 0x05;
            address.oct[1] = 0x05;
            address.oct[2] = 0x05;
            address.oct[3] = 0x05;
            address.oct[4] = 0x05;
            address.oct[5] = 0x05;*/

            LOG(DEBUG) << "ADDRESS IS " << (int)address.oct[0];
        } else {
            MAPF_ERR("TLV DOES NOT EXIST");
            errors++;
        }
    } else {
        MAPF_ERR("TLV1 IS NULL");
        errors++;
    }

    auto tlv2 = received_message.getClass<tlvLinkMetricQuery>();
    if (tlv2 != nullptr) {
        MAPF_DBG("TLV2 LENGTH AFTER INIT: " << tlv2->length());
    } else {
        MAPF_ERR("TLV2 IS NULL");
        errors++;
    }

    auto tlv3 = received_message.getClass<tlvWsc>();
    if (tlv3 != nullptr) {
        MAPF_DBG("TLV3 LENGTH AFTER INIT: " << tlv3->length());
    } else {
        MAPF_ERR("TLV3 IS NULL");
        errors++;
    }
    if (!parse_encrypted_settings(tlv3, keywrapkey, cfg.iv)) {
        MAPF_ERR("TLV3 parse encrypted settings failed");
        errors++;
    }

    auto tlv4 = received_message.getClass<tlvUnknown>()->class_cast<tlvTestVarList>();
    if (tlv4 == nullptr) {
        MAPF_ERR("TLV4 is NULL");
        errors++;
    } else {
        if (tlv4->var0() != 0xa0) {
            MAPF_ERR("TLV4 var0 is 0x" << std::hex << tlv4->var0() << " instead of 0xa0");
            errors++;
        }

        if (tlv4->simple_list_length() != 2) {
            MAPF_ERR("TLV4 simple list length is " << unsigned(tlv4->simple_list_length())
                                                   << " instead of 2");
            errors++;
        }
        for (uint8_t list_idx = 0; list_idx < tlv4->simple_list_length(); list_idx++) {
            uint16_t expected = 0x0bb0;
            if (!tlv4->simple_list(list_idx)) {
                MAPF_ERR("TLV4 has no simple " << list_idx);
                errors++;
            } else {
                auto value = tlv4->simple_list(list_idx);
                if (*value != expected + list_idx) {
                    MAPF_ERR("TLV4 simple ") << list_idx << " has value " << std::hex << *value
                                             << " instead of " << std::hex << expected + list_idx;
                    errors++;
                }
            }
        }

        LOG(DEBUG) << "Total unknown Length: " << tlv4->unknown_length_list_length();
        if (tlv4->unknown_length_list_length() != fourthTlv->unknown_length_list_length()) {
            MAPF_ERR("TLV 4 unknown length list length mismatch");
            errors++;
        }

        LOG(DEBUG) << "TLV 4 length " << tlv4->length();
        // TODO the complex list doesn't work at the moment if it has more than one element
        // Cfr. #137
        if (tlv4->complex_list_length() != 2) {
            MAPF_ERR("TLV4 complex list length is " << unsigned(tlv4->complex_list_length())
                                                    << " instead of 2");
            errors++;
        }

        if (!std::get<0>(tlv4->complex_list(0))) {
            MAPF_ERR("TLV4 has no complex 0");
            errors++;
        } else {
            auto cmplx = std::get<1>(tlv4->complex_list(0));
            if (cmplx.list_length() != 6) {
                MAPF_ERR("TLV4 complex 0 list length is " << unsigned(cmplx.list_length())
                                                          << " instead of 6");
                errors++;
            }
            uint8_t expected = 0xc0;
            for (uint8_t list_idx = 0; list_idx < cmplx.list_length(); list_idx++) {
                if (!cmplx.list(list_idx)) {
                    MAPF_ERR("TLV4 complex 0 has no list[" << list_idx << "]");
                    errors++;
                } else {
                    auto value = cmplx.list(list_idx);
                    if (*value != expected + list_idx) {
                        MAPF_ERR("TLV4 complex 0 list ")
                            << list_idx << " has value " << std::hex << *value << " instead of "
                            << std::hex << expected + list_idx;
                        errors++;
                    }
                }
            }

            if (cmplx.var1() != 0xd00d) {
                MAPF_ERR("TLV4 complex 0 var1 is " << std::hex << cmplx.var1()
                                                   << " instead of 0xd00d");
                errors++;
            }
        }
        if (!std::get<0>(tlv4->complex_list(1))) {
            MAPF_ERR("TLV4 has no complex 1");
            errors++;
        } else {
            auto cmplx = std::get<1>(tlv4->complex_list(1));
            if (cmplx.list_length() != 0) {
                MAPF_ERR("TLV4 complex 1 list length is " << unsigned(cmplx.list_length())
                                                          << " instead of 0");
                errors++;
            }
            if (cmplx.var1() != 0xa11ad11d) {
                MAPF_ERR("TLV4 complex 1 var1 is " << std::hex << cmplx.var1()
                                                   << " instead of 0xa11ad11d");
                errors++;
            }
        }

        auto var1 = tlv4->var1();
        if (!var1) {
            MAPF_ERR("TLV4 var1 is not set");
        } else {
            if (var1->list_length() != 0) {
                MAPF_ERR("TLV4 var1 list length is " << unsigned(var1->list_length())
                                                     << " instead of 0");
                errors++;
            }
            if (var1->var1() != 0xeeee) {
                MAPF_ERR("TLV4 var1 var1 is " << std::hex << var1->var1() << " instead of 0xeeee");
                errors++;
            }
        }
    }

    int invalidBufferSize = 26;
    uint8_t invalidBuffer[invalidBufferSize];
    memcpy(invalidBuffer, recv_buffer, 26);

    CmduMessageRx invmsg(invalidBuffer, invalidBufferSize);
    if (!invmsg.parse()) {
        MAPF_DBG("Parse PROTECTION SUCCESS");
    }

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

int test_mac_from_string()
{
    MAPF_INFO(__FUNCTION__ << " Starting");
    int errors = 0;

    // To make tests easy, we use MAC digits in the range 0x30-0x39, which is just 0-9 as string.
    // To have some letters as well, we can use 0x3d which is = and 0x3f which is ?
    auto check_success = [&errors](const std::string &mac, const char *as_int) {
        uint8_t mac_oct[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
        if (tlvf::mac_from_string(mac_oct, mac)) {
            if (std::memcmp(mac_oct, as_int, sizeof(mac_oct)) != 0) {
                MAPF_INFO("mac_from_string doesn't match expected: "
                          << mac << " -> " << as_int << " got " << tlvf::mac_to_string(mac_oct));
                errors++;
            }
        } else {
            MAPF_INFO("mac_from_string failed for " << mac);
            errors++;
        }
    };

    check_success("30:31:32:33:34:35", "012345");
    check_success("0x363738393d3f", "6789=?");
    check_success("0x363738393D3F", "6789=?");
    check_success("36:37:38:39:3D:3F", "6789=?");
    check_success("333333333333", "333333");
    check_success("", "\0\0\0\0\0\0");

    auto check_fail = [&errors](const std::string &mac) {
        uint8_t mac_oct[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
        if (tlvf::mac_from_string(mac_oct, mac)) {
            MAPF_INFO("mac_from_string should fail for " << mac << " got "
                                                         << tlvf::mac_to_string(mac_oct));
            errors++;
        } else {
            const uint8_t zero[6] = {0, 0, 0, 0, 0, 0};
            if (std::memcmp(mac_oct, zero, sizeof(mac_oct)) != 0) {
                MAPF_INFO("mac_oct not wiped after failed conversion of " << mac);
                errors++;
            }
        }
    };
    check_fail("1");
    check_fail("30:31:32:33:34:3g");    // Non-hex digit
    check_fail("30:31:32:33:34");       // Too few
    check_fail("30:31:32:33:34:35:36"); // Too many
    check_fail("30 31 32 33 34 35");    // Invalid separator
    check_fail("30031:32:33:34:35");    // Wrong format
    check_fail("30:31:32:33:340:35:3"); // Wrong format

    check_fail("0x363738393d3g");  // Non-hex digit
    check_fail("0x363738393d3");   // Too few
    check_fail("0x363738393d3f3"); // Too many
    check_fail("0y363738393d3f3"); // Doesn't start with 0x

    check_fail("363738393d3g");  // Non-hex digit
    check_fail("363738393d3");   // Too few
    check_fail("363738393d3f3"); // Too many

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

/*
 * Test the conditional parameters by using tlvProfile2ChannelScanResult.
 * Parse rx_buffer, and try to access the conditional elements if they
 * must be present (i.e. if the condition is met).
 * Then, try to create a tx TLV with the same values, and check that rx and tx match.
 */
int _test_conditional_parameters_rx_tx(uint8_t *rx_buffer, size_t rx_size)
{
    int errors  = 0;
    auto tlv_rx = tlvProfile2ChannelScanResult(rx_buffer, rx_size, true);
    auto len    = tlv_rx.neighbors_list_length();
    LOG(DEBUG) << "len: " << len << std::endl;
    for (unsigned i = 0; i < len; i++) {
        auto t = tlv_rx.neighbors_list(i);
        if (!std::get<0>(t)) {
            MAPF_ERR("Failed to get neighbor " + i);
            errors++;
        }
        auto &n = std::get<1>(t);
        // bssid follows the station count, when debugging it's useful to print to check that the sizes are correct:
        LOG(DEBUG) << "neighbor " << i << " bssid: " << n.bssid() << std::endl;
        LOG(DEBUG) << "neighbor " << i << " load presence flag: " << n.bss_load_element_present()
                   << std::endl;
        if (n.bss_load_element_present() ==
            wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_PRESENT) {
            LOG(DEBUG) << "neighbor " << i << " channel utilization: " << *(n.channel_utilization())
                       << std::endl;
            LOG(DEBUG) << "neighbor " << i << " station count: " << *(n.station_count())
                       << std::endl;
        } else {
            if (n.channel_utilization()) {
                MAPF_ERR("Load presence flag not set but channel_utilization not nullptr!");
            }
            if (n.station_count()) {
                MAPF_ERR("Load presence flag not set but station_count not nullptr!");
            }
        }
    }

    uint8_t tx_buffer[4096];
    memset(tx_buffer, 0, sizeof(tx_buffer));
    auto tlv_tx              = tlvProfile2ChannelScanResult(tx_buffer, sizeof(tx_buffer), false);
    tlv_tx.radio_uid()       = tlv_rx.radio_uid();
    tlv_tx.operating_class() = tlv_rx.operating_class();
    tlv_tx.channel()         = tlv_rx.channel();
    tlv_tx.success()         = tlv_rx.success();
    tlv_tx.set_timestamp(tlv_rx.timestamp_str());
    tlv_tx.utilization() = tlv_rx.utilization();
    tlv_tx.noise()       = tlv_rx.noise();
    for (unsigned i = 0; i < len; i++) {
        auto t = tlv_rx.neighbors_list(i);
        if (!std::get<0>(t)) {
            MAPF_ERR("Failed to get neighbor " + i);
            errors++;
        }
        auto &rx_neigh                       = std::get<1>(t);
        std::shared_ptr<cNeighbors> tx_neigh = tlv_tx.create_neighbors_list();
        tx_neigh->bssid()                    = rx_neigh.bssid();
        tx_neigh->set_ssid(rx_neigh.ssid_str());
        tx_neigh->signal_strength() = rx_neigh.signal_strength();
        tx_neigh->set_channels_bw_list(rx_neigh.channels_bw_list_str());
        if (rx_neigh.bss_load_element_present() ==
            wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_PRESENT) {
            tx_neigh->set_channel_utilization(*rx_neigh.channel_utilization());
            tx_neigh->set_station_count(*rx_neigh.station_count());
        }

        tlv_tx.add_neighbors_list(tx_neigh);
    }
    tlv_tx.aggregate_scan_duration() = tlv_rx.aggregate_scan_duration();
    tlv_tx.scan_type()               = tlv_rx.scan_type();

    // tlv_rx is already in host byte order (swapping is done in
    // init()). If we want to compare tx to rx, we have to NOT swap
    // tx, to keep it in host byte order as well.

    if (!std::equal(tlv_rx.getStartBuffPtr(), tlv_rx.getStartBuffPtr() + tlv_rx.getLen(),
                    tlv_tx.getStartBuffPtr())) {
        MAPF_ERR("RX and TX buffers do not match!");
        errors++;
        LOG(DEBUG) << "RX: " << std::endl << utils::dump_buffer(tlv_rx.getStartBuffPtr(), rx_size);
        LOG(DEBUG) << "TX: " << std::endl
                   << utils::dump_buffer(tlv_tx.getStartBuffPtr(), tlv_tx.getLen());
    }

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

/**
 * @brief Check if \p field matches \p value.
 *
 * This is meant to be used to increment an `errors` variable on failure.
 * @return 0 if \p field matches \p value, 1 otherwise.
 **/
template <typename T> int check_field(T field, T value, std::string name)
{
    if (field != value) {
        MAPF_ERR(name + " does not match!");
        MAPF_ERR(field);
        MAPF_ERR(value);
        return 1;
    }
    return 0;
}

int test_channel_scan_results()
{
    int errors = 0;
    MAPF_INFO(__FUNCTION__ << " start");

    // 2 neighbors, the second one doesn't have the bss load elements:
    MAPF_INFO(__FUNCTION__ << " start with rx_buffer_3");
    uint8_t rx_buffer[] = {
        0xa7, 0x00, 0x6f, 0x00, 0x50, 0x43, 0x24, 0x19, 0x30, 0x51, 0x06, 0x00, 0x1f, 0x32, 0x30,
        0x38, 0x39, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x33, 0x35, 0x3a,
        0x30, 0x37, 0x2e, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x0a,
        0x64, 0x00, 0x02, 0x00, 0x0c, 0x43, 0x48, 0xa0, 0x26, 0x0e, 0x4d, 0x75, 0x6c, 0x74, 0x69,
        0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x31, 0xe7, 0x05, 0x32, 0x30, 0x4d, 0x48,
        0x7a, 0x80, 0x06, 0x00, 0x00, 0x00, 0x50, 0x43, 0x24, 0x18, 0xb0, 0x0e, 0x4d, 0x75, 0x6c,
        0x74, 0x69, 0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x32, 0xe6, 0x05, 0x32, 0x30,
        0x4d, 0x48, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00};
    auto tlv_rx = tlvProfile2ChannelScanResult(rx_buffer, sizeof(rx_buffer), true);

    errors += check_field<sMacAddr>(tlv_rx.radio_uid(), tlvf::mac_from_string("00:50:43:24:19:30"),
                                    "radio_uid");
    errors += check_field<uint8_t>(tlv_rx.operating_class(), 0x51, "operating_class");
    errors += check_field<uint8_t>(tlv_rx.channel(), 0x06, "channel");
    errors += check_field<tlvProfile2ChannelScanResult::eScanStatus>(
        tlv_rx.success(), tlvProfile2ChannelScanResult::eScanStatus::SUCCESS, "success");
    errors += check_field<std::string>(tlv_rx.timestamp_str(), "2089-02-01T00:35:07.00000+00:00",
                                       "timestamp");
    errors += check_field<uint8_t>(tlv_rx.utilization(), 10, "utilization");
    errors += check_field<uint8_t>(tlv_rx.noise(), 100, "noise");

    errors += check_field<uint16_t>(tlv_rx.neighbors_list_length(), 2, "neighbors list length");
    int neigh_num = 0;

    {
        // Neighbor 0, it has load elements.
        auto t = tlv_rx.neighbors_list(neigh_num);
        if (!std::get<0>(t)) {
            MAPF_ERR("Failed to get neighbor " + neigh_num);
            errors++;
        }
        auto &rx_neigh = std::get<1>(t);
        errors +=
            check_field<sMacAddr>(rx_neigh.bssid(), tlvf::mac_from_string("00:0c:43:48:a0:26"),
                                  "neigh" + std::to_string(neigh_num) + " bssid");
        errors += check_field<uint8_t>(rx_neigh.ssid_length(), 14,
                                       "neigh " + std::to_string(neigh_num) + " ssid_length");
        errors += check_field<std::string>(rx_neigh.ssid_str(), "Multi-AP-24-T1",
                                           "neigh " + std::to_string(neigh_num) + " ssid");
        errors += check_field<uint8_t>(rx_neigh.signal_strength(), 231,
                                       "neigh " + std::to_string(neigh_num) + " signal strength");
        errors += check_field<std::string>(rx_neigh.channels_bw_list_str(), "20MHz",
                                           "neigh " + std::to_string(neigh_num) + " bandwidth");
        errors +=
            check_field<uint8_t>(rx_neigh.bss_load_element_present(),
                                 wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_PRESENT,
                                 "neigh " + std::to_string(neigh_num) + " load element presence");
        errors +=
            check_field<uint8_t>(*rx_neigh.channel_utilization(), 6,
                                 "neigh " + std::to_string(neigh_num) + " channel_utilization");
        errors += check_field<uint16_t>(*rx_neigh.station_count(), 0,
                                        "neigh " + std::to_string(neigh_num) + " station_count");
    }

    ++neigh_num;
    {
        // Neighbor 1, it does NOT have load elements.
        auto t = tlv_rx.neighbors_list(neigh_num);
        if (!std::get<0>(t)) {
            MAPF_ERR("Failed to get neighbor " + neigh_num);
            errors++;
        }
        auto &rx_neigh = std::get<1>(t);
        errors +=
            check_field<sMacAddr>(rx_neigh.bssid(), tlvf::mac_from_string("00:50:43:24:18:b0"),
                                  "neigh" + std::to_string(neigh_num) + " bssid");
        errors += check_field<uint8_t>(rx_neigh.ssid_length(), 14,
                                       "neigh " + std::to_string(neigh_num) + " ssid_length");
        errors += check_field<std::string>(rx_neigh.ssid_str(), "Multi-AP-24-T2",
                                           "neigh " + std::to_string(neigh_num) + " ssid");
        errors += check_field<uint8_t>(rx_neigh.signal_strength(), 230,
                                       "neigh " + std::to_string(neigh_num) + " signal strength");
        errors += check_field<std::string>(rx_neigh.channels_bw_list_str(), "20MHz",
                                           "neigh " + std::to_string(neigh_num) + " bandwidth");
        errors +=
            check_field<uint8_t>(rx_neigh.bss_load_element_present(),
                                 wfa_map::cNeighbors::eBssLoadElementPresent::FIELD_NOT_PRESENT,
                                 "neigh " + std::to_string(neigh_num) + " load element presence");
    }

    errors +=
        check_field<uint32_t>(tlv_rx.aggregate_scan_duration(), 100, "aggregate scan duration");
    errors += check_field<uint8_t>(
        tlv_rx.scan_type(), wfa_map::tlvProfile2ChannelScanResult::eScanType::SCAN_WAS_PASSIVE_SCAN,
        "scan type");

    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}

int test_conditional_parameters_rx_tx()
{
    int errors = 0;
    MAPF_INFO(__FUNCTION__ << " start with rx_buffer_1");

    // 2 neighbors, none have the bss load elements:
    uint8_t rx_buffer_1[] = {
        0xa7, 0x00, 0x6c, 0x00, 0x50, 0x43, 0x24, 0x19, 0x30, 0x51, 0x06, 0x00, 0x1f, 0x32,
        0x30, 0x38, 0x39, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x33,
        0x35, 0x3a, 0x30, 0x37, 0x2e, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x30, 0x3a,
        0x30, 0x30, 0x0a, 0x64, 0x00, 0x02, 0x00, 0x0c, 0x43, 0x48, 0xa0, 0x26, 0x0e, 0x4d,
        0x75, 0x6c, 0x74, 0x69, 0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x31, 0xe7,
        0x05, 0x32, 0x30, 0x4d, 0x48, 0x7a, 0x00, 0x00, 0x50, 0x43, 0x24, 0x18, 0xb0, 0x0e,
        0x4d, 0x75, 0x6c, 0x74, 0x69, 0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x32,
        0xe6, 0x05, 0x32, 0x30, 0x4d, 0x48, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00};
    errors += _test_conditional_parameters_rx_tx(rx_buffer_1, sizeof(rx_buffer_1));

    // 2 neighbors, the first one doesn't have the bss load elements:
    MAPF_INFO(__FUNCTION__ << " start with rx_buffer_2");
    uint8_t rx_buffer_2[] = {
        0xa7, 0x00, 0x6f, 0x00, 0x50, 0x43, 0x24, 0x19, 0x30, 0x51, 0x06, 0x00, 0x1f, 0x32, 0x30,
        0x38, 0x39, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x33, 0x35, 0x3a,
        0x30, 0x37, 0x2e, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x0a,
        0x64, 0x00, 0x02, 0x00, 0x0c, 0x43, 0x48, 0xa0, 0x26, 0x0e, 0x4d, 0x75, 0x6c, 0x74, 0x69,
        0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x31, 0xe7, 0x05, 0x32, 0x30, 0x4d, 0x48,
        0x7a, 0x00, 0x00, 0x50, 0x43, 0x24, 0x18, 0xb0, 0x0e, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x2d,
        0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x32, 0xe6, 0x05, 0x32, 0x30, 0x4d, 0x48, 0x7a,
        0x80, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00};
    errors += _test_conditional_parameters_rx_tx(rx_buffer_2, sizeof(rx_buffer_2));

    // 2 neighbors, the second one doesn't have the bss load elements:
    MAPF_INFO(__FUNCTION__ << " start with rx_buffer_3");
    uint8_t rx_buffer_3[] = {
        0xa7, 0x00, 0x6f, 0x00, 0x50, 0x43, 0x24, 0x19, 0x30, 0x51, 0x06, 0x00, 0x1f, 0x32, 0x30,
        0x38, 0x39, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x33, 0x35, 0x3a,
        0x30, 0x37, 0x2e, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x0a,
        0x64, 0x00, 0x02, 0x00, 0x0c, 0x43, 0x48, 0xa0, 0x26, 0x0e, 0x4d, 0x75, 0x6c, 0x74, 0x69,
        0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x31, 0xe7, 0x05, 0x32, 0x30, 0x4d, 0x48,
        0x7a, 0x80, 0x06, 0x00, 0x00, 0x00, 0x50, 0x43, 0x24, 0x18, 0xb0, 0x0e, 0x4d, 0x75, 0x6c,
        0x74, 0x69, 0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x32, 0xe6, 0x05, 0x32, 0x30,
        0x4d, 0x48, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00};
    errors += _test_conditional_parameters_rx_tx(rx_buffer_3, sizeof(rx_buffer_3));

    // 2 neighbors, both of them have the bss load elements:
    MAPF_INFO(__FUNCTION__ << " start with rx_buffer_4");
    uint8_t rx_buffer_4[] = {
        0xa7, 0x00, 0x72, 0x00, 0x50, 0x43, 0x24, 0x19, 0x30, 0x51, 0x06, 0x00, 0x1f, 0x32, 0x30,
        0x38, 0x39, 0x2d, 0x30, 0x32, 0x2d, 0x30, 0x31, 0x54, 0x30, 0x30, 0x3a, 0x33, 0x35, 0x3a,
        0x30, 0x37, 0x2e, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x0a,
        0x64, 0x00, 0x02, 0x00, 0x0c, 0x43, 0x48, 0xa0, 0x26, 0x0e, 0x4d, 0x75, 0x6c, 0x74, 0x69,
        0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x31, 0xe7, 0x05, 0x32, 0x30, 0x4d, 0x48,
        0x7a, 0x80, 0x06, 0x00, 0x00, 0x00, 0x50, 0x43, 0x24, 0x18, 0xb0, 0x0e, 0x4d, 0x75, 0x6c,
        0x74, 0x69, 0x2d, 0x41, 0x50, 0x2d, 0x32, 0x34, 0x2d, 0x54, 0x32, 0xe6, 0x05, 0x32, 0x30,
        0x4d, 0x48, 0x7a, 0x80, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00};
    errors += _test_conditional_parameters_rx_tx(rx_buffer_4, sizeof(rx_buffer_4));

    return errors;
}

void test_teams_members()
{
    uint8_t tx_buffer[4096];
    uint8_t len;
    memset(tx_buffer, 0, 4096);
    len = test_teams_members_build(tx_buffer, 4096);
    test_teams_members_parse(tx_buffer, len);
}

int main(int argc, char *argv[])
{
    int errors = 0;
    mapf::Logger::Instance();
    MAPF_INFO(__FUNCTION__ << " Starting tests");
    errors += test_int_len_list();
    errors += test_complex_list();
    errors += test_all();
    errors += test_parser();
    errors += test_mac_from_string();
    errors += test_conditional_parameters_rx_tx();
    errors += test_channel_scan_results();
    test_teams_members();
    MAPF_INFO(__FUNCTION__ << " Finished, errors = " << errors << std::endl);
    return errors;
}
