/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <tlvf/WSC/m8.h>
#include <tlvf/tlvfdefines.h>
#include <tlvf/tlvflogging.h>

using namespace WSC;

std::shared_ptr<m8> m8::parse(ieee1905_1::tlvWsc &tlv)
{
    if (!tlv.payload_length()) {
        TLVF_LOG(ERROR) << "No room to add attribute list (payload length = 0)";
        return nullptr;
    }
    auto attributes = std::make_shared<m8>(tlv.payload(), tlv.payload_length(), true);
    if (!attributes) {
        TLVF_LOG(ERROR) << "Failed to initialize attributes";
        return nullptr;
    }
    attributes->init();
    if (attributes->msg_type() != WSC_MSG_TYPE_M8) {
        TLVF_LOG(INFO) << "Not m8, msg type is " << int(attributes->msg_type());
        return nullptr;
    }
    if (!attributes->valid()) {
        TLVF_LOG(ERROR) << "Not all attributes present";
        return nullptr;
    }
    return attributes;
}

std::shared_ptr<m8> m8::create(ieee1905_1::tlvWsc &tlv, const config &cfg)
{
    if (cfg.msg_type != eWscMessageType::WSC_MSG_TYPE_M8)
        return nullptr;
    auto attributes = std::make_shared<m8>(tlv.payload(), tlv.payload_length(), false);
    if (!attributes || !attributes->init(cfg)) {
        TLVF_LOG(ERROR) << "Failed to initialize attributes";
        return nullptr;
    }
    if (!attributes->finalize()) {
        TLVF_LOG(ERROR) << "Failed to finalize attributes";
        return nullptr;
    }
    tlv.addInnerClassList(attributes);
    return attributes;
}

bool m8::init(const config &cfg)
{
    if (m_parse)
        return false; // Used for create only

    auto version = addAttr<cWscAttrVersion>();
    if (!version) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrVersion> failed";
        return false;
    }

    if (cfg.msg_type != eWscMessageType::WSC_MSG_TYPE_M8) {
        TLVF_LOG(ERROR) << "Invalid message type " << cfg.msg_type;
        return false;
    }
    auto msg_type_attr = addAttr<cWscAttrMessageType>();
    if (!msg_type_attr) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrMessageType> failed";
        return false;
    }
    msg_type_attr->msg_type() = cfg.msg_type;

    auto enrollee_nonce_attr = addAttr<cWscAttrEnrolleeNonce>();
    if (!enrollee_nonce_attr) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrEnrolleeNonce> failed";
        return false;
    }
    std::copy_n(cfg.enrollee_nonce, WSC_NONCE_LENGTH, enrollee_nonce_attr->nonce());

    auto registrar_nonce_attr = addAttr<cWscAttrRegistrarNonce>();
    if (!registrar_nonce_attr)
        return false;
    std::copy_n(cfg.registrar_nonce, WSC_NONCE_LENGTH, registrar_nonce_attr->nonce());

    auto public_key_attr = addAttr<cWscAttrPublicKey>();
    if (!public_key_attr) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrPublicKey> failed";
        return false;
    }
    std::copy(cfg.pub_key, cfg.pub_key + WSC_PUBLIC_KEY_LENGTH, public_key_attr->public_key());

    auto vendor_ext_attr = addAttr<cWscAttrVendorExtension>();
    if (!vendor_ext_attr) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrVendorExtension> failed";
        return false;
    }

    // WFA Vendor Data
    const size_t vendor_data_size = sizeof(sWscWfaVendorExtSubelementVersion2);
    if (!vendor_ext_attr->alloc_vendor_data(vendor_data_size)) {
        LOG(ERROR) << "Failed to allocate vendor data [" << vendor_data_size << "]!";
        return false;
    }
    auto vendor_data = vendor_ext_attr->vendor_data();

    // WFA Vendor Extension Subelement at #0: Version2
    sWscWfaVendorExtSubelementVersion2 version2{eWscWfaVendorExtSubelement::VERSION2, 0x01,
                                                eWscVendorExtVersionIE::WSC_VERSION2};
    std::copy_n(reinterpret_cast<uint8_t *>(&version2), sizeof(version2), vendor_data);

    auto encrypted_settings = addAttr<cWscAttrEncryptedSettings>();
    if (!encrypted_settings) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrEncryptedSettings> failed";
        return false;
    }
    std::copy_n(cfg.iv, WSC_ENCRYPTED_SETTINGS_IV_LENGTH, encrypted_settings->iv());
    encrypted_settings->alloc_encrypted_settings(cfg.encrypted_settings.size());
    std::copy_n(cfg.encrypted_settings.data(), encrypted_settings->encrypted_settings_length(),
                encrypted_settings->encrypted_settings());

    auto authenticator = addAttr<cWscAttrAuthenticator>();
    if (!authenticator) {
        TLVF_LOG(ERROR) << "addAttr<cWscAttrAuthenticator> failed";
        return false;
    }

    return true;
}

bool m8::valid() const
{
    if (!getAttr<cWscAttrVersion>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrVersion> failed";
        return false;
    }
    if (!getAttr<cWscAttrMessageType>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrMessageType> failed";
        return false;
    }
    if (!getAttr<cWscAttrEnrolleeNonce>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrEnrolleeNonce> failed";
        return false;
    }
    if (!getAttr<cWscAttrRegistrarNonce>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrRegistrarNonce> failed";
        return false;
    }
    if (!getAttr<cWscAttrPublicKey>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrPublicKey> failed";
        return false;
    }
    if (!getAttr<cWscAttrEncryptedSettings>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrEncryptedSettings> failed";
        return false;
    }
    if (!getAttr<cWscAttrAuthenticator>()) {
        TLVF_LOG(ERROR) << "getAttr<cWscAttrAuthenticator> failed";
        return false;
    }
    return true;
}
