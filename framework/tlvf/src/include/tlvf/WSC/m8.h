/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_WSC_M8_H_
#define _TLVF_WSC_M8_H_

#include <tlvf/WSC/WscAttrList.h>

namespace WSC {

class m8 : public WscAttrList {
public:
    struct config {
        eWscMessageType msg_type;
        uint8_t enrollee_nonce[WSC_NONCE_LENGTH];
        uint8_t registrar_nonce[WSC_NONCE_LENGTH];
        uint8_t pub_key[WSC_PUBLIC_KEY_LENGTH];
        std::vector<uint8_t> encrypted_settings;
        uint8_t iv[WSC_ENCRYPTED_SETTINGS_IV_LENGTH];
    };
    m8(uint8_t *buff, size_t buff_len, bool parse) : WscAttrList(buff, buff_len, parse) {}
    virtual ~m8() = default;

    bool init(const config &cfg);
    bool init() { return WscAttrList::init(); };
    bool valid() const override;
    static std::shared_ptr<m8> create(ieee1905_1::tlvWsc &tlv, const config &cfg);
    static std::shared_ptr<m8> parse(ieee1905_1::tlvWsc &tlv);

    // getters
    eWscMessageType msg_type() const { return getAttr<cWscAttrMessageType>()->msg_type(); };
    uint8_t *enrollee_nonce() { return getAttr<cWscAttrEnrolleeNonce>()->nonce(); };
    uint8_t *public_key() { return getAttr<cWscAttrPublicKey>()->public_key(); };

    uint8_t *authenticator() { return getAttr<cWscAttrAuthenticator>()->data(); };
    uint8_t *registrar_nonce() { return getAttr<cWscAttrRegistrarNonce>()->nonce(); };
    cWscAttrEncryptedSettings &encrypted_settings()
    {
        return *getAttr<cWscAttrEncryptedSettings>();
    };
};

} // namespace WSC

#endif // _TLVF_WSC_M8_H_
