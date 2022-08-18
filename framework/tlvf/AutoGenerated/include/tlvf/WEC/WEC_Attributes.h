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

#ifndef _TLVF_WEC_WEC_ATTRIBUTES_H_
#define _TLVF_WEC_WEC_ATTRIBUTES_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <asm/byteorder.h>
#include <tuple>
#include "tlvf/WEC/eWecDppAttributes.h"
#include "tlvf/WEC/eWecLengths.h"
#include "tlvf/WEC/eWecDppStatus.h"
#include "tlvf/WEC/eWecConnectorKey.h"

namespace WEC {

class cDppAttrResponderCapabilities;
class cDppAttrWrappedDataAttribute;
class cDppAttrInitiatorAuthenticatingTag;
class cDppAttrResponderAuthenticatingTag;
class cDppAttrDppConfigurationObject;
class cDppAttrDppConnector;
class cDppAttrDppConfigurationRequestObject;
class cDppAttrBootstrappingKey;
class cDppAttrCodeIdentifier;
class cDppAttrBootstrappingInfo;
class cDppAttrDppEnvelopedData;
class cDppAttrDppConnectionStatusObject;
class cDppAttrReconfigurationFlags;
class cDppAttrEtagId;
typedef struct sDppAttrDppStatus {
    eWecDppAttributes type;
    uint16_t length;
    eWecDppStatus dpp_status;
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_DPP_STATUS;
        length = sizeof(eWecDppStatus);
        dpp_status = eWecDppStatus::STATUS_OK;
    }
} __attribute__((packed)) sDppAttrDppStatus;

typedef struct sDppAttrInitiatorBootstrappingKeyHash {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t initiator_public_bootstrapping_key_hashed[WEC_SHA256_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_INITIATOR_BOOTSTRAPPING_KEY_HASH;
        length = WEC_SHA256_LENGTH;
    }
} __attribute__((packed)) sDppAttrInitiatorBootstrappingKeyHash;

typedef struct sDppAttrResponderBootstrappingKeyHash {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t responder_public_bootstrapping_key_hashed[WEC_SHA256_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_RESPONDER_BOOTSTRAPPING_KEY_HASH;
        length = WEC_SHA256_LENGTH;
    }
} __attribute__((packed)) sDppAttrResponderBootstrappingKeyHash;

typedef struct sDppAttrInitiatorProtocolKey {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t initiator_public_protocol_key[WEC_PUBLIC_PROTOCOL_KEY_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_INITIATOR_PROTOCOL_KEY;
        length = WEC_PUBLIC_PROTOCOL_KEY_LENGTH;
    }
} __attribute__((packed)) sDppAttrInitiatorProtocolKey;

typedef struct sDppAttrResponderProtocolKey {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t responder_public_protocol_key[WEC_PUBLIC_PROTOCOL_KEY_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_RESPONDER_PROTOCOL_KEY;
        length = WEC_PUBLIC_PROTOCOL_KEY_LENGTH;
    }
} __attribute__((packed)) sDppAttrResponderProtocolKey;

typedef struct sDppAttrInitiatorNonce {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t initiator_nonce[WEC_NONCE_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_INITIATOR_NONCE;
        length = WEC_NONCE_LENGTH;
    }
} __attribute__((packed)) sDppAttrInitiatorNonce;

typedef struct sDppAttrResponderNonce {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t responder_nonce[WEC_NONCE_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_RESPONDER_NONCE;
        length = WEC_NONCE_LENGTH;
    }
} __attribute__((packed)) sDppAttrResponderNonce;

typedef struct sDppAttrEnrolleeNonce {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t enrollee_nonce[WEC_NONCE_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_ENROLLEE_NONCE;
        length = WEC_NONCE_LENGTH;
    }
} __attribute__((packed)) sDppAttrEnrolleeNonce;

typedef struct sDppAttrConfiguratorNonce {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t configurator_nonce[WEC_NONCE_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_CONFIGURATOR_NONCE;
        length = WEC_NONCE_LENGTH;
    }
} __attribute__((packed)) sDppAttrConfiguratorNonce;

typedef struct sDppAttrFiniteCyclicGroup {
    eWecDppAttributes type;
    uint16_t length;
    //need to little endian byte order
    uint16_t integer;
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&integer));
    }
    void struct_init(){
        type = ATTR_FINITE_CYCLIC_GROUP;
        length = 0x2;
    }
} __attribute__((packed)) sDppAttrFiniteCyclicGroup;

typedef struct sDppAttrEncryptedKey {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t encrypted_key[WEC_ENCRYPTED_KEY_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_ENCRYPTED_KEY;
        length = WEC_ENCRYPTED_KEY_LENGTH;
    }
} __attribute__((packed)) sDppAttrEncryptedKey;

typedef struct sDppAttrTransactionId {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t transaction_id;
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_TRANSACTION_ID;
        length = 0x1;
    }
} __attribute__((packed)) sDppAttrTransactionId;

typedef struct sDppAttrChannel {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t operating_class;
    uint8_t channel;
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_CHANNEL;
        length = 0x2;
    }
} __attribute__((packed)) sDppAttrChannel;

typedef struct sDppAttrProtocolVersion {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t dpp_protocol_version;
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_PROTOCOL_VERSION;
        length = 0x1;
        dpp_protocol_version = 0x2;
    }
} __attribute__((packed)) sDppAttrProtocolVersion;

typedef struct sDppAttrSendConnStatus {
    eWecDppAttributes type;
    uint16_t length;
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_SEND_CONN_STATUS;
        length = 0x0;
    }
} __attribute__((packed)) sDppAttrSendConnStatus;

typedef struct sDppAttrANonce {
    eWecDppAttributes type;
    uint16_t length;
    uint8_t enrollee_nonce[WEC_NONCE_LENGTH];
    void struct_swap(){
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&type));
        tlvf_swap(16, reinterpret_cast<uint8_t*>(&length));
    }
    void struct_init(){
        type = ATTR_ENROLLEE_NONCE;
        length = WEC_NONCE_LENGTH;
    }
} __attribute__((packed)) sDppAttrANonce;


class cDppAttrInitiatorCapabilities : public BaseClass
{
    public:
        cDppAttrInitiatorCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrInitiatorCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrInitiatorCapabilities();

        typedef struct sWecICapabilitiesBitfield {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t enrollee_capable : 1;
            uint8_t configurator_capable : 1;
            uint8_t reserved : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t reserved : 6;
            uint8_t configurator_capable : 1;
            uint8_t enrollee_capable : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sWecICapabilitiesBitfield;
        
        eWecDppAttributes& type();
        const uint8_t& length();
        cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield& initiator_capabilities();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint8_t* m_length = nullptr;
        cDppAttrInitiatorCapabilities::sWecICapabilitiesBitfield* m_initiator_capabilities = nullptr;
};

class cDppAttrResponderCapabilities : public BaseClass
{
    public:
        cDppAttrResponderCapabilities(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrResponderCapabilities(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrResponderCapabilities();

        typedef struct sWecRCapabilitiesBitfield {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t enrollee_capable : 1;
            uint8_t configurator_capable : 1;
            uint8_t reserved : 6;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t reserved : 6;
            uint8_t configurator_capable : 1;
            uint8_t enrollee_capable : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sWecRCapabilitiesBitfield;
        
        eWecDppAttributes& type();
        uint8_t& length();
        cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield& responder_capabilities();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint8_t* m_length = nullptr;
        cDppAttrResponderCapabilities::sWecRCapabilitiesBitfield* m_responder_capabilities = nullptr;
};

class cDppAttrWrappedDataAttribute : public BaseClass
{
    public:
        cDppAttrWrappedDataAttribute(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrWrappedDataAttribute(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrWrappedDataAttribute();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t wrapped_data_length() { return m_wrapped_data_idx__ * sizeof(uint8_t); }
        uint8_t* wrapped_data(size_t idx = 0);
        bool set_wrapped_data(const void* buffer, size_t size);
        bool alloc_wrapped_data(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_wrapped_data = nullptr;
        size_t m_wrapped_data_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrInitiatorAuthenticatingTag : public BaseClass
{
    public:
        cDppAttrInitiatorAuthenticatingTag(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrInitiatorAuthenticatingTag(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrInitiatorAuthenticatingTag();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t initiator_authenticating_tag_length() { return m_initiator_authenticating_tag_idx__ * sizeof(uint8_t); }
        uint8_t* initiator_authenticating_tag(size_t idx = 0);
        bool set_initiator_authenticating_tag(const void* buffer, size_t size);
        bool alloc_initiator_authenticating_tag(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_initiator_authenticating_tag = nullptr;
        size_t m_initiator_authenticating_tag_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrResponderAuthenticatingTag : public BaseClass
{
    public:
        cDppAttrResponderAuthenticatingTag(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrResponderAuthenticatingTag(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrResponderAuthenticatingTag();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t responder_authenticating_tag_length() { return m_responder_authenticating_tag_idx__ * sizeof(uint8_t); }
        uint8_t* responder_authenticating_tag(size_t idx = 0);
        bool set_responder_authenticating_tag(const void* buffer, size_t size);
        bool alloc_responder_authenticating_tag(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_responder_authenticating_tag = nullptr;
        size_t m_responder_authenticating_tag_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrDppConfigurationObject : public BaseClass
{
    public:
        cDppAttrDppConfigurationObject(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrDppConfigurationObject(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrDppConfigurationObject();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t configuration_object_length() { return m_configuration_object_idx__ * sizeof(char); }
        std::string configuration_object_str();
        char* configuration_object(size_t length = 0);
        bool set_configuration_object(const std::string& str);
        bool set_configuration_object(const char buffer[], size_t size);
        bool alloc_configuration_object(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_configuration_object = nullptr;
        size_t m_configuration_object_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrDppConnector : public BaseClass
{
    public:
        cDppAttrDppConnector(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrDppConnector(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrDppConnector();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t connector_length() { return m_connector_idx__ * sizeof(char); }
        std::string connector_str();
        char* connector(size_t length = 0);
        bool set_connector(const std::string& str);
        bool set_connector(const char buffer[], size_t size);
        bool alloc_connector(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_connector = nullptr;
        size_t m_connector_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrDppConfigurationRequestObject : public BaseClass
{
    public:
        cDppAttrDppConfigurationRequestObject(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrDppConfigurationRequestObject(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrDppConfigurationRequestObject();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t configuration_request_object_length() { return m_configuration_request_object_idx__ * sizeof(char); }
        std::string configuration_request_object_str();
        char* configuration_request_object(size_t length = 0);
        bool set_configuration_request_object(const std::string& str);
        bool set_configuration_request_object(const char buffer[], size_t size);
        bool alloc_configuration_request_object(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_configuration_request_object = nullptr;
        size_t m_configuration_request_object_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrBootstrappingKey : public BaseClass
{
    public:
        cDppAttrBootstrappingKey(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrBootstrappingKey(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrBootstrappingKey();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t configuration_request_object_length() { return m_configuration_request_object_idx__ * sizeof(char); }
        std::string configuration_request_object_str();
        char* configuration_request_object(size_t length = 0);
        bool set_configuration_request_object(const std::string& str);
        bool set_configuration_request_object(const char buffer[], size_t size);
        bool alloc_configuration_request_object(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_configuration_request_object = nullptr;
        size_t m_configuration_request_object_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrCodeIdentifier : public BaseClass
{
    public:
        cDppAttrCodeIdentifier(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrCodeIdentifier(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrCodeIdentifier();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t code_identifier_length() { return m_code_identifier_idx__ * sizeof(char); }
        std::string code_identifier_str();
        char* code_identifier(size_t length = 0);
        bool set_code_identifier(const std::string& str);
        bool set_code_identifier(const char buffer[], size_t size);
        bool alloc_code_identifier(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_code_identifier = nullptr;
        size_t m_code_identifier_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrBootstrappingInfo : public BaseClass
{
    public:
        cDppAttrBootstrappingInfo(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrBootstrappingInfo(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrBootstrappingInfo();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t bootstrapping_info_length() { return m_bootstrapping_info_idx__ * sizeof(char); }
        std::string bootstrapping_info_str();
        char* bootstrapping_info(size_t length = 0);
        bool set_bootstrapping_info(const std::string& str);
        bool set_bootstrapping_info(const char buffer[], size_t size);
        bool alloc_bootstrapping_info(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_bootstrapping_info = nullptr;
        size_t m_bootstrapping_info_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrDppEnvelopedData : public BaseClass
{
    public:
        cDppAttrDppEnvelopedData(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrDppEnvelopedData(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrDppEnvelopedData();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t enveloped_data_length() { return m_enveloped_data_idx__ * sizeof(uint8_t); }
        uint8_t* enveloped_data(size_t idx = 0);
        bool set_enveloped_data(const void* buffer, size_t size);
        bool alloc_enveloped_data(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_enveloped_data = nullptr;
        size_t m_enveloped_data_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrDppConnectionStatusObject : public BaseClass
{
    public:
        cDppAttrDppConnectionStatusObject(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrDppConnectionStatusObject(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrDppConnectionStatusObject();

        eWecDppAttributes& type();
        const uint16_t& length();
        size_t dpp_connection_status_json_object_length() { return m_dpp_connection_status_json_object_idx__ * sizeof(char); }
        std::string dpp_connection_status_json_object_str();
        char* dpp_connection_status_json_object(size_t length = 0);
        bool set_dpp_connection_status_json_object(const std::string& str);
        bool set_dpp_connection_status_json_object(const char buffer[], size_t size);
        bool alloc_dpp_connection_status_json_object(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        char* m_dpp_connection_status_json_object = nullptr;
        size_t m_dpp_connection_status_json_object_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class cDppAttrReconfigurationFlags : public BaseClass
{
    public:
        cDppAttrReconfigurationFlags(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrReconfigurationFlags(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrReconfigurationFlags();

        typedef struct sWecReconfigurationFlags {
            #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t connector_key : 1;
            uint8_t reserved : 7;
            #elif defined(__BIG_ENDIAN_BITFIELD)
            uint8_t reserved : 7;
            uint8_t connector_key : 1;
            #else
            #error "Bitfield macros are not defined"
            #endif
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sWecReconfigurationFlags;
        
        eWecDppAttributes& type();
        uint8_t& length();
        cDppAttrReconfigurationFlags::sWecReconfigurationFlags& reconfiguration_flags();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint8_t* m_length = nullptr;
        cDppAttrReconfigurationFlags::sWecReconfigurationFlags* m_reconfiguration_flags = nullptr;
};

class cDppAttrEtagId : public BaseClass
{
    public:
        cDppAttrEtagId(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit cDppAttrEtagId(std::shared_ptr<BaseClass> base, bool parse = false);
        ~cDppAttrEtagId();

        eWecDppAttributes& type();
        uint16_t& length();
        size_t etag_id_length() { return m_etag_id_idx__ * sizeof(uint8_t); }
        uint8_t* etag_id(size_t idx = 0);
        bool set_etag_id(const void* buffer, size_t size);
        bool alloc_etag_id(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eWecDppAttributes* m_type = nullptr;
        uint16_t* m_length = nullptr;
        uint8_t* m_etag_id = nullptr;
        size_t m_etag_id_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: WEC

#endif //_TLVF/WEC_WEC_ATTRIBUTES_H_
