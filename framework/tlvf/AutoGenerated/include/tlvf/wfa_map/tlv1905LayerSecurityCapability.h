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

#ifndef _TLVF_WFA_MAP_TLV1905LAYERSECURITYCAPABILITY_H_
#define _TLVF_WFA_MAP_TLV1905LAYERSECURITYCAPABILITY_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include <ostream>

namespace wfa_map {


class tlv1905LayerSecurityCapability : public BaseClass
{
    public:
        tlv1905LayerSecurityCapability(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlv1905LayerSecurityCapability(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlv1905LayerSecurityCapability();

        enum eOnboardingProtocol: uint8_t {
            IEEE1905_PROVISIONING_PROTOCOL = 0x0,
            RESERVED1 = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eOnboardingProtocol_str(eOnboardingProtocol enum_value) {
            switch (enum_value) {
            case IEEE1905_PROVISIONING_PROTOCOL: return "IEEE1905_PROVISIONING_PROTOCOL";
            case RESERVED1:                      return "RESERVED1";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eOnboardingProtocol value) { return out << eOnboardingProtocol_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        enum eMicAlgorithm: uint8_t {
            HMAC_SHA256 = 0x0,
            RESERVED2 = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eMicAlgorithm_str(eMicAlgorithm enum_value) {
            switch (enum_value) {
            case HMAC_SHA256: return "HMAC_SHA256";
            case RESERVED2:   return "RESERVED2";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eMicAlgorithm value) { return out << eMicAlgorithm_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        enum eEncryptionAlgorithm: uint8_t {
            AES_SIV = 0x0,
            RESERVED3 = 0x1,
        };
        // Enum AutoPrint generated code snippet begining- DON'T EDIT!
        // clang-format off
        static const char *eEncryptionAlgorithm_str(eEncryptionAlgorithm enum_value) {
            switch (enum_value) {
            case AES_SIV:   return "AES_SIV";
            case RESERVED3: return "RESERVED3";
            }
            static std::string out_str = std::to_string(int(enum_value));
            return out_str.c_str();
        }
        friend inline std::ostream &operator<<(std::ostream &out, eEncryptionAlgorithm value) { return out << eEncryptionAlgorithm_str(value); }
        // clang-format on
        // Enum AutoPrint generated code snippet end
        
        const eTlvTypeMap& type();
        const uint16_t& length();
        eOnboardingProtocol& onboarding_protocol();
        eMicAlgorithm& mic_algorithm();
        eEncryptionAlgorithm& encryption_algorithm();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        eOnboardingProtocol* m_onboarding_protocol = nullptr;
        eMicAlgorithm* m_mic_algorithm = nullptr;
        eEncryptionAlgorithm* m_encryption_algorithm = nullptr;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLV1905LAYERSECURITYCAPABILITY_H_
