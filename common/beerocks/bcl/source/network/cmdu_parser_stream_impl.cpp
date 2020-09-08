/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/cmdu_parser_stream_impl.h>

#include <bcl/beerocks_backport.h>
#include <bcl/beerocks_string_utils.h>
#include <bcl/beerocks_utils.h>

#include <tlvf/ieee_1905_1/tlvVendorSpecific.h>

namespace beerocks {
namespace net {

bool CmduParserStreamImpl::parse_cmdu(Buffer &buffer, uint32_t &iface_index, sMacAddr &dst_mac,
                                      sMacAddr &src_mac, ieee1905_1::CmduMessageRx &cmdu_rx)
{
    // Check if UDS Header exists
    size_t length = buffer.length();
    if (length < sizeof(message::sUdsHeader)) {
        LOG(DEBUG) << "Buffer length (" << length << ") is less than UDS header length ("
                   << sizeof(message::sUdsHeader) << ")";
        return false;
    }

    // Get pointer to received data
    uint8_t *data = buffer.data();

    // Header ready
    auto uds_header       = reinterpret_cast<message::sUdsHeader *>(data);
    size_t cmdu_length    = uds_header->length;
    uint8_t *cmdu_data    = data + sizeof(message::sUdsHeader);
    size_t message_length = sizeof(message::sUdsHeader) + cmdu_length;

    // Try to read the message
    if (length < message_length) {
        LOG(DEBUG) << "Buffer length (" << length << ") is less than UDS header length ("
                   << sizeof(message::sUdsHeader) << ") + CMDU length (" << cmdu_length << ")";
        return false;
    }

    // Verify and parse the message
    bool result = false;
    if (!verify_cmdu(cmdu_data, cmdu_length)) {
        LOG(ERROR) << "Failed verifying cmdu!";
        LOG(DEBUG) << "hex_dump (" << cmdu_length << " bytes):" << std::endl
                   << utils::dump_buffer(cmdu_data, cmdu_length);
    } else if (cmdu_length > cmdu_rx.getMessageBuffLength()) {
        LOG(ERROR) << "CMDU length (" << cmdu_length << ") is greater than CMDU buffer size ("
                   << cmdu_rx.getMessageBuffLength() << ")";
    } else {
        std::copy_n(cmdu_data, cmdu_length, cmdu_rx.getMessageBuff());
        if (!cmdu_rx.parse()) {
            LOG(ERROR) << "Failed parsing CMDU, rx_buffer: " << std::hex << data << std::dec
                       << ", CMDU length =" << cmdu_length;
        } else {
            iface_index = uds_header->if_index;
            std::copy_n(uds_header->dst_bridge_mac, MAC_ADDR_LEN, dst_mac.oct);
            std::copy_n(uds_header->src_bridge_mac, MAC_ADDR_LEN, src_mac.oct);

            result = true;
        }
    }

    // Shift bytes remaining in buffer (i.e.: consume processed bytes and return bytes not
    // processed yet, if any)
    buffer.shift(message_length);

    return result;
}

// FIXME - WLANRTSYS-6360 - should be moved to transport
bool CmduParserStreamImpl::verify_cmdu(uint8_t *data, size_t length)
{
    if (length < ieee1905_1::cCmduHeader::get_initial_size() + sizeof(ieee1905_1::sTlvHeader)) {
        LOG(ERROR) << "Invalid CMDU length";
        return false;
    }

    ieee1905_1::sTlvHeader *tlv = reinterpret_cast<ieee1905_1::sTlvHeader *>(
        data + ieee1905_1::cCmduHeader::get_initial_size());

    bool ret = true;

    do {

        auto tlv_type = static_cast<ieee1905_1::eTlvType>(tlv->type);

        uint16_t tlv_length = tlv->length;
        swap_16(tlv_length);

        if (tlv_type == ieee1905_1::eTlvType::TLV_VENDOR_SPECIFIC) {
            auto tlv_vendor_specific =
                ieee1905_1::tlvVendorSpecific(reinterpret_cast<uint8_t *>(tlv),
                                              sizeof(ieee1905_1::sTlvHeader) + tlv_length, true);
            if (!tlv_vendor_specific.isInitialized()) {
                LOG(ERROR) << "tlvVendorSpecific init() failure";
                ret = false;
                break;
            }

            if (tlv_vendor_specific.vendor_oui() ==
                ieee1905_1::tlvVendorSpecific::eVendorOUI::OUI_INTEL) {
                // assuming that the magic is the first data on the beerocks header
                auto beerocks_magic =
                    *(reinterpret_cast<uint32_t *>(tlv_vendor_specific.payload()));
                swap_32(beerocks_magic);
                if (beerocks_magic != message::MESSAGE_MAGIC) {
                    LOG(WARNING) << "mismatch magic " << std::hex << int(beerocks_magic)
                                 << " != " << int(message::MESSAGE_MAGIC) << std::dec;
                    ret = false;
                    break;
                }

            } else {
                LOG(INFO) << "Not an Intel vendor specific message!";
            }

            // cancel the swap we did
            tlv_vendor_specific.class_swap();
        } else if ((tlv_type == ieee1905_1::eTlvType::TLV_END_OF_MESSAGE) && (0 == tlv_length)) {
            return true;
        }

        // set the next tlv
        tlv = reinterpret_cast<ieee1905_1::sTlvHeader *>(
            reinterpret_cast<uint8_t *>(tlv) + sizeof(ieee1905_1::sTlvHeader) + tlv_length);

    } while (reinterpret_cast<uint8_t *>(tlv) < (data + length));

    LOG(ERROR) << "TLV end of message not found! tlv_type=" << tlv->type
               << ", tlv_length=" << tlv->length;

    return ret;
}

} // namespace net
} // namespace beerocks
