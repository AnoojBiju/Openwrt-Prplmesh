/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/network/cmdu_serializer_stream_impl.h>

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

namespace beerocks {
namespace net {

bool CmduSerializerStreamImpl::serialize_cmdu(const sMacAddr &dst_mac, const sMacAddr &src_mac,
                                              ieee1905_1::CmduMessageTx &cmdu_tx, Buffer &buffer)
{
    // If a destination MAC address has been given, then source MAC address must be given too
    if (beerocks::net::network_utils::ZERO_MAC != dst_mac) {
        if (beerocks::net::network_utils::ZERO_MAC == src_mac) {
            LOG(ERROR) << "Source MAC address is empty!";
            return false;
        }
    }

    // Check if given buffer already contains some data
    if (buffer.length() > 0) {
        LOG(ERROR) << "Buffer is not empty!";
        return false;
    }

    // Serialize CMDU
    size_t cmdu_length = cmdu_tx.getMessageLength();
    uint8_t *cmdu_data = cmdu_tx.getMessageBuff();
    if (!cmdu_tx.finalize()) {
        LOG(ERROR) << "Failed finalizing cmdu!";
        LOG(DEBUG) << "hex_dump (" << cmdu_length << " bytes):" << std::endl
                   << utils::dump_buffer(cmdu_data, cmdu_length);
        return false;
    }

    // Update payload length (finalize() adds an end-of-message TLV)
    cmdu_length = cmdu_tx.getMessageLength();

    // Check if serialized data fits into given buffer
    size_t length = sizeof(message::sUdsHeader) + cmdu_length;
    size_t size   = buffer.size();
    if (length > size) {
        LOG(ERROR) << "Buffer is too small! Required size: " << length << ", actual size: " << size;
        return false;
    }

    // Fill in UDS header
    message::sUdsHeader uds_header;
    std::copy_n(src_mac.oct, MAC_ADDR_LEN, uds_header.src_bridge_mac);
    std::copy_n(dst_mac.oct, MAC_ADDR_LEN, uds_header.dst_bridge_mac);
    uds_header.length = cmdu_length;

    // Fill in the buffer with header and payload
    if (!buffer.append(reinterpret_cast<uint8_t *>(&uds_header), sizeof(message::sUdsHeader))) {
        LOG(ERROR) << "Failed appending header to the buffer!";
        return false;
    }
    if (!buffer.append(cmdu_data, cmdu_length)) {
        LOG(ERROR) << "Failed appending payload to the buffer!";
        return false;
    }

    return true;
}

} // namespace net
} // namespace beerocks
