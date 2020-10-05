/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_ucc_serializer_message_impl.h>

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>

namespace beerocks {

bool UccSerializerMessageImpl::serialize_reply(const std::string &reply,
                                               beerocks::net::Buffer &buffer)
{
    // Check if given buffer already contains some data
    if (buffer.length() > 0) {
        LOG(ERROR) << "Buffer is not empty!";
        return false;
    }

    // Check if given reply is an empty string
    if (reply.empty()) {
        LOG(ERROR) << "Reply is empty!";
        return false;
    }

    // Check if serialized data fits into given buffer
    size_t length = reply.length();
    size_t size   = buffer.size();
    if (length > size) {
        LOG(ERROR) << "Buffer is too small! Required size: " << length << ", actual size: " << size;
        return false;
    }

    // Copy reply string to the buffer "as is" (without any null-termination char)
    if (buffer.append(reinterpret_cast<const uint8_t *>(reply.c_str()), reply.length())) {
        LOG(ERROR) << "Failed appending reply to the buffer!";
        return false;
    }

    return true;
}

} // namespace beerocks
