/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_UCC_SERIALIZER_MESSAGE_IMPL_H_
#define _BEEROCKS_UCC_SERIALIZER_MESSAGE_IMPL_H_

#include <bcl/beerocks_ucc_serializer.h>

namespace beerocks {

class UccSerializerMessageImpl : public UccSerializer {
public:
    /**
     * @brief Serializes a UCC reply string to a byte buffer.
     *
     * @see UccSerializer::serialize_reply
     *
     * This implementation is intended to be used together with a message-oriented socket
     * (DGRAM_STREAM in UDS or UDP).
     */
    bool serialize_reply(const std::string &reply, beerocks::net::Buffer &buffer) override;
};

} // namespace beerocks

#endif /* _BEEROCKS_UCC_SERIALIZER_MESSAGE_IMPL_H_ */
