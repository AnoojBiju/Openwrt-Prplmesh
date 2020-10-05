/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_UCC_PARSER_MESSAGE_IMPL_H_
#define _BEEROCKS_UCC_PARSER_MESSAGE_IMPL_H_

#include <bcl/beerocks_ucc_parser.h>

namespace beerocks {

class UccParserMessageImpl : public UccParser {
public:
    /**
     * @brief Parses a UCC command string out of a byte buffer.
     *
     * @see UccParser::parse_command
     *
     * This implementation is intended to be used together with a message-oriented socket
     * (DGRAM_STREAM in UDS or UDP). Parsing procedure assumes that buffer with received data
     * contains one and only one message and that the message is complete.
     *
     * If data were received through a stream-oriented socket, the command might not have been
     * fully received. It could also happen that more than one command had been received at once.
     * Since there is no framing protocol defined in the UCC communication, there is no way to
     * know or fix it.
     */
    bool parse_command(beerocks::net::Buffer &buffer, std::string &command) override;
};

} // namespace beerocks

#endif /* _BEEROCKS_UCC_PARSER_MESSAGE_IMPL_H_ */
