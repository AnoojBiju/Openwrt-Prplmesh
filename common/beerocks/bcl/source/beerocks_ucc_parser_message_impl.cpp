/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_ucc_parser_message_impl.h>

#include <bcl/beerocks_utils.h>

#include <easylogging++.h>

namespace beerocks {

bool UccParserMessageImpl::parse_command(beerocks::net::Buffer &buffer, std::string &command)
{
    // Append a terminating null char after the bytes received
    // If data were received through a stream-oriented socket, the command might not have been
    // fully received. It could also happen that more than one command had been received at once.
    // Since there is no framing protocol defined in the UCC communication, there is no way to
    // know or fix it.
    uint8_t null_termination_char[]{'\0'};
    if (!buffer.append(null_termination_char, sizeof(null_termination_char))) {
        LOG(ERROR) << "Command received is too large";
        return false;
    }

    // Build command string and trim white spaces from it
    command = reinterpret_cast<const char *>(buffer.data());
    beerocks::string_utils::trim(command);

    // Clear buffer as all bytes have been processed
    buffer.clear();

    return true;
}

} // namespace beerocks
