/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_ucc_parser_stream_impl.h>

#include <bcl/beerocks_utils.h>

#include <easylogging++.h>

namespace beerocks {

bool UccParserStreamImpl::parse_command(beerocks::net::Buffer &buffer, std::string &command)
{
    // Framing protocol consists of a Line Feed ("LF") character (0x0A, \n) added at the end of the
    // command. Check if that trailer exists.
    size_t length    = buffer.length();
    uint8_t *data    = buffer.data();
    uint8_t *last    = data + length;
    uint8_t *trailer = std::find(data, last, '\n');
    if (trailer == last) {
        LOG(DEBUG) << "Trailer not found, buffer length = " << length;

        // Just in case, clear buffer if it becomes full to let it store next commands to be
        // received.
        // This is never going to be required if everything works as expected (it would mean that
        // sender is sending a very large command, without a newline char at the end)
        if (length == buffer.size()) {
            buffer.clear();
        }

        return false;
    }

    // Replace trailer char with a terminating null char
    trailer[0] = '\0';

    // Build command string and trim white spaces from it
    command = reinterpret_cast<const char *>(data);
    beerocks::string_utils::trim(command);

    // Shift bytes remaining in buffer (i.e.: consume processed bytes and return bytes not
    // processed yet, if any)
    buffer.shift(command.length() + 1);

    return true;
}

} // namespace beerocks
