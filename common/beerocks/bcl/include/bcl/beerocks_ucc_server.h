/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_UCC_SERVER_H_
#define _BEEROCKS_UCC_SERVER_H_

#include <functional>

namespace beerocks {

class UccServer {
public:
    /**
     * @brief Command-received event handler function.
     *
     * @param fd File descriptor of the socket connection the UCC command was received through.
     * @param command The UCC command received.
     */
    using CommandReceivedHandler = std::function<void(int fd, const std::string &command)>;

    /**
     * Default destructor.
     */
    virtual ~UccServer() = default;

    /**
     * @brief Sets the command-received event handler function.
     *
     * Sets the callback function to handle UCC commands received. Use nullptr to remove
     * previously installed callback function.
     *
     * If a handler is set, it will be called back whenever a UCC command is received at the
     * server.
     *
     * @param handler Command-received event handler function (or nullptr).
     */
    void set_command_received_handler(const CommandReceivedHandler &handler)
    {
        m_handler = handler;
    }

    /**
     * @brief Clears previously set command-received event handler function.
     *
     * Clears callback function previously set. Behaves like calling the set method with nullptr.
     */
    void clear_command_received_handler() { m_handler = nullptr; }

    /**
     * @brief Sends a reply string to a previously received UCC command.
     *
     * Sends a reply string to a client through the given socket connection.
     *
     * @param fd File descriptor of the socket connection to send reply string through.
     * @param reply The reply string to send.
     * @return true on success and false otherwise.
     */
    virtual bool send_reply(int fd, const std::string &reply) = 0;

protected:
    /**
     * @brief Notifies a command-received event.
     *
     * @param fd File descriptor of the socket connection the UCC command was received through.
     * @param command The UCC command received.
     */
    void notify_command_received(int fd, const std::string &command) const
    {
        if (m_handler) {
            m_handler(fd, command);
        }
    }

private:
    /**
     * CMDU-received event handler function that is called back whenever a CMDU message is received
     * at this server.
     */
    CommandReceivedHandler m_handler;
};

} // namespace beerocks

#endif // _BEEROCKS_UCC_SERVER_H_
