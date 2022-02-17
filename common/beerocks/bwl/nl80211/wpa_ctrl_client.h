/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_WPA_CTRL_CLIENT_H_
#define _BWL_WPA_CTRL_CLIENT_H_

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

// Forward declaration
struct wpa_ctrl;

namespace bwl {
namespace nl80211 {

/**
 * @brief WPA Ctrl socket Class.
 *
 * This class implements all wpa_ctrl methods to open/close connections with running
 * hostapd/wpa_supplicant daemons, through a wpa_ctrl socket.
 */
class wpa_ctrl_socket {
public:
    /**
     * @brief Returns the wpa_ctrl socket file path.
     *
     * @return String.
     */
    const std::string &path() const;

    /**
     * @brief Returns the current wpa_ctrl socket file descriptor.
     *
     * @return int file descriptor or -1 if socket is not opened.
     */
    int fd() const;

    /**
     * @brief Abstract method:
     * Connect to hostapd/wpa_supplicant deamon.
     * This method has to be implemented with appropriate connection sequence.
     *
     * @return True on success and false otherwise.
     */
    virtual bool connect() = 0;

    /**
     * @brief Abstract method:
     * Disconnect from hostapd/wpa_supplicant deamon.
     * This interface has to be implemented with appropriate disconnection sequence.
     *
     * @param[in] force Indicates if socket must closed anyway at the end.
     *
     * @return True on success and false otherwise.
     */
    virtual bool disconnect(bool force = false) = 0;

protected:
    /**
     * @brief Base Constructor wpa_ctrl socket object.
     * This is intentionally protected to allow only instances of child classes.
     *
     * @param[in] path The WPA Ctrl socket file path
     *
     * @return
     */
    wpa_ctrl_socket(const std::string &path);

    /**
     * @brief Base Destructor of wpa_ctrl socket object.
     * This will close the socket and cleans all internal resources.
     *
     * @return
     */
    virtual ~wpa_ctrl_socket();

    /**
     * @brief Open wpa_ctrl socket.
     * Once successful, a new file descriptor is available for sending messages
     * hostapd/wpa_supplicant.
     *
     * @return True on success and when already opened,
     * and false otherwise.
     */
    virtual bool open();

    /**
     * @brief Close wpa_ctrl socket.
     * It also cleans/frees the internal resources used by wpa_ctrl socket
     *
     * @return void
     */
    virtual void close();

    /**
     * Pointer to wpa_ctrl client context, used to communicate with
     * hostapd/wpa_supplicant deamon.
     * It is allocate when opening the socket, and freed when closing it.
     */
    struct wpa_ctrl *m_ctx = nullptr;

    /**
     * Const value: maximum retries of time-outed buffer reading
     */
    static constexpr int WPA_CTRL_READ_RETRY_MAX = 3;

private:
    /**
     * Wpa_ctrl socket file path.
     */
    std::string m_path;
};

} // namespace nl80211
} // namespace bwl

#endif
