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

/**
 * @brief WPA Ctrl Command socket Class.
 *
 * This class derives from Base wpa_ctrl_socket class, and it is exclusively used for
 * sending request and receiving synchronous replies.
 */
class wpa_ctrl_socket_cmd : public wpa_ctrl_socket {
public:
    /**
     * @brief Constructor wpa_ctrl command socket object.
     *
     * @param[in] path The WPA Ctrl socket file path
     */
    explicit wpa_ctrl_socket_cmd(const std::string &path);

    /**
     * @brief Default destructor of wpa_ctrl command socket object.
     */
    virtual ~wpa_ctrl_socket_cmd() = default;

    /**
     * @brief Connect socket to hostapd/wpa_supplicant deamon.
     * This implementation implies opening the socket.
     *
     * @return True on success and false otherwise.
     */
    virtual bool connect() override;

    /**
     * @brief Disconnect socket from hostapd/wpa_supplicant deamon.
     * This implementation implies closing the socket.
     *
     * @param[in] force Enforce closing the socket.
     *
     * @return True on success and false otherwise.
     */
    virtual bool disconnect(bool force = false) override;

    /**
     * @brief Send request with synchronous reply, on wpa_ctrl socket.
     *
     * @param[in] cmd String to be sent over the opened socket.
     * @param[in/out] buffer Buffer data to be filled with received answer.
     * @param[in] buff_size Maximum data size to be saved in the buffer.
     *
     * @return True on success and false if:
     * - socket is not opened
     * - or sending failed
     * - or time outed while waiting for reply
     * - or received data size exceeds the buffer size
     */
    bool request(const std::string &cmd, char *buffer, size_t buff_size);
};

/**
 * @brief WPA Ctrl Event socket Class.
 *
 * This class derives from Base wpa_ctrl_socket class, and it is exclusively used for
 * receiving unsolicited events from hostapd/wpa_supplicant daemon
 */
class wpa_ctrl_socket_event : public wpa_ctrl_socket {
public:
    /**
     * @brief Constructor wpa_ctrl event socket object.
     *
     * @param[in] path The WPA Ctrl socket file path
     * @param[in] event_fds The list of file descriptors to be updated
     * for event monitoring
     */
    wpa_ctrl_socket_event(const std::string &path, std::vector<int> &event_fds);

    /**
     * @brief Custom destructor of wpa_ctrl event socket object.
     * It enforces socket disconnection.
     */
    virtual ~wpa_ctrl_socket_event();

    /**
     * @brief Opens and attach event socket to hostapd/wpa_supplicant deamon.
     *
     * @return True if socket is open and attached and false otherwise.
     */
    virtual bool connect() override;

    /**
     * @brief Detach and close event socket to hostapd/wpa_supplicant deamon.
     *
     * @param[in] force Enforce socket closing
     *
     * @return True if socket is detached and close (unless closing is enforced)
     * and false otherwise.
     */
    virtual bool disconnect(bool force = false) override;

    /**
     * @brief Checks whether the socket has pending data to be read.
     *
     * @return True if socket was attached and has pending data.
     */
    bool pending();

    /**
     * @brief Read available data on wpa_ctrl socket.
     *
     * @param[in/out] buffer Buffer data to be filled wit received data.
     * @param[in] buff_size Maximum data size to be saved in the buffer.
     *
     * @return True on success and false if:
     * - socket is not opened.
     * - or reading has failed or time outed.
     * - or received data size exceeds the buffer size .
     */
    bool receive(char *buffer, size_t buff_size);

private:
    /**
     * This boolean indicates if wpa_ctrl socket is actually attached
     * (subscribed) for receiving unsolicited events from daemon.
     */
    bool m_attached;

    /**
     * Reference to event queues list , with all monitored file descriptors.
     * This list is updated upon opening or closing eventing socket.
     */
    std::vector<int> &m_event_fds;

    /**
     * @brief Adds wpa_ctrl event socket to monitored event queues list.
     * If the file descriptor value is new (not found), it is set at first empty entry
     * (i.e equals -1) , or appended to the list.
     *
     * @param[in] fd File descriptor to be added in the list.
     *
     * @return void
     */
    void add_event_fd(int fd);

    /**
     * @brief Removes wpa_ctrl event socket from monitored event queues list.
     *
     * @param[in] fd File descriptor to be removed in the list.
     *
     * @return void
     */
    void del_event_fd(int fd);

    /**
     * @brief Opens wpa_ctrl event socket
     * and add the new file descriptor to event monitoring FDs queue.
     *
     * @return True if socket is open, false otherwise.
     */
    virtual bool open() override;

    /**
     * @brief Closes wpa_ctrl event socket
     * and remove the relative file descriptor from event monitoring FDs queue.
     *
     * @return void.
     */
    virtual void close() override;

    /**
     * @brief Attach the wpa_ctrl socket (i.e subscribe client)
     * to be notified with events from hostapd/wpa_supplicant daemon.
     *
     * @return True on success and when already attached.
     * false otherwise.
     */
    bool attach();

    /**
     * @brief Detach the wpa_ctrl socket (i.e unsubscribe client)
     * to stop receiving events from hostapd/wpa_supplicant daemon.
     *
     * @return True on success and when detached or closed.
     * false otherwise.
     */
    bool detach();
};

} // namespace nl80211
} // namespace bwl

#endif
