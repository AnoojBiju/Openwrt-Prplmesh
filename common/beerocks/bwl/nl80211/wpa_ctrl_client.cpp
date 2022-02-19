/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "wpa_ctrl_client.h"

#include <easylogging++.h>

extern "C" {
#include <wpa_ctrl.h>
}

namespace bwl {
namespace nl80211 {

wpa_ctrl_socket::wpa_ctrl_socket(const std::string &path) : m_path(path) {}

wpa_ctrl_socket::~wpa_ctrl_socket() { close(); }

const std::string &wpa_ctrl_socket::path() const { return m_path; }

bool wpa_ctrl_socket::open()
{
    if (m_ctx) {
        return true;
    }
    if (!(m_ctx = wpa_ctrl_open(m_path.c_str()))) {
        LOG(ERROR) << "wpa_ctrl_open() failed, ctrl_iface_path: " << m_path;
        return false;
    }
    LOG(DEBUG) << "WPA ctrl sock is opened with path " << m_path;
    return true;
}

void wpa_ctrl_socket::close()
{
    if (!m_ctx) {
        return;
    }
    wpa_ctrl_close(m_ctx);
    m_ctx = nullptr;
}

int wpa_ctrl_socket::fd() const
{
    if (!m_ctx) {
        LOG(DEBUG) << "WPA ctrl sock " << m_path << " not opened.";
        return -1;
    }
    return wpa_ctrl_get_fd(m_ctx);
}

wpa_ctrl_socket_cmd::wpa_ctrl_socket_cmd(const std::string &path) : wpa_ctrl_socket(path) {}

bool wpa_ctrl_socket_cmd::connect() { return open(); }

bool wpa_ctrl_socket_cmd::disconnect(bool force)
{
    close();
    return true;
}

bool wpa_ctrl_socket_cmd::request(const std::string &cmd, char *buffer, size_t buff_size)
{
    if (!m_ctx) {
        LOG(ERROR) << "Control socket not available!";
        return false;
    }

    int result;
    int try_cnt         = 0;
    auto buff_size_copy = buff_size;
    do {
        result = wpa_ctrl_request(m_ctx, cmd.c_str(), cmd.size(), buffer, &buff_size_copy, NULL);
    } while (result == -2 && ++try_cnt < WPA_CTRL_READ_RETRY_MAX);

    if (result < 0) {
        LOG(ERROR) << "can't send wpa_ctrl_request with cmd: " << cmd;
        return false;
    }

    if (buff_size_copy >= buff_size) {
        LOG(ERROR) << "wpa_ctrl_request returned reply of size " << buff_size_copy;
        return false;
    }

    // the wpa_ctrl does not put null terminator at the and of the string
    buffer[buff_size_copy] = 0;
    return true;
}

} // namespace nl80211
} // namespace bwl
