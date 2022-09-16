#!/bin/sh
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

set -e
set -x


ssh -q glinet-b1300-1 "hostapd_cli -i wlan0 enable"
ssh -q glinet-b1300-2 "/etc/init.d/network restart"
ssh -q glinet-b1300-2 "ebtables -F"
ssh -q glinet-b1300-2 "ebtables -t nat -F"
ssh -q glinet-b1300-1 "ebtables -F"
ssh -q glinet-b1300-1 "ebtables -t nat -F"

