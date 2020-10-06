###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import re
from typing import Dict


'''Regular expression to match a MAC address in a bytes string.'''
RE_MAC = rb"(?P<mac>([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"


class MapClient:
    '''Represents a client (STA) in the connection map.'''

    def __init__(self, mac: str):
        self.mac = mac


class MapVap:
    '''Represents a VAP in the connection map.'''

    def __init__(self, bssid: str, ssid: bytes):
        self.bssid = bssid
        self.ssid = ssid
        self.clients = {}

    def add_client(self, mac: str):
        client = MapClient(mac)
        self.clients[mac] = client
        return client


class MapRadio:
    '''Represents a radio in the connection map.'''

    def __init__(self, uid: str):
        self.uid = uid
        self.vaps = {}

    def add_vap(self, bssid: str, ssid: bytes):
        vap = MapVap(bssid, ssid)
        self.vaps[bssid] = vap
        return vap


class MapDevice:
    '''Represents a device in the connection map.'''

    def __init__(self, mac: str):
        self.mac = mac
        self.radios = {}

    def add_radio(self, uid: str):
        radio = MapRadio(uid)
        self.radios[uid] = radio
        return radio
