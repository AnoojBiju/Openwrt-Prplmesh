###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################


class MapClient:
    '''Represents a client (STA) in the connection map.'''

    def __init__(self, mac: str):
        self.mac = mac

    def __str__(self):
        return "      STA   {}".format(self.mac)


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

    def __str__(self):
        my_id = self.bssid + " " + self.ssid
        return "    BSS   " + '\n'.join([my_id] + [str(client) for client in self.clients.values()])


class MapRadio:
    '''Represents a radio in the connection map.'''

    def __init__(self, uid: str):
        self.uid = uid
        self.vaps = {}

    def add_vap(self, bssid: str, ssid: bytes):
        vap = MapVap(bssid, ssid)
        self.vaps[bssid] = vap
        return vap

    def __str__(self):
        return "  Radio " + '\n'.join([self.uid] + [str(vap) for vap in self.vaps.values()])


class MapDevice:
    '''Represents a device in the connection map.'''

    def __init__(self, mac: str):
        self.mac = mac
        self.radios = {}

    def add_radio(self, uid: str):
        radio = MapRadio(uid)
        self.radios[uid] = radio
        return radio

    def __str__(self):
        return "Agent " + '\n'.join([self.mac] + [str(radio) for radio in self.radios.values()])
