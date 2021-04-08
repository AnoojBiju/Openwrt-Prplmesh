###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

'''Model for devices in a Multi-AP network.

This models devices and the connectivity between them. It attempts to be as abstract as possible.
In addition to connectivity, it also models the quality of the connection, which allows us to
evaluate the quality of a chosen topology.

In addition to the somewhat static model of the connectivity between devices, the model also keeps
track of the chosen topology, i.e. which links are active for backhaul traffic. The model by itself
does no consistency checks of the topology (e.g. loops, disconnected, ...) but functions to do
these checks are provided.

The model is intended to be used as write-once: Devices and Links can be created, but not removed.
Instead, dynamics are modeled by changing link metric. Resetting the link metric is as good as
destroying the link.
'''

# It would probably be more efficient to make the model a simply symmetrical matrix of qualities,
# where each row/column represents a device and each cell represents a link. However, explicit
# objects make the model easier to understand.

import collections
from typing import NamedTuple


class Metric(NamedTuple):
    '''Model of the quality of a link.

    This is abstracted into a class to make easy to evaluate multiple metrics together (e.g.
    latency, throughput, load). For now, it's a simple bitrate.

    Attributes
    ----------
    bitrate_mbps: float
        The bitrate in millions of bits per second. If zero, this is equivalent to a link that is
        down/broken.
    '''
    bitrate_mbps: float


class Network:
    '''Model of the network.

    This is a collection of devices and links.

    By convention, the first device that is added to the network is considered the gateway.

    Attributes
    ----------
    devices: [Device]
        List of devices that belong to the network. The first device is the gateway.
    '''

    def __init__(self):
        self.devices = []

    def add_device(self):
        """Create a new device and add it to the network.

        The index is set automatically based on the number of devices already in the network.

        Returns
        -------
        Device
            The new device object.
        """
        device = Device(len(self.devices))
        self.devices.append(device)
        return device

    def add_devices_with_links(self, num_devices: int, metric: Metric) -> None:
        '''Create a number of devices, and links between them.

        A full set of (symmetrical) links between the devices will be created, all with the same
        metric.

        If devices exist already, no links will be created with the existing devices.
        '''
        new_devices = []
        for _ in range(num_devices):
            new_device = self.add_device()
            for device in new_devices:
                new_device.add_link(device, metric)
            new_devices.append(new_device)


class Device:
    '''Models a device in the Multi-AP network.

    Parameters
    ----------
    idx: int
        Device index, used to identify the device.

    Attributes
    ----------
    idx: int
        Device index, used to identify the device.
    links: {Device: [Link]}
        Links to/from this device. Links are always bidirectional. The links are organised as a
        dictionary with the other device as the key, to make it easier to look up the links
        between two devices. This attribute is updated automatically when a Link is created.
    bridged_links: {Link}
        Links that are currently included in the bridge, i.e. messages can be forwarded over these
        links.
    '''

    def __init__(self, idx: int):
        '''Create a device with no links.'''
        self.idx = idx
        self.links = collections.defaultdict(list)
        self.bridged_links = set()

    def add_link(self, other: 'Device', metric: Metric) -> 'Link':
        '''Create a link between this device and another device.'''
        return Link(self, other, metric)

    def neighbors(self) -> set('Device'):
        '''Get the neighbors of this device in the current topology.'''
        return {link.other(self) for link in self.bridged_links}

    def __repr__(self):
        return f"Device({self.idx})"


class Link:
    '''Models a link between two devices, as well as its metric.

    Loops (i.e. a link between a device and itself) are not allowed.

    Parameters
    ----------
    dev1, dev2: Device
        The devices between which the link exists. The order of the devices doesn't matter.
    metric: Metric
        The metric of the link.

    Attributes
    ----------
    network: Network
        The network to which the device belongs.
    devices: set[Device]
        The devices between which the link exists. Since this is symmetrical, and loops are not
        allowed, this is modeled as a set which always has two elements.
    metric: Metric
        The metric of the link.
    '''

    def __init__(self, dev1: Device, dev2: Device, metric: Metric):
        assert dev1 != dev2, "Self-link is not allowed"

        self.devices = {dev1, dev2}
        self.metric = metric

        dev1.links[dev2].append(self)
        dev2.links[dev1].append(self)

    def __repr__(self):
        d0, d1 = self.devices
        return f"link({d0}) <-> {d1})"

    def other(self, device: Device) -> Device:
        '''Get the other device on the link.'''
        assert device in self.devices, f"{device} is not on {self}"
        devices = set(self.devices)
        devices.discard(device)
        return devices.pop()
