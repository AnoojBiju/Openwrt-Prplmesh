###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

from devices import Device, Link, Message
import logging
from sim import Algorithm, Simulation, Tick, send_msg
from typing import Callable, Optional


class AlgPingController(Algorithm):
    """Ping the controller regularly to detect network breakage.

    This algorithm regularly sends a message to the controller. If no reply is received, the
    network is considered broken and a callback is called to handle this situation. The same
    callback is also called when the controller can be reached again.

    This algorithm adds two attributes to the devices it controls:

    ping_status: bool
        True if the last ping received a reply, False if the last ping timed out.
    ping_received_pong: bool
        Used to determine if timeout occurred. Set to False when a ping is sent, set to True when
        pong is received.

    Parameters
    ----------
    interval: Tick
        Ping interval. The ping message is sent every so many ticks.
    simulation: Simulation
        The Simulation to which this algorithm belongs. Used for creating events.
    handler: Callable[Tick, Device, Simulation, bool]
        Handler for reachable state change. It is called once when the controller is no longer
        reachable, and again when the controller is reachable again. First argument Tick is the
        tick at which this is detected. Second argument Device is the device on which the algorithm
        runs. Third argument Simulation is the simulation. Fourth argument bool is True if the
        controller is reachable, False if it is not. So if the controller becomes unreachable at
        tick 5 and reachable again at tick 10, the callback is called at tick 5 with fourth argument
        False, and at tick 10 with fourth argument True.
    timeout: Tick, default 1s
        How long before a reply is expected. If no reply was received after this time, the network
        is considered broken.
    """

    def __init__(self, interval: Tick, simulation: Simulation,
                 handler: Callable[[Tick, Device, Simulation, bool], None],
                 timeout: Tick = Tick.s(1)):
        self.interval = interval
        self.timeout = timeout
        self.handler = handler
        self._seqno = 0  # Note that this is shared between all devices, but it's just an ID so OK.
        super().__init__("PingController", simulation)

    def _ping_timeout(self, when: Tick, device: Device, seqno: int):
        """Handle ping timeout."""
        controller = self.simulation.network.devices[0]
        # Controller doesn't send ping
        if device != controller:
            if not device.ping_received_pong:
                if device.ping_status:
                    logging.info(f"@{when} Ping {seqno} timeout for {device}")
                    self.handler(when, device, self.simulation, False)
                    device.ping_status = False

    def _send_ping(self, when: Tick, device: Device, description: str):
        """Send a ping to the controller.

        The description parameter is just there to use this function as a timeout handler.
        """
        controller = self.simulation.network.devices[0]
        # Controller doesn't send ping
        if device != controller:
            msg = Message('Ping', self._seqno)
            send_msg(msg, device, controller, self.simulation)

            self.set_timeout(when + self.interval, device, self._send_ping, description)
            device.ping_received_pong = False
            self.set_timeout(when + self.timeout, device, self._ping_timeout, self._seqno)
            self._seqno += 1

    def start(self, when: Tick, device: Device):
        device.ping_status = True  # The handler should be triggered if initially disconnected.
        self._send_ping(when, device, 'Ping')

    def handle_message(self, when: Tick, device: Device, message: Message, src: Device,
                       dst: Optional[Device], src_link: Optional[Link]):
        msg_type, seqno = message
        controller = self.simulation.network.devices[0]
        if device == controller:
            if msg_type == 'Pong':
                logging.warning(f"{when}: Pong received by controller {device}.")
                return
            if msg_type != 'Ping':
                # Ignore non ping-pong messages
                return
            logging.info(f"{when}: Send pong {seqno} to {src}")
            send_msg(Message('Pong', seqno), device, src, self.simulation)
        else:
            if msg_type == 'Ping':
                logging.warning(f"{when}: Ping received by non-controller {device}.")
                return
            if msg_type != 'Pong':
                # Ignore non ping-pong messages
                return
            logging.debug(f"{when}: {device} received Pong")
            device.ping_received_pong = True
            if not device.ping_status:
                self.handler(when, device, self.simulation, True)
                device.ping_status = True
