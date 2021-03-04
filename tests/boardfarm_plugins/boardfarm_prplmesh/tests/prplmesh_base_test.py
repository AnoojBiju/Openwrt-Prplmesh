# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from typing import Any, Dict, Union, Callable, NoReturn

from boardfarm.exceptions import SkipTest
from boardfarm.tests import bft_base_test
from capi import tlv
from opts import debug
import connmap
import environment as env
import sniffer
import time


class PrplMeshBaseTest(bft_base_test.BftBaseTest):
    """PrplMesh base test case, no actual testing.

    Contains common methods used by other(derived) prplmesh test cases.
    """

    def startMarker(self):
        """Calls method with the same name in base class and then prints current topology.

        To make sure all devices are always in a known state before the test starts, clears
        existing SSID configuration on all agents. If required, a particular test must configure
        the SSIDs for that test (as part of the test logic).

        This method is called right before the test.
        """
        super().startMarker()

        '''Clear existing SSID configuration on all agents.'''
        self.configure_ssids([])

        debug("Current network topology:")
        topology = self.get_topology()
        for value in topology.values():
            debug(value)

    def check_log(self, entity_or_radio: Union[env.ALEntity, env.Radio], regex: str,
                  start_line: int = 0, timeout: float = 0.6, fail_on_mismatch: bool = True) -> bool:
        result, line, match = entity_or_radio.wait_for_log(regex, start_line, timeout,
                                                           fail_on_mismatch=fail_on_mismatch)
        if fail_on_mismatch and not result:
            raise Exception
        return result, line, match

    def prplmesh_status_check(self, entity_or_radio: Union[env.ALEntity, env.Radio]) -> bool:
        """Check prplMesh status by executing status command to initd service.
        Return True if operational.
        """
        result = entity_or_radio.prprlmesh_status_check()
        if not result:
            raise Exception
        return result

    def check_cmdu(
        self, msg: str, match_function: Callable[[sniffer.Packet], bool]
    ) -> [sniffer.Packet]:
        """Verify that the wired_sniffer has captured a CMDU that satisfies match_function.

        Mark failure if no satisfying packet is found.

        Parameters
        ----------
        msg: str
            Message to show in case of failure. It is formatted in a context like
            "No CMDU <msg> found".

        match_function: Callable[[sniffer.Packet], bool]
            A function that returns True if it is the expected packet. It is called on every packet
            returned by get_packet_capture.

        Returns
        -------
        [sniffer.Packet]
            The matching packets.
        """
        debug("Checking for CMDU {}".format(msg))
        result = self.dev.DUT.wired_sniffer.get_cmdu_capture(match_function)
        assert result, "No CMDU {} found".format(msg)
        return result

    def check_cmdu_type(
        self, msg: str, msg_type: int, eth_src: str, eth_dst: str = None, mid: int = None
    ) -> [sniffer.Packet]:
        """Verify that the wired sniffer has captured a CMDU.

        Mark failure if the CMDU is not found.

        Parameters
        ----------
        msg: str
            Message to show in case of failure. It is formatted in a context like
            "No CMDU <msg> found".

        msg_type: int
            CMDU message type that is expected.

        eth_src: str
            MAC address of the sender that is expected.

        eth_dst: str
            MAC address of the destination that is expected. If omitted, the IEEE1905.1 multicast
            MAC address is used.

        mid: int
            Message Identifier that is expected. If omitted, the MID is not checked.

        Returns
        -------
        [sniffer.Packet]
            The matching packets.
        """
        debug("Checking for CMDU {} (0x{:04x}) from {} to {} mid {}"
              .format(msg, msg_type, eth_src,
                      eth_dst if eth_dst else "Multicast",
                      mid if mid else "Any"))
        result = self.dev.DUT.wired_sniffer.get_cmdu_capture_type(msg_type, eth_src, eth_dst, mid)
        assert result, "No CMDU {} found".format(msg)
        return result

    def check_cmdu_type_single(
        self, msg: str, msg_type: int, eth_src: str, eth_dst: str = None, mid: int = None
    ) -> sniffer.Packet:
        '''Like check_cmdu_type, but also check that only a single CMDU is found.'''
        debug("Checking for single CMDU {} (0x{:04x}) from {} to {} mid {}"
              .format(msg, msg_type, eth_src,
                      eth_dst if eth_dst else "Multicast",
                      mid if mid else "Any"))
        cmdus = self.check_cmdu_type(msg, msg_type, eth_src, eth_dst, mid)
        assert len(cmdus) == 1, \
            "Multiple CMDUs {} found:\n {}".format(msg, '\n'.join([str(cmdu) for cmdu in cmdus]))
        return cmdus[0]

    def check_no_cmdu_type(
        self, msg: str, msg_type: int, eth_src: str, eth_dst: str = None
    ) -> NoReturn:
        '''Like check_cmdu_type, but check that *no* machting CMDU is found.'''
        debug("Checking for no CMDU {} (0x{:04x}) from {}".format(msg, msg_type, eth_src))
        result = self.dev.DUT.wired_sniffer.get_cmdu_capture_type(msg_type, eth_src, eth_dst)
        if result:
            for packet in result:
                debug("  {}".format(packet))
            assert False, "Unexpected CMDU {}".format(msg)

    def check_cmdu_has_tlvs(
        self, packet: sniffer.Packet, tlv_type: int
    ) -> [sniffer.Tlv]:
        '''Check that the packet has at least one TLV of the given type.

        Mark failure if no TLV of that type is found.

        Parameters
        ----------
        packet: Union[sniffer.Packet]
            The packet to verify. If it is empty or it is not an IEEE1905
            packet, an AssertionError is raised.

        tlv_type: int
            The type of TLV to look for.

        Returns
        -------
        [sniffer.Tlv]
            List of TLVs of the requested type. An AssertionError is raised if
            no TLV is found.
        '''
        assert packet, "No packet found"
        assert packet.ieee1905, "Packet is not IEEE1905: {}".format(packet)
        tlvs = [tlv for tlv in packet.ieee1905_tlvs if tlv.tlv_type == tlv_type]
        if not tlvs:
            debug("  {}".format(packet))
            assert False, "No TLV of type 0x{:02x} found in packet".format(tlv_type)
        return tlvs

    def check_cmdu_has_tlv_single(
        self, packet: Union[sniffer.Packet, None], tlv_type: int
    ) -> sniffer.Tlv:
        '''Like check_cmdu_has_tlvs, but also check that only one TLV of that type is found.'''
        tlvs = self.check_cmdu_has_tlvs(packet, tlv_type)
        if len(tlvs) > 1:
            debug("  {}".format(packet))
            assert False, "More than one ({}) TLVs of type 0x{:02x} found".format(
                len(tlvs), tlv_type)
        return tlvs[0]

    def check_cmdu_has_tlvs_exact(
        self, packet: Union[sniffer.Packet, None], tlvs: [sniffer.Tlv]
    ) -> NoReturn:
        '''Check that the CMDU has exactly the TLVs given.'''
        assert packet, "Packet not found"
        assert packet.ieee1905, "Packet is not IEEE1905: {}".format(packet)

        packet_tlvs = list(packet.ieee1905_tlvs)
        for t in tlvs:
            if t in packet_tlvs:
                packet_tlvs.remove(t)
            else:
                assert False, "Packet misses tlv:\n {}".format(str(t))

        assert not packet_tlvs, "Packet has unexpected tlvs:\n {}".format(
            "\n ".join(map(str, packet_tlvs)))

    def check_cmdu_contains_tlvs(
        self, packet: Union[sniffer.Packet, None], tlvs: [sniffer.Tlv]
    ) -> NoReturn:
        '''Check that the CMDU contains the TLVs given.'''
        assert packet, "Packet not found"
        assert packet.ieee1905, "Packet is not IEEE1905: {}".format(packet)

        packet_tlvs = list(packet.ieee1905_tlvs)
        for t in tlvs:
            assert t in packet_tlvs, "Packet misses tlv:\n {}".format(str(t))

    def checkpoint(self) -> None:
        '''Checkpoint the current state.

        Any subsequent calls to functions that query cumulative state
        (e.g. log files, packet captures) will not match any of the state that was
        accumulated up till now, but only afterwards.

        TODO: Implement for log functions.
        '''
        self.dev.DUT.wired_sniffer.checkpoint()

    def fail(self, msg: str):
        '''Throw an exception message.'''
        FAIL = '\033[91m'
        END = '\033[0m'
        msg = FAIL + msg + END
        raise Exception(msg)

    def safe_check_obj_attribute(self, obj: object, attrib_name: str,
                                 expected_val: Any, fail_str: str) -> NoReturn:
        """Check if expected attrib exists first, fail test if it does not exist"""
        try:
            if getattr(obj, attrib_name) != expected_val:
                self.fail(fail_str)
        except AttributeError:
            self.fail("{} has no attribute {}".format(type(obj).__name__, attrib_name))

    def base_test_client_capability_query(self, sta: env.Station):
        try:
            agent = self.dev.DUT.agent_entity
            controller = self.dev.lan.controller_entity
        except AttributeError as ae:
            raise SkipTest(ae)

        mid = controller.ucc_socket.dev_send_1905(agent.mac, 0x8009, tlv(
            0x90, 0x000C, '{} {}'.format(agent.radios[0].mac, sta.mac)))

        time.sleep(1)

        query = self.check_cmdu_type_single("client capability query", 0x8009,
                                            controller.mac, agent.mac, mid)

        query_tlv = self.check_cmdu_has_tlv_single(query, 0x90)
        self.safe_check_obj_attribute(query_tlv, 'client_info_mac_addr', sta.mac,
                                      "Wrong mac address in query")
        self.safe_check_obj_attribute(query_tlv, 'client_info_bssid',
                                      agent.radios[0].mac,
                                      "Wrong bssid in query")

        report = self.check_cmdu_type_single("client capability report", 0x800a,
                                             agent.mac, controller.mac, mid)

        client_info_tlv = self.check_cmdu_has_tlv_single(report, 0x90)
        self.safe_check_obj_attribute(client_info_tlv, 'client_info_mac_addr', sta.mac,
                                      "Wrong mac address in report")
        self.safe_check_obj_attribute(client_info_tlv, 'client_info_bssid',
                                      agent.radios[0].mac,
                                      "Wrong bssid in report")
        return report

    def get_device_by_name(self, device_name: str) -> env.ALEntity:
        try:
            return [_.obj for _ in self.dev.devices if _.obj.name == device_name][0]
        except IndexError as ae:
            raise SkipTest(ae)

    def check_topology_notification(self, eth_src: str, neighbors: list,
                                    sta: env.Station, event: env.StationEvent, bssid: str) -> bool:
        """Verify topology notification reliable multicast - given a source mac and
           a list of neighbors macs, check that exactly one relayed multicast CMDU
           was sent to the IEEE1905.1 multicast MAC address, and a single unicast
           CMDU with the relayed bit unset to each of the given neighbors destination MACs.
           Verify correctness of the association event TLV inside the topology notification.
           Mark failure if any of the above conditions isn't met.

        Parameters
        ----------

        eth_src: str
            source AL MAC (origin of the topology notification)

        neighbors: list
            destination AL MACs (destinations of the topology notification)

        sta: environment.Station
            station mac

        event: environment.StationEvent
            station event - CONNECTED / DISCONNECTED

        bssid: str
            bssid Multi-AP Agent BSSID

        Returns:
        bool
            True for valid topology notification, False otherwise
        """
        mcast = self.check_cmdu_type_single("topology notification", 0x1, eth_src)

        # relay indication should be set
        if not mcast.ieee1905_relay_indicator:
            self.fail("Multicast topology notification should be relayed")
            return False

        mid = mcast.ieee1905_mid
        for eth_dst in neighbors:
            ucast = self.check_cmdu_type_single("topology notification",
                                                0x1, eth_src, eth_dst, mid)
            if ucast.ieee1905_relay_indicator:
                self.fail("Unicast topology notification should not be relayed")
                return False

        # check for requested event
        debug("Check for event: sta mac={}, bssid={}, event={}".format(sta.mac, bssid, event))
        if mcast.ieee1905_tlvs[0].assoc_event_client_mac != sta.mac or \
                mcast.ieee1905_tlvs[0].assoc_event_agent_bssid != bssid or \
                int(mcast.ieee1905_tlvs[0].assoc_event_flags, 16) != event.value:
            self.fail("No match for association event")
            return False

        return True

    def get_topology(self) -> Dict[str, connmap.MapDevice]:
        '''Get the topology.

        Returns a list of devices, the rest of the topology is a tree under it.

        Uses the northbound API to get this information.
        '''
        controller = self.dev.lan.controller_entity

        devices = controller.nbapi_get_instances("Controller.Network.Device")
        map_devices = {}
        for name, device in devices.items():
            map_device = connmap.MapDevice(device["ID"])
            map_device.path = "Controller.Network.Device." + name[:-1]  # strip trailing .
            map_devices[map_device.mac] = map_device
            radios = controller.nbapi_get_instances(map_device.path + ".Radio")
            for radio_name, radio in radios.items():
                map_radio = map_device.add_radio(radio["ID"])
                map_radio.path = map_device.path + ".Radio." + radio_name[:-1]  # strip trailing .
                bsses = controller.nbapi_get_instances(map_radio.path + ".BSS")
                for bss_name, bss in bsses.items():
                    map_vap = map_radio.add_vap(bss["BSSID"], bss["SSID"])
                    map_vap.path = map_radio.path + ".BSS." + bss_name[:-1]  # strip trailing .
                    stas = controller.nbapi_get_instances(map_vap.path + ".STA")
                    for sta_name, sta in stas.items():
                        map_client = map_vap.add_client(sta["MACAddress"])
                        map_client.path = map_vap.path + ".STA." + sta_name[:-1]  # strip trailing .
            interfaces = controller.nbapi_get_instances(map_device.path + ".Interface")
            for interface_name, interface in interfaces.items():
                map_interface = map_device.add_interface(interface["MACAddress"])
                # strip trailing .
                map_interface.path = map_device.path + ".Interface." + interface_name[:-1]
                neighbors = controller.nbapi_get_instances(map_interface.path + ".Neighbor")
                for neighbor_name, neighbor in neighbors.items():
                    map_neighbor = map_interface.add_neighbor(neighbor["ID"])
                    map_neighbor.path = map_interface.path + \
                        ".Neighbor." + neighbor_name[:-1]  # str
        return map_devices

    def configure_ssids_clear(self):
        '''Clear the SSID configuration.

        Removes all Controller.Network.AccessPoint instances in the northbound API.
        '''
        controller = self.dev.lan.controller_entity
        access_points = controller.nbapi_get_instances('Controller.Network.AccessPoint')
        for name, access_point in access_points.items():
            controller.nbapi_command('Controller.Network.AccessPoint', 'del', {'name': name})

    def configure_ssid(self, ssid: str, multi_ap_mode: str = "Fronthaul",
                       bands: Dict = None) -> str:
        '''Configure an SSID.

        Adds a Controller.Network.AccessPoint instance and configures it with the given SSID,
        bands and multi AP mode.
        If parameter 'bands' was not passed the SSID will be enabled on all bands.
        If one of the band was not specified its value will be set to false.
        The value of 'multi_ap_mode' can be one of "Fronthaul","Backhaul","Fronthaul+Backhaul".
        By default, multi AP mode set as fronthaul-only in open mode.

        Parameters
        ----------
        ssid: str
            The SSID to configure.

        Returns
        -------
        str
            Path to the Controller.Network.AccessPoint instance.
        '''
        if not bands:
            bands = {"Band5GH": True, "Band6G":  True, "Band5GL": True, "Band2_4G": True}

        controller = self.dev.lan.controller_entity
        params = {"parameters": {
            "MultiApMode": multi_ap_mode,
            "Band5GH": bands.get("Band5GH", False),
            "Band6G": bands.get("Band6G", False),
            "Band5GL": bands.get("Band5GL", False),
            "Band2_4G": bands.get("Band2_4G", False),
            "SSID": ssid,
        }}
        new_inst = controller.nbapi_command("Controller.Network.AccessPoint", "add", params)
        return "Controller.Network.AccessPoint." + new_inst["name"]

    def configure_ssids(self, ssids: [str], clear_old: bool = True):
        '''Configure SSIDs on all agents.

        Configure all radios on all agents with the given set of ssids. They
        are configured as fronthaul-only, in open mode.

        If clear_old is True, the existing configuration is cleared first. By
        setting it to false, it is possible to add more complicated custom
        configuration first and then call configure_ssids for the simple SSIDs.

        After configuration completes, check that all agents have been updated.

        Uses northbound API.

        Parameters
        ---------
        ssid: [str]
            List of SSIDs to configure. Each SSID will configure an additional
            VAP on the radios.

        clear_old: bool
            If True (default), the existing configuration is cleared before
            adding new SSIDs.
        '''
        if clear_old:
            self.configure_ssids_clear()
        for ssid in ssids:
            self.configure_ssid(ssid)

        self.dev.lan.controller_entity.nbapi_command("Controller.Network", "AccessPointCommit")
        # TODO check that renew was sent to all agents
        # TODO check that all agents have been configured with the SSIDs
        time.sleep(5)  # Temporary until above TODOs are fixed

    @classmethod
    def teardown_class(cls):
        """Teardown method, optional for boardfarm tests."""

        test = cls.test_obj

        for dev in test.dev:
            if dev.model in ['prplWRT_STA', 'STA_dummy'] and dev.associated_vap:
                dev.wifi_disconnect(dev.associated_vap)

        print("Sniffer - stop")
        test.dev.DUT.wired_sniffer.stop()
        # Send additional Ctrl+C to the device to terminate "tail -f"
        # Which is used to read log from device. Required only for tests on HW
        try:
            test.dev.DUT.agent_entity.device.send('\003')
        except AttributeError:
            # If AttributeError was raised - we are dealing with dummy devices.
            # We don't have to additionaly send Ctrl+C for dummy devices.
            pass
