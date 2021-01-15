# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

from typing import Any, Union, Callable, NoReturn

from boardfarm.exceptions import SkipTest
from boardfarm.tests import bft_base_test
from capi import tlv
from opts import debug
import environment as env
import sniffer
import time


class PrplMeshBaseTest(bft_base_test.BftBaseTest):
    """PrplMesh base test case, no actual testing.

    Contains common methods used by other(derived) prplmesh test cases.
    """

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
