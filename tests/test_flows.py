#! /usr/bin/env python3
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import argparse
import os
import sys
import time
import traceback
from typing import Callable, Union, Any, NoReturn

import environment as env
from capi import tlv
from opts import debug, err, message, opts, status
import sniffer


class TestFlows:
    def __init__(self):
        self.tests = [attr[len('test_'):] for attr in dir(self) if attr.startswith('test_')]
        self.running = ''

    def __fail_no_message(self) -> bool:
        '''Increment failure count and return False.'''
        self.check_error += 1
        if opts.stop_on_failure:
            sys.exit(1)
        return False

    def fail(self, msg: str) -> bool:
        '''Print a red error message, increment failure count and return False.'''
        err('FAIL: {}'.format(msg))
        return self.__fail_no_message()

    def start_test(self, test: str):
        '''Call this at the beginning of a test.'''
        self.running = test
        status(test + " starting")

    def check_log(self, entity_or_radio: Union[env.ALEntity, env.Radio], regex: str,
                  start_line: int = 0, fail_on_mismatch: bool = True) -> bool:
        '''Verify that the log-file for "entity_or_radio" matches "regex",
           fail if no match is found when "fail_on_mismatch" is enabled.
        '''
        return self.wait_for_log(entity_or_radio, regex, start_line, 0.3,
                                 fail_on_mismatch=fail_on_mismatch)

    def wait_for_log(self, entity_or_radio: Union[env.ALEntity, env.Radio], regex: str,
                     start_line: int, timeout: float, fail_on_mismatch: bool = True) -> bool:
        result, line, match = entity_or_radio.wait_for_log(regex, start_line, timeout,
                                                           fail_on_mismatch=fail_on_mismatch)
        if fail_on_mismatch and (not result):
            self.__fail_no_message()
        return result, line, match

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
        result = env.wired_sniffer.get_cmdu_capture(match_function)
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
        debug("Checking for CMDU {} (0x{:04x}) from {}".format(msg, msg_type, eth_src))
        result = env.wired_sniffer.get_cmdu_capture_type(msg_type, eth_src, eth_dst, mid)
        assert result, "No CMDU {} found".format(msg)
        return result

    def check_cmdu_type_single(
        self, msg: str, msg_type: int, eth_src: str, eth_dst: str = None, mid: int = None
    ) -> sniffer.Packet:
        '''Like check_cmdu_type, but also check that only a single CMDU is found.'''
        debug("Checking for single CMDU {} (0x{:04x}) from {}".format(msg, msg_type, eth_src))
        cmdus = self.check_cmdu_type(msg, msg_type, eth_src, eth_dst, mid)
        if not cmdus:
            assert False  # Failure already reported by check_cmdu
        if len(cmdus) > 1:
            self.fail("Multiple CMDUs {} found".format(msg))
            assert False
        return cmdus[0]

    def check_no_cmdu_type(
        self, msg: str, msg_type: int, eth_src: str, eth_dst: str = None
    ) -> [sniffer.Packet]:
        '''Like check_cmdu_type, but check that *no* machting CMDU is found.'''
        debug("Checking for no CMDU {} (0x{:04x}) from {}".format(msg, msg_type, eth_src))
        result = env.wired_sniffer.get_cmdu_capture_type(msg_type, eth_src, eth_dst)
        if result:
            self.fail("Unexpected CMDU {}".format(msg))
            for packet in result:
                debug("  {}".format(packet))
            assert False
        return result

    def check_cmdu_has_tlvs(
        self, packet: sniffer.Packet, tlv_type: int
    ) -> [sniffer.Tlv]:
        '''Check that the packet has at least one TLV of the given type.

        Mark failure if no TLV of that type is found.

        Parameters
        ----------
        packet: Union[sniffer.Packet, None]
            The packet to verify. It may also be None, to make it easy to let it follow
            check_cmdu_type_single. If it is None, no failure is raised. If it is not an IEEE1905
            packet, a failure *is* raised.

        tlv_type: int
            The type of TLV to look for.

        Returns
        -------
        [sniffer.Tlv]
            List of TLVs of the requested type. Empty list if the check fails.
        '''
        if not packet:
            return []  # No additional failure, assumed to already have been raised
        if not packet.ieee1905:
            self.fail("Packet is not IEEE1905: {}".format(packet))
            return []
        tlvs = [tlv for tlv in packet.ieee1905_tlvs if tlv.tlv_type == tlv_type]
        if not tlvs:
            self.fail("No TLV of type 0x{:02x} found in packet".format(tlv_type))
            debug("  {}".format(packet))
            assert False
        return tlvs

    def check_cmdu_has_tlv_single(
        self, packet: Union[sniffer.Packet, None], tlv_type: int
    ) -> sniffer.Tlv:
        '''Like check_cmdu_has_tlvs, but also check that only one TLV of that type is found.'''
        tlvs = self.check_cmdu_has_tlvs(packet, tlv_type)
        if not tlvs:
            assert False
        if len(tlvs) > 1:
            self.fail("More than one ({}) TLVs of type 0x{:02x} found".format(len(tlvs), tlv_type))
            debug("  {}".format(packet))
            assert False
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

    def safe_check_obj_attribute(self, obj: object, attrib_name: str,
                                 expected_val: Any, fail_str: str) -> NoReturn:
        """Check if expected attrib exists first, fail test if it does not exist"""
        try:
            if getattr(obj, attrib_name) != expected_val:
                self.fail(fail_str)
        except AttributeError:
            self.fail("{} has no attribute {}".format(type(obj).__name__, attrib_name))

    def run_tests(self, tests):
        '''Run all tests as specified on the command line.'''
        total_errors = 0
        if not tests:
            tests = self.tests
        for test in tests:
            test_full = 'test_' + test
            self.start_test(test)
            env.wired_sniffer.start(test_full)
            self.check_error = 0
            try:
                getattr(self, test_full)()
            except AssertionError as ae:
                # do not add empty message if test has already been marked as failed
                # and AssertionError does not contain a message
                if str(ae):
                    self.fail("{}".format(ae))
                elif not self.check_error:
                    self.fail("Assertion failed\n{}"
                              .format(traceback.format_exc()))

            except Exception as e:
                self.fail("Test failed unexpectedly: {}\n{}"
                          .format(e.__repr__(), traceback.format_exc()))
            finally:
                env.wired_sniffer.stop()
            if self.check_error != 0:
                err(test + " failed")
            else:
                message(test + " OK", 32)
            total_errors += self.check_error
        return total_errors

    # TEST DEFINITIONS #

    def test_ap_config_bss_tear_down(self):
        # Configure the controller and send renew
        env.controller.cmd_reply("DEV_RESET_DEFAULT")
        env.controller.cmd_reply(
            "DEV_SET_CONFIG,bss_info1,"
            "{} 8x Multi-AP-24G-3 0x0020 0x0008 maprocks1 0 1".format(env.agents[0].mac))
        env.controller.dev_send_1905(env.agents[0].mac, 0x000A,
                                     tlv(0x01, 0x0006, "{" + env.controller.mac + "}"),
                                     tlv(0x0F, 0x0001, "{0x00}"),
                                     tlv(0x10, 0x0001, "{0x00}"))

        # Wait a bit for the renew to complete
        time.sleep(3)

        self.check_log(env.agents[0].radios[0],
                       r"Received credentials for ssid: Multi-AP-24G-3 .*"
                       r"fronthaul: true backhaul: false")
        self.check_log(env.agents[0].radios[1], r".* tear down radio")
        conn_map = env.controller.get_conn_map()
        repeater1 = conn_map[env.agents[0].mac]
        repeater1_wlan0 = repeater1.radios[env.agents[0].radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid not in (b'Multi-AP-24G-3', b'N/A'):
                self.fail('Wrong SSID: {vap.ssid} instead of Multi-AP-24G-3'.format(vap=vap))
        repeater1_wlan2 = repeater1.radios[env.agents[0].radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

        # SSIDs have been removed for the CTT Agent1's front radio
        env.controller.cmd_reply(
            "DEV_SET_CONFIG,bss_info1,{} 8x".format(env.agents[0].mac))
        # Send renew message
        env.controller.dev_send_1905(env.agents[0].mac, 0x000A,
                                     tlv(0x01, 0x0006, "{" + env.controller.mac + "}"),
                                     tlv(0x0F, 0x0001, "{0x00}"),
                                     tlv(0x10, 0x0001, "{0x00}"))

        time.sleep(3)
        self.check_log(env.agents[0].radios[0], r".* tear down radio")
        conn_map = env.controller.get_conn_map()
        repeater1 = conn_map[env.agents[0].mac]
        repeater1_wlan0 = repeater1.radios[env.agents[0].radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))
        repeater1_wlan2 = repeater1.radios[env.agents[0].radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

    def test_ap_config_bss_tear_down_cli(self):
        # Same test as the previous one but using CLI instead of dev_send_1905

        env.beerocks_cli_command('bml_clear_wifi_credentials {}'.format(env.agents[0].mac))
        env.beerocks_cli_command('bml_set_wifi_credentials {} {} {} {} {}'
                                 .format(env.agents[0].mac,
                                         "Multi-AP-24G-3-cli", "maprocks1", "24g", "fronthaul"))
        env.beerocks_cli_command('bml_update_wifi_credentials {}'.format(env.agents[0].mac))

        # Wait a bit for the renew to complete
        time.sleep(3)

        self.check_log(env.agents[0].radios[0],
                       r"Received credentials for ssid: Multi-AP-24G-3-cli .*"
                       r"fronthaul: true backhaul: false")
        self.check_log(env.agents[0].radios[1], r".* tear down radio")
        conn_map = env.controller.get_conn_map()
        repeater1 = conn_map[env.agents[0].mac]
        repeater1_wlan0 = repeater1.radios[env.agents[0].radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid not in (b'Multi-AP-24G-3-cli', b'N/A'):
                self.fail('Wrong SSID: {vap.ssid} instead of Multi-AP-24G-3-cli'.format(vap=vap))
        repeater1_wlan2 = repeater1.radios[env.agents[0].radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

        env.beerocks_cli_command('bml_clear_wifi_credentials {}'.format(env.agents[0].mac))
        env.beerocks_cli_command('bml_update_wifi_credentials {}'.format(env.agents[0].mac))

        time.sleep(3)
        self.check_log(env.agents[0].radios[0], r".* tear down radio")
        conn_map = env.controller.get_conn_map()
        repeater1 = conn_map[env.agents[0].mac]
        repeater1_wlan0 = repeater1.radios[env.agents[0].radios[0].mac]
        for vap in repeater1_wlan0.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))
        repeater1_wlan2 = repeater1.radios[env.agents[0].radios[1].mac]
        for vap in repeater1_wlan2.vaps.values():
            if vap.ssid != b'N/A':
                self.fail('Wrong SSID: {vap.ssid} instead torn down'.format(vap=vap))

    def test_multi_ap_policy_config_w_steering_policy(self):
        debug("Send multi-ap policy config request with steering policy to agent 1")
        mid = env.controller.dev_send_1905(env.agents[0].mac, 0x8003,
                                             tlv(0x89, 0x000C, "{0x00 0x00 0x01 {%s 0x01 0xFF 0x14}}" % env.agents[0].radios[0].mac))  # noqa E501
        time.sleep(1)
        debug("Confirming multi-ap policy config request has been received on agent")

        self.check_log(env.agents[0], r"MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE")
        time.sleep(1)
        debug("Confirming multi-ap policy config ack message has been received on the controller")
        self.check_log(env.controller, r"ACK_MESSAGE, mid=0x{:04x}".format(mid))

    def send_and_check_policy_config_metric_reporting(self, agent, include_sta_traffic_stats=True,
                                                      include_sta_link_metrics=True):
        debug("Send multi-ap policy config request with metric reporting policy to agent")
        reporting_value = 0
        if include_sta_traffic_stats:
            reporting_value |= 0x80
        if include_sta_link_metrics:
            reporting_value |= 0x40
        radio_policies = ["{%s 0x00 0x00 0x01 0x%02x}" % (radio.mac, reporting_value)
                          for radio in agent.radios]
        metric_reporting_tlv = tlv(0x8a, 2 + 10 * len(radio_policies),
                                   "{0x00 0x%02x %s}" % (len(radio_policies),
                                                         " ".join(radio_policies)))
        mid = env.controller.dev_send_1905(agent.mac, 0x8003, metric_reporting_tlv)
        time.sleep(1)
        debug("Confirming multi-ap policy config request was acked by agent")
        self.check_cmdu_type_single("ACK", 0x8000, agent.mac, env.controller.mac, mid)

    def test_multi_ap_policy_config_w_metric_reporting_policy(self):
        self.send_and_check_policy_config_metric_reporting(env.agents[0], True, True)

    def configure_multi_ap_policy_config_with_unsuccessful_association(
            self, enable: 0x80, max_repeat: 0x0A):
        debug("Send multi-ap policy config request with unsuccessful association policy to agent 1")
        mid = env.controller.dev_send_1905(env.agents[0].mac, 0x8003,
                                           tlv(0xC4, 0x0005, "{{0x{:02X} 0x{:08X}}}"
                                               .format(enable, max_repeat)))
        time.sleep(1)
        debug("Confirming multi-ap policy config with unsuccessful association"
              "request has been received on agent")

        self.check_log(env.agents[0], r"MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE")
        time.sleep(1)
        debug("Confirming multi-ap policy config ack message has been received on the controller")
        self.check_cmdu_type_single("ACK", 0x8000, env.agents[0].mac, env.controller.mac, mid)

    def test_multi_ap_policy_config_w_unsuccessful_association(self):
        self.configure_multi_ap_policy_config_with_unsuccessful_association(0x80, 0x01)
        self.mismatch_psk()

    def test_higher_layer_data_payload_trigger(self):
        mac_gateway_hex = '0x' + env.controller.mac.replace(':', '')
        debug("mac_gateway_hex = " + mac_gateway_hex)
        payload = 199 * (mac_gateway_hex + " ") + mac_gateway_hex

        debug("Send Higher Layer Data message")
        # MCUT sends Higher Layer Data message to CTT Agent1 by providing:
        # Higher layer protocol = "0x00"
        # Higher layer payload = 200 concatenated copies of the ALID of the MCUT (1200 octets)
        mid = env.controller.dev_send_1905(env.agents[0].mac, 0x8018,
                                           tlv(0xA0, 0x04b1, "{0x00 %s}" % payload))

        debug("Confirming higher layer data message was received in one of the agent's radios")

        received_in_radio0, _, _ = self.check_log(env.agents[0].radios[0],
                                                  r"HIGHER_LAYER_DATA_MESSAGE",
                                                  fail_on_mismatch=False)
        received_in_radio1, _, _ = self.check_log(env.agents[0].radios[1],
                                                  r"HIGHER_LAYER_DATA_MESSAGE",
                                                  fail_on_mismatch=False)

        number_of_receiving_radios = int(received_in_radio0) + int(received_in_radio1)
        if (number_of_receiving_radios != 1):
            self.fail(f"higher layer data message was received and acknowledged by "
                      f"{number_of_receiving_radios} agent's radios, "
                      f"expected exactly 1")

        received_agent_radio = (env.agents[0].radios[0] if received_in_radio0
                                else env.agents[0].radios[1])

        debug("Confirming matching protocol and payload length")
        self.check_log(received_agent_radio, r"Protocol: 0")
        self.check_log(received_agent_radio, r"Payload-Length: 0x4b0")

        debug("Confirming ACK message was received in the controller")
        self.check_log(env.controller, r"ACK_MESSAGE, mid=0x{:04x}".format(mid))

    def test_topology(self):
        mid = env.controller.dev_send_1905(env.agents[0].mac, 0x0002)
        debug("Confirming topology query was received")
        self.check_log(env.agents[0], r"TOPOLOGY_QUERY_MESSAGE.*mid=0x{:x}".format(mid))

    def test_beacon_report_query(self):
        # associated STA
        sta = env.Station.create()

        # for testing non existing STA, when want to test the error flow
        # sta1 = env.Station.create()

        debug("Connect dummy STA (" + sta.mac + ") to wlan0")
        env.agents[0].radios[0].vaps[0].associate(sta)

        # send beacon query request
        # (please take a look at https://github.com/prplfoundation/prplMesh/issues/1272)
        debug("Sending beacon report query to repeater:")
        request = '{mac} '.format(mac=sta.mac)
        request += '0x73 0xFF 0xFFFFFFFFFFFF 0x02 0x00 0x01 0x02 0x73 0x24 0x30 0x00'

        debug(request)
        mid = env.controller.dev_send_1905(env.agents[0].mac, 0x8011,
                                           tlv(0x99, 0x0016, "{" + request + "}"))

        self.check_log(env.agents[0],
                       r"BEACON METRICS QUERY: "
                       r"sending ACK message to the originator mid: 0x{:x}".format(mid))

        # this line is printed in the monitor log - however currently there is no way to test it -
        # self.check_log(env.agents[0].radios[0].???,
        #                r"inserting 1 RRM_EVENT_BEACON_REP_RXED event(s) to the pending list")
        env.agents[0].radios[0].vaps[0].disassociate(sta)

    def validate_tunnelled_frame(self, agent_mac, sta_mac, payload_type, payload_data):
        '''Validates the CMDU of Controller reception of the tennulled frame.'''

        # Validate "Tunnelled Message" CMDU was sent
        response = self.check_cmdu_type_single(
            "Tunnelled Message", 0x8026, agent_mac, env.controller.mac)

        # This function validates R2 messages, which are not yet defined
        # in tshark 2.6.x which is the default version in Ubuntu 18.04.
        # Undefined message values are stored in "tlv_data" attributes.
        # tshark 3.x (Ubuntu 20.04) fully recognizes these messages.
        # In order to support both versions, this function checks if the
        # fully named attribute is available. If not, it simply reads the
        # value from the generic "tlv_data" attribute.

        debug("Check Tunnelled Message has valid Source Info TLV")
        tlv_source_info = self.check_cmdu_has_tlv_single(response, 0xc0)
        if hasattr(tlv_source_info, 'source_info_tunneled_source_mac_address'):
            source_sta_mac = tlv_source_info.source_info_tunneled_source_mac_address
        else:
            source_sta_mac = tlv_source_info.tlv_data

        # Validate Srouce Info STA MAC
        if source_sta_mac != sta_mac:
            self.fail("Source Info TLV has wrong STA MAC {} instead of {}".format(
                source_sta_mac, sta_mac))

        debug("Check Tunnelled Message has valid Type TLV")
        tlv_type = self.check_cmdu_has_tlv_single(response, 0xc1)
        if hasattr(tlv_type, 'tunneled_message_type_tunneled_payload_type'):
            source_payload_type = int(tlv_type.tunneled_message_type_tunneled_payload_type, 16)
        else:
            source_payload_type = int(tlv_type.tlv_data, 16)

        if source_payload_type != payload_type:
            self.fail("Type TLV has wrong value of {} instead of {}".format(
                source_payload_type, payload_type))

        debug("Check Tunnelled Message has valid Data TLV")
        tlv_data = self.check_cmdu_has_tlv_single(response, 0xc2)
        if hasattr(tlv_type, 'tunneled_message_type_tunneled_payload_type'):
            source_payload = tlv_data.tunneled_tunneled_protocol_payload.replace(":", "")
        else:
            source_payload = tlv_data.tlv_data.replace(":", "")

        if source_payload.lower() != payload_data.lower():
            self.fail("Type TLV has wrong value of {} instead of {}".format(
                source_payload, payload_data))

        debug("Confirming Tunnelled Message was received on the Controller")
        self.check_log(
            env.controller, r"Received Tunnelled Message from {}".format(agent_mac))
        self.check_log(
            env.controller, r"Tunnelled Message STA MAC: {}, Type: 0x{:x}".format(
                sta_mac, payload_type))

    def test_tunnelled_frames(self):
        '''Associate a STA and inject a WNM Request event.'''

        # Create STAs and Agents
        sta1 = env.Station.create()
        sta2 = env.Station.create()
        vap1 = env.agents[0].radios[0].vaps[0]
        vap2 = env.agents[1].radios[1].vaps[0]

        # Associate the STAs
        vap1.associate(sta1)
        vap2.associate(sta2)

        vap1_mac_hex = vap1.bssid.replace(':', '').upper()
        vap2_mac_hex = vap2.bssid.replace(':', '').upper()
        sta1_mac_hex = sta1.mac.replace(':', '').upper()
        sta2_mac_hex = sta2.mac.replace(':', '').upper()

        # Simulated events data
        event1_type = 2  # BTQ Query
        event1_data = "D0003A01{}{}{}60010A060100".format(
            vap1_mac_hex,  # DA
            sta1_mac_hex,  # SA
            vap1_mac_hex)  # BSSID

        event2_type = 4  # ANQP REQUEST
        event2_data = "D0083A01{}{}{}C000040A7D6C0200000E0000010A0002010601070108010C01".format(
            vap2_mac_hex,  # DA
            sta2_mac_hex,  # SA
            vap2_mac_hex)  # BSSID

        debug("Simulate BTM Query management frame event")
        env.agents[0].radios[0].send_bwl_event(
            "EVENT MGMT-FRAME DATA={}".format(event1_data))

        debug("Simulate ANQP Request management frame event")
        env.agents[1].radios[1].send_bwl_event(
            "EVENT MGMT-FRAME DATA={}".format(event2_data))

        # Allow the events to propagate
        time.sleep(1)

        # Validate the first (WNM Request) event
        self.validate_tunnelled_frame(env.agents[0].mac, sta1.mac, event1_type, event1_data)

        # Validate the second (ANQP REQUEST) event
        self.validate_tunnelled_frame(env.agents[1].mac, sta2.mac, event2_type, event2_data)

        # Disconnect the stations
        vap1.disassociate(sta1)
        vap2.disassociate(sta2)

    def test_simulate_v2_certification_4_7_10(self):

        agent = env.agents[0]
        sta1 = env.Station.create()
        sta2 = env.Station.create()
        sta3 = env.Station.create()
        vap1 = agent.radios[0].vaps[0]
        vap2 = agent.radios[1].vaps[0]

        # Phase 1
        # Phase 1 (step 1): reset controller
        env.controller.cmd_reply("DEV_RESET_DEFAULT")
        # wait
        time.sleep(2)
        '''
        todo: add verification
        '''
        # Phase 1 (step 1): config controller
        env.controller.cmd_reply(
            "dev_set_config,bss_info1,"
            "{} 8x Multi-AP-24G-1 0x0020 0x0008 maprocks1 0 1".format(agent.mac))
        # wait
        time.sleep(2)
        '''
        todo: add verification
        '''
        # Phase 1 (step 2): config agent
        agent.cmd_reply("dev_reset_default")
        time.sleep(2)
        agent.cmd_reply("dev_set_config,backhaul,eth")
        # wait
        time.sleep(2)

        # Phase 2 (step 3)
        mid = env.controller.dev_send_1905(agent.mac, 0x8001)
        # wait
        time.sleep(1)
        # Phase 2 (step 4)
        '''
        Todo:
        Verify that MAUT sends a correctly formatted AP Capability Report message within 1 sec of
        receiving the AP Capability Query message sent by the Controller.
        Verify that the AP Capability Report message contains one Metric Collection Interval TLV and
        one R2 AP Capability TLV with the Byte Counter Units field set to 0x01.
        '''
        resp = self.check_cmdu_type_single("AP Capability Report message", 0x8002,
                                           agent.mac, env.controller.mac,
                                           mid)

        self.check_cmdu_has_tlvs(resp, 0xC5)
        ap_capability_tlv = self.check_cmdu_has_tlvs(resp, 0xB4)
        print(ap_capability_tlv)

        # Phase 3
        # Phase 4
        vap1.associate(sta1)
        vap1.associate(sta3)
        vap2.associate(sta2)

        time.sleep(1)
        # Phase 5
        # Phase 6

        # Phase 7

        # prepare tlvs
        sta_mac_addr_tlv = tlv(0x95, 0x0006, '{}'.format(sta2.mac))
        # send
        mid = env.controller.dev_send_1905(agent.mac, 0x800D, sta_mac_addr_tlv)
        # wait
        time.sleep(5)
        # check response
        resp = self.check_cmdu_type_single("associated sta link metrics response", 0x800E,
                                           agent.mac, env.controller.mac,
                                           mid)
        self.check_cmdu_has_tlvs(resp, 0xC8)
        self.check_cmdu_has_tlvs(resp, 0x96)

        # Phases 9 + 10

        # Disable reporting
        self.configure_multi_ap_policy_config_with_unsuccessful_association(0x00, 0x00)
        # report should not be sent as we disabled the feature
        self.mismatch_psk('no')

        # Enable unsuccsfull association - 1 per minute
        self.configure_multi_ap_policy_config_with_unsuccessful_association(0x80, 0x01)
        # First report should be sent
        self.mismatch_psk('yes')

        # tear down the test: disassociated
        vap1.disassociate(sta1)
        vap1.disassociate(sta3)
        vap2.disassociate(sta2)

        # reset everything
        env.controller.cmd_reply("DEV_RESET_DEFAULT")

        # wait
        time.sleep(2)

    def mismatch_psk(self, expect='yes'):
        '''
        expect: yes / no / exceed
        '''

        # Simulate Mismatch PSK sent by STA

        # Create STA and Agent
        sta = env.Station.create()
        agent = env.agents[0]
        agent_radio = env.agents[0].radios[0]

        # Simulate Failed Association Message
        agent_radio.send_bwl_event(
            "EVENT AP-STA-POSSIBLE-PSK-MISMATCH {}".format(sta.mac))

        # Wait for something to happen
        time.sleep(1)

        # Check correct flow

        if expect == 'yes':
            # Validate "Failed Connection Message" CMDU was sent
            response = self.check_cmdu_type_single(
                "Failed Connection Message", 0x8033, agent.mac, env.controller.mac)

            debug("Check Failed Connection Message has valid STA TLV")
            tlv_sta_mac = self.check_cmdu_has_tlv_single(response, 0x95)
            if hasattr(tlv_sta_mac, 'sta_mac_addr_type_mac_addr'):
                received_sta_mac = tlv_sta_mac.sta_mac_addr_type_mac_addr
            else:
                received_sta_mac = '00:00:00:00:00:00'

            # Validate Srouce Info STA MAC
            if received_sta_mac != sta.mac:
                self.fail("Source Info TLV has wrong STA MAC {} instead of {}".format(
                    received_sta_mac, sta.mac))
        elif expect == 'no':
            debug("expecting no cmdu, policy set to no report")
            self.check_no_cmdu_type("Failed Connection Message", 0x8033,
                                    agent.mac, env.controller.mac)
        elif expect == 'exceed':
            debug("expecting no cmdu, exceeded number of reports in a minute")
            self.check_no_cmdu_type("Failed Connection Message", 0x8033,
                                    agent.mac, env.controller.mac)
        else:
            debug("unknown 'expect' = {}".format(expect))


if __name__ == '__main__':
    t = TestFlows()

    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", "-v", action='store_true', default=False,
                        help="(ignored for backward compatibility)")
    parser.add_argument("--stop-on-failure", "-s", action='store_true', default=False,
                        help="exit on the first failure")
    user = os.getenv("SUDO_USER", os.getenv("USER", ""))
    parser.add_argument("--unique-id", "-u", type=str, default=user,
                        help="append UNIQUE_ID to all container names, e.g. gateway-<UNIQUE_ID>; "
                             "defaults to {}".format(user))
    parser.add_argument("--tag", "-t", type=str,
                        help="use runner image with tag TAG instead of 'latest'")
    parser.add_argument("--skip-init", action='store_true', default=False,
                        help="don't start up the containers")
    parser.add_argument("tests", nargs='*',
                        help="tests to run; if not specified, run all tests: " + ", ".join(t.tests))
    options = parser.parse_args()

    unknown_tests = [test for test in options.tests if test not in t.tests]
    if unknown_tests:
        parser.error("Unknown tests: {}".format(', '.join(unknown_tests)))

    opts.tcpdump_dir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', 'logs'))
    opts.stop_on_failure = options.stop_on_failure

    t.start_test('init')
    env.launch_environment_docker(options.unique_id, options.skip_init, options.tag)

    if t.run_tests(options.tests):
        sys.exit(1)
