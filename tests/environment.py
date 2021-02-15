###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

from enum import Enum
import json
import os
import platform
import re
import subprocess
import time
import yaml
import pexpect

from capi import UCCSocket
from collections import namedtuple
from connmap import MapDevice
from opts import opts, debug, err
from typing import Dict, Any
import sniffer


class ALEntity:
    '''Abstract representation of a MultiAP device (1905.1 AL Entity).

    Derived classes provide concrete implementations for a specific device (e.g. docker).

    This provides basic information about the entity, e.g. its AL MAC address. How this information
    is retrieved is implementation-specific.

    It also provides an abstract interface to interact with the entity, e.g. for sending CAPI
    commands.

    If a device runs both the agent and the controller, two ALEntities should be created for it,
    with the same MAC address. This is not how it is modeled in 1905.1, but it corresponds to how
    it is implemented in prplMesh and it allows us to have e.g. a separate UCCSocket to controller
    and agent.
    '''

    def __init__(self, mac: str, ucc_socket: UCCSocket, installdir: str,
                 is_controller: bool = False):
        self.mac = mac
        self.ucc_socket = ucc_socket
        self.installdir = installdir
        self.is_controller = is_controller
        self.radios = []

        # Convenience functions that propagate to ucc_socket
        self.cmd_reply = self.ucc_socket.cmd_reply
        self.dev_get_parameter = self.ucc_socket.dev_get_parameter
        self.dev_send_1905 = self.ucc_socket.dev_send_1905
        self.start_wps_registration = self.ucc_socket.start_wps_registration

    def command(self, *command: str) -> bytes:
        '''Run `command` on the device and return its output as bytes.

        Example: command('ip', 'addr') to get IP addresses of all interfaces.
        '''
        raise NotImplementedError("command is not implemented in abstract class ALEntity")

    def prplmesh_command(self, command: str, *args: str) -> bytes:
        '''Run `command` with "args" on the device and return its output as bytes.

        "command" is relative to the installation directory of prplmesh, e.g. "bin/beerocks_cli".
        '''
        return self.command(os.path.join(self.installdir, command), *args)

    def wait_for_log(self, regex: str, start_line: int, timeout: float,
                     fail_on_mismatch: bool = True) -> bool:
        '''Poll the entity's logfile until it contains "regex" or times out.'''
        raise NotImplementedError("wait_for_log is not implemented in abstract class ALEntity")

    # Northbound API access functions

    def nbapi_command(self, path: str, command: str, args: Dict = None) -> Dict:
        '''Run a northbound API command.

        Run northbound API "command" on the object specified with "path" with arguments "args".
        '''
        raise NotImplementedError("nbapi_command is not implemented in abstract class ALEntity")

    def nbapi_get(self, path: str, args: Dict = None) -> Dict:
        '''Run a northbound API 'get' command.

        Run northbound API "get" on the object specified with "path" with arguments "args". Parse
        the return value and remove the outer dict (with is always a single-entry dict with 'path.'
        as the key).
        '''
        ret = self.nbapi_command(path, "get", args)
        if not ret:
            return {}
        assert len(ret) == 1, "NBAPI 'get' should return a single object"
        return ret[path + "."]

    def nbapi_get_parameter(self, path: str, parameter: str) -> Any:
        '''Get a parameter from nbapi.

        Gets the northbound API "parameter" in the object specified with "path". Returns the value,
        converted to a Python object.

        Equivalent to nbapi_get_object(path)[parameter] but slightly more efficient.
        '''
        values = self.nbapi_get(path, {"parameters": [parameter]})
        return values and values[parameter]

    def nbapi_get_instances(self, path: str) -> Dict[str, Dict[str, Any]]:
        '''Get all instances of a template object from nbapi.

        Gets the northbound API objects instantiated from the template object "path". Returns a
        dictionary of dictionaries corresponding to the instances. The key of the outer dictionary
        is the instance name (i.e., "1.", "2." etc.).
        '''
        values = self.nbapi_get(path, {"depth": 1})
        # Filter out the template parameters, i.e. anything that doesn't start with a number
        for k in list(values.keys()):
            if not re.match("^[0-9]", k):
                del values[k]
        return values


ChannelInfo = namedtuple("ChannelInfo", "channel bandwidth center_channel")


class Radio:
    '''Abstract representation of a radio on a MultiAP agent.

    This provides basic information about the radio, e.g. its mac address, and functionality for
    checking its status.
    '''

    def __init__(self, agent: ALEntity, mac: str):
        self.agent = agent
        agent.radios.append(self)
        self.mac = mac
        self.vaps = []

    def wait_for_log(self, regex: str, start_line: int, timeout: float,
                     fail_on_mismatch: bool = True) -> bool:
        '''Poll the radio's logfile until it contains "regex" or times out.'''
        raise NotImplementedError("wait_for_log is not implemented in abstract class Radio")

    def get_current_channel(self) -> ChannelInfo:
        '''Get the current channel information.

        Returns
        -------
        ChannelInfo
            3-tuple with the channel information: channel index, bandwidth as an integer, and
            center channel for VHT.
        '''
        raise NotImplementedError("get_current_channel is not implemented in abstract class Radio")

    def get_power_limit(self) -> int:
        '''Get the current tx_power information.'''
        raise NotImplementedError("get_power_limit is not implemented in abstract class Radio")


class Station:
    '''Placeholder for a wireless (fronthaul) station.

    Unlike the other classes, this is not an abstract class. Instead, it is a placeholder that
    represents a station. Handling the station is actually done through the VirtualAP concrete
    implementation.
    '''

    def __init__(self, mac: str):
        self.mac = mac

    __mac_base = 0

    @staticmethod
    def create():
        '''Generate a Station placeholder with a random MAC address.'''
        mac = '51:a1:10:20:{:02x}:{:02x}'.format(int(Station.__mac_base / 256),
                                                 Station.__mac_base % 256)
        Station.__mac_base += 1
        if Station.__mac_base > 256*256:
            Station.__mac_base = 0
        return Station(mac)


class StationEvent(Enum):
    '''An enum representing the possible station events
    based on client association event TLV assoc_event_flags'''
    CONNECT = 0x00000080
    DISCONNECT = 0x00000000


class VirtualAP:
    '''Abstract representation of a VAP on a MultiAP Radio.'''

    def __init__(self, radio: Radio, bssid: str):
        self.radio = radio
        radio.vaps.append(self)
        self.bssid = bssid

    def associate(self, sta: Station) -> bool:
        '''Associate "sta" with this VAP.'''
        raise NotImplementedError("associate is not implemented in abstract class VirtualAP")

    def disassociate(self, sta: Station) -> bool:
        '''Disassociate "sta" from this VAP.'''
        raise NotImplementedError("disassociate is not implemented in abstract class VirtualAP")


# The following variables are initialized as None, and have to be set when a concrete test
# environment is started.
wired_sniffer = None
controller = None
agents = []


def beerocks_cli_command(command: str) -> bytes:
    '''Execute `command` beerocks_cli command on the controller and return its output.'''
    debug("Send CLI command " + command)
    res = controller.prplmesh_command("bin/beerocks_cli", "-c", command)
    debug("  Response: " + res.decode('utf-8', errors='replace').strip())
    return res


def checkpoint() -> None:
    '''Checkpoint the current state.

    Any subsequent calls to functions that query cumulative state (e.g. log files, packet captures)
    will not match any of the state that was accumulated up till now, but only afterwards.

    TODO: Implement for log functions.
    '''
    wired_sniffer.checkpoint()


# Helper function used by the implementations based on ubus
def nbapi_ubus_command(entity: ALEntity, path: str, command: str, args: Dict = None) -> Dict:
    command = ['ubus', 'call', path, command]
    if args:
        command.append(json.dumps(args))
    result = entity.command(*command)
    if result:
        return json.loads(result)
    else:
        return result


# Concrete implementation with docker

rootdir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
installdir = os.path.join(rootdir, 'build', 'install')
on_wsl = "microsoft" in platform.uname()[3].lower()


# Temporary workaround
# Since we have multiple log files that correspond to a radio, multiple programs are passed
# as argument. In the log messages, we only use the first one.
# This should be reverted again as part of Unified Agent.
def _docker_wait_for_log(container: str, programs: [str], regex: str, start_line: int,
                         timeout: float, fail_on_mismatch: bool = True) -> bool:
    def logfilename(program):
        logfilename = os.path.join(rootdir, 'logs', container, 'beerocks_{}.log'.format(program))

        print(' --- logfilename: {}'.format(logfilename))

        # WSL doesn't support symlinks on NTFS, so resolve the symlink manually
        if on_wsl:
            logfilename = os.path.join(
                rootdir, 'logs', container,
                subprocess.check_output(["tail", "-2", logfilename]).decode('utf-8').
                rstrip(' \t\r\n\0'))
        return logfilename

    logfilenames = [logfilename(program) for program in programs]

    deadline = time.monotonic() + timeout
    try:
        while True:
            for logfilename in logfilenames:
                with open(logfilename, 'rb') as logfile:
                    for (i, v) in enumerate(logfile.readlines()):
                        if i <= start_line:
                            continue
                        search = re.search(regex.encode('utf-8'), v)
                        if search:
                            debug("Found '{}'\n\tin {}".format(regex, logfilename))
                            return (True, i, search.groups())
            if time.monotonic() < deadline:
                time.sleep(.3)
            else:
                if fail_on_mismatch:
                    err("Can't find '{}'\n\tin log of {} on {} after {}s".format(regex,
                                                                                 programs[0],
                                                                                 container,
                                                                                 timeout))
                else:
                    debug("Can't find '{}'\n\tin log of {} on {},"
                          "but failure allowed".format(regex, programs[0], container))

                return (False, start_line, None)
    except OSError:
        err("Can't read log of {} on {}".format(programs[0], container))
        return (False, start_line, None)


def _device_clear_input_buffer(device):
    """Clears input buffer of boardfarm"""
    # Interrupt any running command:
    device.send('\003')
    # Expect the prompt and the end of the line, to make sure we match
    # the last one. Doing this will make sure we don't keep old data
    # in the buffer.
    device.expect(['{}$'.format(device.prompt), pexpect.TIMEOUT, pexpect.EOF])

# Temporary workaround
# Since we have multiple log files that correspond to a radio, multiple log files are passed
# as argument. In the log messages, we only use the first one.
# This should be reverted again as part of Unified Agent.
def _device_wait_for_log(device: None, log_paths: [str], regex: str,
                         timeout: int, start_line: int = 0, fail_on_mismatch = True):
    """Waits for log matching regex expression to show up."""
    _device_clear_input_buffer(device)

    device.sendline("tail -f -n +{:d} {}".format(start_line + 1, " ".join(log_paths)))
    device.expect(regex, timeout=timeout)
    match = device.match.group(0)
    # Send Ctrl-C to interrupt tail -f
    device.send('\003')
    device.expect(device.prompt)
    try:
        if match:
            first_matched_line = match.partition('\r\n')[0]
            device.sendline("tail -n +{:d} {} | grep -a -n \"{}\"".format(start_line,
                                                                          " ".join(log_paths),
                                                                          first_matched_line))
            # Typical output of grep -n from log: "line_num:severity"
            # this regex has to capture just number of line in log
            device.expect(r"(?P<line_number>[0-9]+):[A-Z]+\s[0-9]", timeout=timeout)
            matched_line = int(device.match.group('line_number')) + start_line
            return (True, matched_line, match)
        else:
            return (False, start_line, None)
    # except pexpect.exceptions.TIMEOUT as e:
    #
    #    if fail_on_mismatch:
    #        raise e
    #    else:
    #        return (False, start_line, None)
    except Exception as e:
        raise Exception("Exception name: %s" % type(e).__name__)


class ALEntityDocker(ALEntity):
    '''Docker implementation of ALEntity.

    The entity is defined from the name of the container, the rest is derived from that.
    '''
    # NOTE: name arg can be also extracted from the device class itself, but test_flows.py
    # don't have it. We can remove this arg as soon, as we drop test_flows.py

    def __init__(self, name: str, device: None = None, is_controller: bool = False,
                 compose: bool = False):

        self.name = name
        ucc_interface_name = 'eth0'
        if device:
            self.device = device

        # First, get the UCC port from the config file
        if is_controller:
            config_file_name = 'beerocks_controller.conf'
        else:
            config_file_name = 'beerocks_agent.conf'
        with open(os.path.join(installdir, 'config', config_file_name)) as config_file:
            ucc_port = \
                re.search(r'ucc_listener_port=(?P<port>[0-9]+)',
                          config_file.read()).group('port')

        # On WSL, connect to the locally exposed container port
        if on_wsl or compose:
            published_port_output = subprocess.check_output(
                ["docker", "port", name, ucc_port]).decode('utf-8').split(":")
            device_ip = published_port_output[0]
            ucc_port = int(published_port_output[1])
        else:
            device_ip_output = self.command(
                'ip', '-f', 'inet', 'addr', 'show', ucc_interface_name)
            device_ip = re.search(
                r'inet (?P<ip>[0-9.]+)', device_ip_output.decode('utf-8')).group('ip')

        ucc_socket = UCCSocket(device_ip, ucc_port)
        mac = ucc_socket.dev_get_parameter('ALid')

        super().__init__(mac, ucc_socket, installdir, is_controller)

        # We always have two radios, wlan0 and wlan2
        RadioDocker(self, "wlan0")
        RadioDocker(self, "wlan2")

    def command(self, *command: str) -> bytes:
        '''Execute `command` in docker container and return its output.'''
        return subprocess.check_output(("docker", "exec", self.name) + command)

    def wait_for_log(self, regex: str, start_line: int, timeout: float,
                     fail_on_mismatch: bool = True) -> bool:
        '''Poll the entity's logfile until it contains "regex" or times out.'''
        program = "controller" if self.is_controller else "agent"
        return _docker_wait_for_log(self.name, [program], regex, start_line, timeout,
                                    fail_on_mismatch=fail_on_mismatch)

    def nbapi_command(self, path: str, command: str, args: Dict = None) -> Dict:
        return nbapi_ubus_command(self, path, command, args)

    def prprlmesh_status_check(self):
        return self.device.prprlmesh_status_check()

    def beerocks_cli_command(self, command) -> bytes:
        '''Execute `command` beerocks_cli command on the controller and return its output.
        Will return None if called from an object that is not a controller.
        '''
        if self.is_controller:
            debug("Send CLI command " + command)
            res = self.prplmesh_command("bin/beerocks_cli", "-c", command)
            debug("  Response: " + res.decode('utf-8', errors='replace').strip())
            return res
        return None

    def get_conn_map(self) -> Dict[str, MapDevice]:
        '''Get the connection map from the controller.'''

        '''Regular expression to match a MAC address in a bytes string.'''
        RE_MAC = rb"(?P<mac>([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"

        conn_map = {}
        for line in self.beerocks_cli_command("bml_conn_map").split(b'\n'):
            # TODO we need to parse indentation to get the exact topology.
            # For the time being, just parse the repeaters.
            bridge = re.search(rb' {8}IRE_BRIDGE: .* mac: ' + RE_MAC, line)
            radio = re.match(rb' {16}RADIO: .* mac: ' + RE_MAC, line)
            vap = re.match(rb' {20}fVAP.* bssid: ' + RE_MAC + rb', ssid: (?P<ssid>.*)$', line)
            client = re.match(rb' {24}CLIENT: mac: ' + RE_MAC, line)
            if bridge:
                cur_agent = MapDevice(bridge.group('mac').decode('utf-8'))
                conn_map[cur_agent.mac] = cur_agent
            elif radio:
                cur_radio = cur_agent.add_radio(radio.group('mac').decode('utf-8'))
            elif vap:
                cur_vap = cur_radio.add_vap(vap.group('mac').decode('utf-8'), vap.group('ssid'))
            elif client:
                cur_vap.add_client(client.group('mac').decode('utf-8'))
        return conn_map


class RadioDocker(Radio):
    '''Docker implementation of a radio.'''

    def __init__(self, agent: ALEntityDocker, iface_name: str):
        self.iface_name = iface_name
        ip_output = agent.command("ip", "-o",  "link", "list", "dev", self.iface_name).decode()
        mac = re.search(r"link/ether (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})",
                        ip_output).group(1)
        super().__init__(agent, mac)

        # Since dummy bwl always uses the first VAP, in practice we always have a single VAP with
        # the radio MAC as the bssid.
        VirtualAPDocker(self, mac)

    def wait_for_log(self, regex: str, start_line: int, timeout: float,
                     fail_on_mismatch: bool = True) -> bool:
        '''Poll the radio's logfile until it contains "regex" or times out.'''
        programs = ("agent_" + self.iface_name, "ap_manager_" + self.iface_name)
        return _docker_wait_for_log(self.agent.name, programs, regex,
                                    start_line, timeout, fail_on_mismatch=fail_on_mismatch)

    def send_bwl_event(self, event: str) -> None:
        # The file is only available within the docker container so we need to use an echo command.
        # Use '|| true' to make sure it doesn't fail on timeout.
        command = "echo \"{}\" | timeout 1s tee /tmp/beerocks/{}/EVENT* >/dev/null || true"\
            .format(event, self.iface_name)
        self.agent.command('sh', '-c', command)

    def read_tmp_file(self, filename: str) -> bytes:
        '''Read the file given by `filename` from the radio's status directory'''
        # The file is only available within the docker container so we need to use cat.
        path = "/tmp/beerocks/{}/{}".format(self.iface_name, filename)
        return self.agent.command("cat", path)

    def get_current_channel(self) -> ChannelInfo:
        channel_info = yaml.safe_load(self.read_tmp_file("channel"))
        return ChannelInfo(channel_info["channel"], channel_info["bw"],
                           channel_info["center_channel"])

    def get_power_limit(self) -> int:
        power_info = yaml.safe_load(self.read_tmp_file("tx_power"))
        return power_info["tx_power"]


class VirtualAPDocker(VirtualAP):
    '''Docker implementation of a VAP.'''

    def __init__(self, radio: RadioDocker, bssid: str):
        super().__init__(radio, bssid)

    def associate(self, sta: Station) -> bool:
        '''Associate "sta" with this VAP.'''
        self.radio.send_bwl_event("EVENT AP-STA-CONNECTED {}".format(sta.mac))

    def disassociate(self, sta: Station) -> bool:
        '''Disassociate "sta" from this VAP.'''
        self.radio.send_bwl_event("EVENT AP-STA-DISCONNECTED {}".format(sta.mac))


def _get_bridge_interface(unique_id: str):
    '''Use docker network inspect to get the docker bridge interface.'''
    docker_network = 'prplMesh-net-{}'.format(unique_id)
    docker_network_inspect_cmd = ('docker', 'network', 'inspect', docker_network)
    inspect_result = subprocess.run(docker_network_inspect_cmd, stdout=subprocess.PIPE)
    if inspect_result.returncode != 0:
        # Assume network doesn't exist yet. Create it.
        # This is normally done by test_gw_repeater.sh, but we need it earlier to be able to
        # start tcpdump
        # Raise an exception if it fails (check=True).
        subprocess.run(('docker', 'network', 'create', '--label', 'prplmesh',
                        '--label', 'prplmesh-id={}'.format(unique_id), docker_network), check=True,
                       stdout=subprocess.DEVNULL)

        # Inspect again, now raise if it fails (check=True).
        inspect_result = subprocess.run(docker_network_inspect_cmd, check=True,
                                        stdout=subprocess.PIPE)

    inspect = json.loads(inspect_result.stdout)
    prplmesh_net = inspect[0]
    # podman adds a 'plugins' indirection that docker doesn't have.
    if 'plugins' in prplmesh_net:
        bridge = prplmesh_net['plugins'][0]['bridge']
    else:
        # docker doesn't report the interface name of the bridge. So format it based on the ID.
        bridge_id = prplmesh_net['Id']
        bridge = 'br-' + bridge_id[:12]

    return bridge


def launch_environment_docker(unique_id: str, skip_init: bool = False, tag: str = ""):
    global wired_sniffer
    iface = _get_bridge_interface(unique_id)
    wired_sniffer = sniffer.Sniffer(iface, opts.tcpdump_dir)

    gateway = 'gateway-' + unique_id
    repeater1 = 'repeater1-' + unique_id
    repeater2 = 'repeater2-' + unique_id

    if not skip_init:
        command = [os.path.join(rootdir, "tests", "test_gw_repeater.sh"), "-f", "-u", unique_id,
                   "-g", gateway, "-r", repeater1, "-r", repeater2, "-d", "7"]
        if tag:
            command += ["-t", tag]
        wired_sniffer.start('init')
        try:
            subprocess.check_call(command)
        finally:
            wired_sniffer.stop()

    global controller, agents
    controller = ALEntityDocker(name=gateway, is_controller=True)
    agents = (ALEntityDocker(name=repeater1), ALEntityDocker(name=repeater2))

    debug('controller: {}'.format(controller.mac))
    debug('agent1: {}'.format(agents[0].mac))
    debug('agent1 wlan0: {}'.format(agents[0].radios[0].mac))
    debug('agent1 wlan2: {}'.format(agents[0].radios[1].mac))
    debug('agent2: {}'.format(agents[1].mac))
    debug('agent2 wlan0: {}'.format(agents[1].radios[0].mac))
    debug('agent2 wlan2: {}'.format(agents[1].radios[1].mac))


class ALEntityPrplWrt(ALEntity):
    """Abstraction of ALEntity in real device."""

    def __init__(self, device: None, is_controller: bool = False):
        self.device = device
        self.name = device.name

        if is_controller:
            self.config_file_name = '/opt/prplmesh/config/beerocks_controller.conf'
        else:
            self.config_file_name = '/opt/prplmesh/config/beerocks_agent.conf'

        ucc_port_raw = self.command("grep \"ucc_listener_port\" {}".format(self.config_file_name))
        ucc_port = int(re.search(r'ucc_listener_port=(?P<port>[0-9]+)',
                                 ucc_port_raw).group('port'))
        log_folder_raw = self.command(
            "grep log_files_path {}".format(self.config_file_name))
        self.log_folder = re.search(r'log_files_path=(?P<log_path>[a-zA-Z0-9_\/]+)',
                                    log_folder_raw).group('log_path')
        ucc_socket = UCCSocket(str(self.device.wan_ip), int(ucc_port))
        mac = ucc_socket.dev_get_parameter('ALid')

        super().__init__(mac, ucc_socket, installdir, is_controller)

        # We always have two radios, wlan0 and wlan2
        RadioHostapd(self, "wlan0")
        RadioHostapd(self, "wlan2")

    def command(self, *command: str) -> bytes:
        """Execute `command` in device and return its output."""
        self.device.sendline(" ".join(command))
        self.device.expect(self.device.prompt, timeout=10)
        return self.device.before

    def wait_for_log(self, regex: str, start_line: int, timeout: float,
                     fail_on_mismatch: bool = True) -> bool:
        """Poll the entity's logfile until it contains "regex" or times out."""
        program = "controller" if self.is_controller else "agent"
        # Multiply timeout by 100, as test sets it in float.
        return _device_wait_for_log(self.device,
                                    ["{}/beerocks_{}.log".format(self.log_folder, program)],
                                    regex, timeout, start_line, fail_on_mismatch)

    def nbapi_command(self, path: str, command: str, args: Dict = None) -> Dict:
        return nbapi_ubus_command(self, path, command, args)

    def prprlmesh_status_check(self):
        return self.device.prprlmesh_status_check()


class RadioHostapd(Radio):
    """Abstraction of real Radio in prplWRT device."""

    def __init__(self, agent: ALEntityPrplWrt, iface_name: str):
        self.iface_name = iface_name
        self.agent = agent
        _device_clear_input_buffer(self.agent.device)
        ip_raw = self.agent.command("ip link list dev {}".format(self.iface_name))
        mac = re.search(r"link/ether (([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})",
                        ip_raw).group(1)
        self.log_folder = agent.log_folder
        super().__init__(agent, mac)

        # Find out amount of VAPs avalaible on device.
        # If 0 - spawn one VAP to represent AP.
        self.agent.device.sendline("ip link list | grep -c \"{}\\.\"".format(self.iface_name))
        # Look for number of 1 or 2 digits surrounded by CRLF.
        self.agent.device.expect("\r\n(?P<vaps>[0-9]{1,2})\r\n")
        vap_amount = int(self.agent.device.match.group('vaps'))
        if vap_amount == 0:
            VirtualAPHostapd(self, mac)
        else:
            for vap_number in range(0, vap_amount):
                vap_mac = self.get_mac("{}.{}".format(self.iface_name, vap_number))
                VirtualAPHostapd(self, vap_mac)

    def wait_for_log(self, regex: str, start_line: int, timeout: float,
                     fail_on_mismatch: bool = True):
        ''' Poll the Radio's logfile until it match regular expression '''

        log_files = [
            "{}/beerocks_agent_{}.log".format(self.log_folder, self.iface_name),
            "{}/beerocks_ap_manager_{}.log".format(self.log_folder, self.iface_name)
        ]

        # Multiply timeout by 100, as test sets it in float.
        return _device_wait_for_log(self.agent.device, log_files, regex, timeout, start_line,
                                    fail_on_mismatch)

    def get_mac(self, iface: str) -> str:
        """Return mac of specified iface"""
        device = self.agent.device
        device.sendline("ip link show {}".format(iface))
        device.expect("link/ether (?P<mac>([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})")
        return device.match.group('mac')

    def get_current_channel(self) -> ChannelInfo:
        device = self.agent.device
        device.sendline("iw {} info".format(self.iface_name))
        device.expect(
            "channel (?P<channel>[0-9]+) .*width.* (?P<width>[0-9]+) " +
            "MHz.*center1.* (?P<center>[0-9]+) MHz")
        return ChannelInfo(device.match.group('channel'), device.match.group('width'),
                           device.match.group('center'))

    def get_power_limit(self) -> int:
        device = self.agent.device
        device.sendline("iw {} info".format(self.iface_name))
        device.expect("txpower (?P<power_limit>[0-9]*[.]?[0-9]*) dBm")
        return device.match.group('power_limit')


class VirtualAPHostapd(VirtualAP):
    """Docker implementation of a VAP."""

    def __init__(self, radio: RadioHostapd, bssid: str):
        super().__init__(radio, bssid)
        self.iface = self.get_iface(self.bssid)

    def get_ssid(self) -> str:
        """Get current SSID of attached radio. Return string."""
        device = self.radio.agent.device
        device.sendline("iw {} info".format(self.iface))
        # We are looking for SSID definition
        # ssid Multi-AP-24G-1
        # type AP
        device.expect("ssid (?P<ssid>.*)\r\n\ttype AP\r\n\t")
        return device.match.group('ssid')

    def get_psk(self) -> str:
        """Get SSIDs personal key set during last autoconfiguration. Return string"""
        device = self.radio.agent.device
        ssid = self.get_ssid()
        device.sendline(("grep \"Autoconfiguration for ssid: " +
                         "{}\" \"{}/beerocks_agent_{}.log\" | tail -n 1")
                        .format(ssid, self.radio.log_folder, self.radio.iface_name))
        # We looking for key, which was set during last autoconfiguration. E.g of such string:
        # network_key: maprocks2 fronthaul:
        device.expect("network_key: (?P<psk>.*) fronthaul")
        return device.match.group('psk')

    def get_iface(self, bssid: str) -> str:
        device = self.radio.agent.device
        device.sendline("ip link list | grep -B1 \"{}\"".format(bssid))
        device.expect("[0-9]{1,4}: (?P<iface_name>wlan[0-9.]{1,4}): <")
        return device.match.group('iface_name')

    def associate(self, sta: Station) -> bool:
        ''' Associate "sta" with this VAP '''
        # TODO: complete this stub
        return True

    def disassociate(self, sta: Station) -> bool:
        ''' Disassociate "sta" from this VAP.'''
        # TODO: complete this stub
        return True
