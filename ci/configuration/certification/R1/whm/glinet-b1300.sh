#!/bin/sh

# We need to source some files which are only available on prplWrt
# devices, so prevent shellcheck from trying to read them:
# shellcheck disable=SC1091

set -e

# Start with a new log file:
rm -f /var/log/messages && syslog-ng-ctl reload

data_overlay_not_initialized()
{
  grep -q overlayfs:/tmp/root /proc/mounts || test -f /tmp/.switch_jffs2 || pgrep 'mount_root done'
}

if data_overlay_not_initialized; then
  logger -t prplmesh -p daemon.info "Waiting for data overlay initialization..."
  while data_overlay_not_initialized; do
    sleep 2
  done
  logger -t prplmesh -p daemon.info "Data overlay is initialized."
fi
sleep 5

ubus wait_for DHCPv4
ubus wait_for DHCPv6

# Stop and disable the DHCP clients and servers:
ubus call DHCPv4.Client.1 _set '{"parameters": { "Enable": False }}'
ubus call DHCPv6.Client.1 _set '{"parameters": { "Enable": False }}'
ubus call DHCPv4.Server _set '{"parameters": { "Enable": False }}'
ubus call DHCPv6.Server _set '{"parameters": { "Enable": False }}'

# Save the IP settings persistently (PPM-2351):
sed -ri 's/(dm-save.*) = false/\1 = true/g' /etc/amx/ip-manager/ip-manager.odl
/etc/init.d/ip-manager restart
sleep 15

# Since for the GL-inet eth0 (LAN) is always detected as UP, eth1 (WAN) will be configured as a backhaul interface
# This allows prplMesh to detect the state of the backhaul interface
# WAN and LAN interfaces are effectively switched

# Remove the physical LAN interface from the LAN-bridge; it will become the control interface
# Also add the WAN interface to the LAN-bridge
# Set the LAN bridge IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"br-lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.100.172" } }'

# Move the WAN port into the LAN bridge if it's not there yet (to use it for data):
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth1\"]." }' || {
    echo "Adding WAN interface to LAN-bridge"
    ubus call "Bridging.Bridge" _add '{ "rel_path": ".[Alias == \"lan\"].Port.",  "parameters": { "Name": "eth1", "Alias": "ETH1", "Enable": true } }'
}

# One of the LAN ports is used for control. Create a section for it:
uci set network.cert=interface
# Setting ifname is not supported in the current version of the TR-181
# IP manager (v1.11.1), set it in UCI instead:
uci set network.cert.ifname='eth0'

# Remove the control interface from the LAN bridge if it's not already the case:
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth0\"]." }' && {
    echo "Removing LAN interface from LAN-bridge"
    echo "It will be used as control interface"
    ubus call "Bridging.Bridge" _del '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth0\"]." }'
    uci changes; sleep 5
}

# To set the IP on the control interface, we first need to find the
# corresponding Ethernet.Interface:
ETH_IF="$(ubus call Ethernet.Interface _list | jsonfilter -e '@.instances[@.name="ETH0"].index')"
# Then if there is no corresponding Ethernet.Link yet, we need to add
# one:
ubus call Ethernet.Link _get '{ "rel_path": ".[Name == \"eth0\"]." }' || {
    echo "Adding Ethernet Link for LAN interface"
    ETH_LINK="$(ubus call Ethernet.Link _add "{ \"parameters\": { \"Name\": \"eth0\", \"Alias\": \"eth0\",\"LowerLayers\": \"Device.Ethernet.Interface.$ETH_IF.\", \"Enable\": true } }" | jsonfilter -e '@.index')"
}
# We can now create an IP.Interface if there is none yet:
LAN_INTERFACE="IP.Interface"
ubus call IP.Interface _get '{ "rel_path": ".[Name == \"eth0\"]." }' || {
    echo "Adding IP.Interface"
    LAN_INTERFACE="IP.Interface.""$(ubus call IP.Interface _add "{ \"parameters\": { \"Name\": \"eth0\", \"UCISectionNameIPv4\": \"cert\", \"Alias\": \"eth0\", \"LowerLayers\": \"Device.Ethernet.Link.$ETH_LINK.\", \"Enable\": true } }" | jsonfilter -e '@.index')"

    # Create an SSH server on the control interface if there is none
    # echo "Adding an SSH server on the control interface"
    # ubus call SSH.Server _get '{ "rel_path": ".[Alias == \"control\"]." }' || {
    #     sleep 2
    #     ubus call "SSH.Server" _add "{ \"rel_path\": \".\", \"parameters\": { \"Interface\": \"Device.$LAN_INTERFACE.\", \"AllowRootPasswordLogin\": true, \"Alias\": \"control\" } }"
    # }
}

# Wait until the interface is created, it seems like we can not add to the newly created interface object directly after creating it
ubus wait_for "$LAN_INTERFACE"
sleep 15

# We can now add the IP address if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Alias == \"eth0\"].IPv4Address.[Alias == \"eth0\"]." }' || {
    echo "Adding IP address $IP"
    ubus call "IP.Interface" _add '{ "rel_path": ".[Alias == \"eth0\"].IPv4Address.", "parameters": { "IPAddress": "192.168.250.172", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Alias": "eth0", "Enable" : true } }'
}
sleep 5
# Finally, we can enable it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"eth0\"].", "parameters": { "IPv4Enable": true } }'

# Wired backhaul interface:
# Set the WAN interface as backhaul interface
uci set prplmesh.config.backhaul_wire_iface='eth1'

# Stop and disable the firewall:
/etc/init.d/tr181-firewall stop
rm -f /etc/rc.d/S22tr181-firewall

# Restart the ssh server
/etc/init.d/ssh-server restart

# Required for config_load:
. /lib/functions/system.sh
# Required for config_foreach:
. /lib/functions.sh

# add private vaps to lan to workaround Netmodel missing wlan mib
# this must be reverted once Netmodel version is integrated
brctl addif br-lan wlan0 > /dev/null 2>&1 || true
brctl addif br-lan wlan1 > /dev/null 2>&1 || true

# configure private vaps
ubus call "WiFi.SSID.1" _set '{ "parameters": { "SSID": "prplmesh" } }'
ubus call "WiFi.SSID.2" _set '{ "parameters": { "SSID": "prplmesh" } }'
ubus call "WiFi.AccessPoint.1.Security" _set '{ "parameters": { "KeyPassPhrase": "prplmesh_pass" } }'
ubus call "WiFi.AccessPoint.2.Security" _set '{ "parameters": { "KeyPassPhrase": "prplmesh_pass" } }'
ubus call "WiFi.AccessPoint.1.Security" _set '{ "parameters": { "ModeEnabled": "WPA2-Personal" } }'
ubus call "WiFi.AccessPoint.2.Security" _set '{ "parameters": { "ModeEnabled": "WPA2-Personal" } }'
ubus call "WiFi.AccessPoint.1.WPS" _set '{ "parameters": { "ConfigMethodsEnabled": "PushButton" } }'
ubus call "WiFi.AccessPoint.2.WPS" _set '{ "parameters": { "ConfigMethodsEnabled": "PushButton" } }'

# Make sure specific channels are configured. If channel is set to 0,
# ACS will be configured. If ACS is configured hostapd will refuse to
# switch channels when we ask it to. Channels 1 and 48 were chosen
# because they are NOT used in the WFA certification tests (this
# allows to verify that the device actually switches channel as part
# of the test).
# See also PPM-1928.
ubus call "WiFi.Radio.1" _set '{ "parameters": { "Channel": "1" } }'
ubus call "WiFi.Radio.2" _set '{ "parameters": { "Channel": "48" } }'

#Increase pwhm related log for deubug purpose (PROVISORY)
ubus-cli "WiFi.set_trace_zone(zone = chanInf, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = chanMgt, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = chan, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = rad, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = ssid, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genStaC, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genHapd, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genRadI, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = gen, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genWsup, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genVap, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genHapd, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genEvt, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wld, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genFsm, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = genEp, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = apMf, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = apRssi, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = ap11v, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = apPub, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = apSec, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = apNeigh, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = ap11k, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = ROpStd, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = ap, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = ep, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wSupPsr, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlEvt, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlCore, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlParser, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = fileMgr, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wpaSupp, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wpaCtrl, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlDbg, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wpaCtrl, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = hapdAP, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlRad, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wpaCtrl, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = hapdCfg, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = fileMgr, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = hapdRad, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = secDmn, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wSupCfg, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlApi, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = nlAP, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = tyRoam, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wldEPrf, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = tyRoam, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wldTrap, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wld, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wld, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wldDmn, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = utilMon, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = utilEvt, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wld_acm, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = netUtil, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = netUtil, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = linuxIfStats, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = radPrb, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wldScan, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wldFsm, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = radCaps, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wldDly, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = radStm, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = radEvtH, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = radIfM, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = util, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wps, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = wld, level = 400)"
ubus-cli "WiFi.set_trace_zone(zone = TH_EP, level = 400)"

# secondary vaps and backhaul are not supported yet (WIP)

# Try to work around PCF-681: if we don't have a connectivity, restart
# tr181-bridging
# Check the status of the LAN bridge
ip a |grep "br-lan:" |grep "state UP" >/dev/null || (echo "LAN Bridge DOWN, restarting bridge manager" && /etc/init.d/tr181-bridging restart && sleep 15)

# If we still can't ping the UCC, restart the IP manager
ping -i 1 -c 2 192.168.250.199 || (/etc/init.d/ip-manager restart && sleep 15)
ping -i 1 -c 2 192.168.250.199 || (/etc/init.d/ip-manager restart && sleep 15)

# Remove the default lan/wan SSH servers if they exist
# ubus call "SSH.Server" _del '{ "rel_path": ".[Alias == \"lan\"]" }' || true
# ubus call "SSH.Server" _del '{ "rel_path": ".[Alias == \"wan\"]" }' || true

# Trigger the startup of the SSH server
# The SSH server on eth0 has some problems starting through the server component
# Launch a server on the control IP later
# ubus call "SSH.Server" _set '{ "rel_path": ".[Alias == \"control\"].", "parameters": { "Enable": false } }'
# sleep 5
# ubus call "SSH.Server" _set '{ "rel_path": ".[Alias == \"control\"].", "parameters": { "Enable": true } }'

# Restart the ssh server
/etc/init.d/ssh-server restart
sleep 5

# Add command to start dropbear to rc.local to allow SSH access after reboot
BOOTSCRIPT="/etc/rc.local"
SERVER_CMD="sleep 20 && dropbear -F -T 10 -p192.168.250.172:22 &"
if ! grep -q "$SERVER_CMD" "$BOOTSCRIPT"; then { head -n -2 "$BOOTSCRIPT"; echo "$SERVER_CMD"; tail -2 "$BOOTSCRIPT"; } >> btscript.tmp; mv btscript.tmp "$BOOTSCRIPT"; fi

# Start an ssh server on the control interfce
dropbear -F -T 10 -p192.168.250.172:22 &
