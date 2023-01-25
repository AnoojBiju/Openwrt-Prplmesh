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

# The OSP has two "physical WAN" ports: eth0_6 and eth0_0 (left to right)
# The yellow "LAN" ports are: eth0_2, eth0_3, eth0_4, eth0_5 (left to right)
# eth0_0 is in the LAN bridge by default
# We use eth0_6 as WAN (control); and eth0_5 as LAN (prplMesh data)

# Set the LAN bridge IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"br-lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.100.120" } }'

# We use WAN - eth0_6 for the control interface.
# Add the IP address if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.[Alias == \"wan\"]." }' || {
    echo "Adding IP address $IP"
    ubus call "IP.Interface" _add '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.", "parameters": { "Alias": "wan", "AddressingType": "Static" } }'
}
# Configure it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.1", "parameters": { "IPAddress": "192.168.250.120", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Enable" : true } }'
# Enable it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].", "parameters": { "IPv4Enable": true } }'

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth0_5'

# wireless.radio0.band='2.4GHz'
# wireless.radio2.band='5GHz'
# wireless.radio4.band='6GHz'
# wireless.radio6.band='5GHz'

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

# secondary vaps and backhaul are not supported yet (WIP)

# Remove 6Ghz radio until it's supported
ubus call WiFi.SSID _get '{ "rel_path": ".[Name == \"wlan4.1\"]." }' && {
    ubus call WiFi.SSID _del '{ "rel_path": ".[Name == \"wlan4.1\"]." }'
}
ubus call WiFi.SSID _get '{ "rel_path": ".[Name == \"wlan4.2\"]." }' && {
    ubus call WiFi.SSID _del '{ "rel_path": ".[Name == \"wlan4.2\"]." }'
}
ubus call WiFi.AccessPoint _get '{ "rel_path": ".[Alias == \"wlan4.1\"]." }' && {
    ubus call WiFi.AccessPoint _del '{ "rel_path": ".[Alias == \"wlan4.1\"]." }'
}
ubus call WiFi.AccessPoint _get '{ "rel_path": ".[Alias == \"wlan4.2\"]." }' && {
    ubus call WiFi.AccessPoint _del '{ "rel_path": ".[Alias == \"wlan4.2\"]." }'
}
ubus call WiFi.Radio _get '{ "rel_path": ".[Name == \"wlan4\"]." }' && {
    ubus call WiFi.Radio _del '{ "rel_path": ".[Name == \"wlan4\"]." }'
}

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
SERVER_CMD="sleep 20 && dropbear -F -T 10 -p192.168.250.120:22 &"
if ! grep -q "$SERVER_CMD" "$BOOTSCRIPT"; then { head -n -2 "$BOOTSCRIPT"; echo "$SERVER_CMD"; tail -2 "$BOOTSCRIPT"; } >> btscript.tmp; mv btscript.tmp "$BOOTSCRIPT"; fi

# Start an ssh server on the control interfce
dropbear -F -T 10 -p192.168.250.120:22 &
