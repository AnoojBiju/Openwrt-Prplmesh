#!/bin/sh

# We need to source some files which are only available on prplWrt
# devices, so prevent shellcheck from trying to read them:
# shellcheck disable=SC1091

set -e
echo conf_file_exit_code=$?

# Start with a new log file:
rm -f /var/log/messages && syslog-ng-ctl reload

data_overlay_not_initialized()
{
  grep -q overlayfs:/tmp/root /proc/mounts || test -f /tmp/.switch_jffs2 || pgrep 'mount_root done'
}

if data_overlay_not_initialized; then
  logger -t prplmesh -p daemon.info "Waiting for data overlay initialization..."
  echo conf_file_exit_code=$?
  while data_overlay_not_initialized; do
    sleep 2
  done
  logger -t prplmesh -p daemon.info "Data overlay is initialized."
  sleep 20
  echo conf_file_exit_code=$?
fi


sh /etc/init.d/tr181-upnp stop || true
echo conf_file_exit_code=$?
rm -f /etc/rc.d/S*tr181-upnp
echo conf_file_exit_code=$?

# Save the IP settings persistently (PPM-2351):
sed -ri 's/(dm-save.*) = false/\1 = true/g' /etc/amx/ip-manager/ip-manager.odl
echo conf_file_exit_code=$?
sh /etc/init.d/ip-manager restart && sleep 15
echo conf_file_exit_code=$?

ubus wait_for IP.Interface
echo conf_file_exit_code=$?

# Stop and disable the DHCP clients and servers:
if ubus call DHCPv4 _list >/dev/null ; then
  ubus call DHCPv4.Server _set '{"parameters": { "Enable": False }}'
  echo conf_file_exit_code=$?
else
    echo "DHCPv4 service not active!"
fi
if ubus call DHCPv6 _list >/dev/null ; then
  ubus call DHCPv6.Server _set '{"parameters": { "Enable": False }}'
  echo conf_file_exit_code=$?
else
    echo "DHCPv6 service not active!"
    echo conf_file_exit_code=$?
fi

# We use WAN for the control interface.
# Add the IP address if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.[Alias == \"wan\"]." }' || {
    echo "Adding IP address $IP"
    ubus call "IP.Interface" _add '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.", "parameters": { "Alias": "wan", "AddressingType": "Static" } }'
    echo conf_file_exit_code=$?
}
# Configure it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.1", "parameters": { "IPAddress": "192.168.250.130", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Enable" : true } }'
echo conf_file_exit_code=$?
# Enable it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].", "parameters": { "IPv4Enable": true } }'
echo conf_file_exit_code=$?

# Set the LAN bridge IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"br-lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.100.130" } }'
echo conf_file_exit_code=$?

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='lan3'
echo conf_file_exit_code=$?
uci commit
echo conf_file_exit_code=$?

# enable Wi-Fi radios
ubus call "WiFi.Radio" _set '{ "rel_path": ".[OperatingFrequencyBand == \"2.4GHz\"].", "parameters": { "Enable": "true" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.Radio" _set '{ "rel_path": ".[OperatingFrequencyBand == \"5GHz\"].", "parameters": { "Enable": "true" } }'
echo conf_file_exit_code=$?

# all pwhm default configuration can be found in /etc/amx/wld/wld_defaults.odl.uc

# Restart the ssh server
sh /etc/init.d/ssh-server restart
echo conf_file_exit_code=$?

# Required for config_load:
. /lib/functions/system.sh
echo conf_file_exit_code=$?
# Required for config_foreach:
. /lib/functions.sh
echo conf_file_exit_code=$?

# add private vaps to lan to workaround Netmodel missing wlan mib
# this must be reverted once Netmodel version is integrated
# brctl addif br-lan wlan0 > /dev/null 2>&1 || true
# brctl addif br-lan wlan1 > /dev/null 2>&1 || true

# configure private vaps
ubus call "WiFi.SSID.1" _set '{ "parameters": { "SSID": "prplmesh" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.SSID.3" _set '{ "parameters": { "SSID": "prplmesh" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.AccessPoint.1.Security" _set '{ "parameters": { "KeyPassPhrase": "prplmesh_pass" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.AccessPoint.3.Security" _set '{ "parameters": { "KeyPassPhrase": "prplmesh_pass" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.AccessPoint.1.Security" _set '{ "parameters": { "ModeEnabled": "WPA2-Personal" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.AccessPoint.3.Security" _set '{ "parameters": { "ModeEnabled": "WPA2-Personal" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.AccessPoint.1.WPS" _set '{ "parameters": { "ConfigMethodsEnabled": "PushButton" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.AccessPoint.3.WPS" _set '{ "parameters": { "ConfigMethodsEnabled": "PushButton" } }'
echo conf_file_exit_code=$?

ubus-cli "WiFi.AccessPoint.1.MBOEnable=1"
echo conf_file_exit_code=$?
ubus-cli "WiFi.AccessPoint.2.MBOEnable=1"
echo conf_file_exit_code=$?
ubus-cli "WiFi.AccessPoint.3.MBOEnable=1"
echo conf_file_exit_code=$?
ubus-cli "WiFi.AccessPoint.4.MBOEnable=1"
echo conf_file_exit_code=$?
ubus-cli "WiFi.AccessPoint.5.MBOEnable=1"
echo conf_file_exit_code=$?
ubus-cli "WiFi.AccessPoint.6.MBOEnable=1"
echo conf_file_exit_code=$?

# Make sure specific channels are configured. If channel is set to 0,
# ACS will be configured. If ACS is configured hostapd will refuse to
# switch channels when we ask it to. Channels 1 and 48 were chosen
# because they are NOT used in the WFA certification tests (this
# allows to verify that the device actually switches channel as part
# of the test).
# See also PPM-1928.
ubus call "WiFi.Radio" _set '{ "rel_path": ".[OperatingFrequencyBand == \"2.4GHz\"].", "parameters": { "Channel": "1" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.Radio" _set '{ "rel_path": ".[OperatingFrequencyBand == \"5GHz\"].", "parameters": { "Channel": "48" } }'
echo conf_file_exit_code=$?

# Restrict channel bandwidth or the certification test could miss beacons
# (see PPM-258)
ubus call "WiFi.Radio" _set '{ "rel_path": ".[OperatingFrequencyBand == \"2.4GHz\"].", "parameters": { "OperatingChannelBandwidth": "20MHz" } }'
echo conf_file_exit_code=$?
ubus call "WiFi.Radio" _set '{ "rel_path": ".[OperatingFrequencyBand == \"5GHz\"].", "parameters": { "OperatingChannelBandwidth": "20MHz" } }'
echo conf_file_exit_code=$?

sleep 10
echo conf_file_exit_code=$?

# Try to work around PCF-681: if we don't have a connectivity, restart
# tr181-bridging
# Check the status of the LAN bridge
ip a |grep "br-lan:" |grep "state UP" >/dev/null || (echo "LAN Bridge DOWN, restarting bridge manager" && sh /etc/init.d/tr181-bridging restart && sleep 15)
echo conf_file_exit_code=$?

# If we still can't ping the UCC, restart the IP manager
ping -i 1 -c 2 192.168.250.199 || (sh /etc/init.d/ip-manager restart && sleep 15)
echo conf_file_exit_code=$?
ping -i 1 -c 2 192.168.250.199 || (sh /etc/init.d/ip-manager restart && sleep 15)
echo conf_file_exit_code=$?

# Remove the default lan/wan SSH servers if they exist
# ubus call "SSH.Server" _del '{ "rel_path": ".[Alias == \"lan\"]" }' || true
# ubus call "SSH.Server" _del '{ "rel_path": ".[Alias == \"wan\"]" }' || true

# Trigger the startup of the SSH server
# The SSH server on eth0 has some problems starting through the server component
# Launch a server on the control IP later
# ubus call "SSH.Server" _set '{ "rel_path": ".[Alias == \"control\"].", "parameters": { "Enable": false } }'
# sleep 5
# ubus call "SSH.Server" _set '{ "rel_path": ".[Alias == \"control\"].", "parameters": { "Enable": true } }'

# Stop the default ssh server on the lan-bridge
sh /etc/init.d/ssh-server stop || true
echo conf_file_exit_code=$?
sleep 5
echo conf_file_exit_code=$?

# Add command to start dropbear to rc.local to allow SSH access after reboot
BOOTSCRIPT="/etc/rc.local"
SERVER_CMD="sleep 20 && sh /etc/init.d/ssh-server stop && dropbear -F -T 10 -p192.168.250.130:22 &"
echo conf_file_exit_code=$?
if ! grep -q "$SERVER_CMD" "$BOOTSCRIPT"; then { head -n -2 "$BOOTSCRIPT"; echo "$SERVER_CMD"; tail -2 "$BOOTSCRIPT"; } >> btscript.tmp; mv btscript.tmp "$BOOTSCRIPT"; fi
echo conf_file_exit_code=$?

# Stop and disable the firewall:
sh /etc/init.d/tr181-firewall stop
echo conf_file_exit_code=$?
rm -f /etc/rc.d/S22tr181-firewall
echo conf_file_exit_code=$?

# Start an ssh server on the control interfce
dropbear -F -T 10 -p192.168.250.130:22 &
