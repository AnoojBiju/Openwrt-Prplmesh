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
sleep 2

# Stop and disable the miniupnpd as it is logging a lot
/etc/init.d/tr181-upnp stop
rm -f /etc/rc.d/*tr181-upnp
pkill -9 miniupnpd

# disable firewall
/etc/init.d/tr181-firewall stop ; sleep 2 ; /etc/init.d/tr181-firewall stop
rm -f /etc/rc.d/*tr181-firewall

ubus wait_for IP.Interface

# Stop and disable the DHCP clients:
ubus call DHCPv4.Client _set '{ "rel_path": "[Alias == \"wan\"].", "parameters":{"Enable":false}}'
ubus call DHCPv6.Client _set '{ "rel_path": "[Alias == \"wan\"].", "parameters":{"Enable":false}}'
/etc/init.d/tr181-dhcpv4client stop
rm -f /etc/rc.d/*tr181-dhcpv4client
/etc/init.d/tr181-dhcpv6client stop
rm -f /etc/rc.d/*tr181-dhcpv6client

# IP for device upgrades, operational tests, Boardfarm data network, ...
# Note that this device uses the WAN interface (as on some Omnias the
# others don't work in the bootloader):

# Set a LAN IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.0.100" } }'
# Set a WAN IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.1", "parameters": { "IPAddress": "192.168.1.100", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Enable" : true } }'

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth2'
uci commit

# enable Wi-Fi radios
ubus call "WiFi.Radio.1" _set '{ "parameters": { "Enable": "true" } }'
ubus call "WiFi.Radio.2" _set '{ "parameters": { "Enable": "true" } }'

# all pwhm default configuration can be found in /etc/amx/wld/wld_defaults.odl.uc

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

ping -i 1 -c 2 192.168.1.2 || (/etc/init.d/ip-manager restart && sleep 12)

# Start an ssh server on the control interfce
# The ssh server that is already running will only accept connections from 
# the IP interface that was configured with the IP-Manager
dropbear -F -T 10 -p192.168.1.100:22 &
