#!/bin/sh

# We need to source some files which are only available on prplWrt
# devices, so prevent shellcheck from trying to read them:
# shellcheck disable=SC1091

set -e

# Start with a new log file:
rm -f /var/log/messages && syslog-ng-ctl reload

# Restore the services in case they were removed by other pipelines:
cp /rom/etc/rc.d/S27tr181-dhcpv4client /etc/rc.d/S27tr181-dhcpv4client
cp /rom//etc/rc.d/S25tr181-dhcpv6client /etc/rc.d/S25tr181-dhcpv6client
/etc/rc.d/S27tr181-dhcpv4client restart
/etc/init.d/tr181-dhcpv6client restart

# Stop and disable the DHCP clients and servers:
ubus wait_for DHCPv4.Client.1
ubus call DHCPv4.Client.1 _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv6.Client.1
ubus call DHCPv6.Client.1 _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv4.Server
ubus call DHCPv4.Server _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv6.Server
ubus call DHCPv6.Server _set '{"parameters": { "Enable": False }}'

# IP for device upgrades, operational tests, Boardfarm data network, ...
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.168.1.110" } }'

# enable Wi-Fi radios
ubus call "WiFi.Radio.1" _set '{ "parameters": { "Enable": "true" } }'
ubus call "WiFi.Radio.2" _set '{ "parameters": { "Enable": "true" } }'

# all pwhm default configuration can be found in /etc/amx/wld/wld_defaults.odl.uc

# For now there is no way to disable the firewall (see PCF-590).
# Instead, wait for it in the datamodel, then set the whole INPUT
# chain to ACCEPT:
ubus wait_for Firewall
iptables -P INPUT ACCEPT

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

# Try to work around PCF-681: if we don't have a connectivity, restart
# tr181-bridging
ping 192.168.1.2 -c 3 || /etc/init.d/tr181-bridging restart
