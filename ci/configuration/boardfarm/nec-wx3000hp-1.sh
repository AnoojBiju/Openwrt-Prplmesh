#!/bin/sh

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

# Stop and disable the DHCP clients:
/etc/init.d/tr181-dhcpv4client stop
rm -f /etc/rc.d/S27tr181-dhcpv4client
/etc/init.d/tr181-dhcpv6client stop
rm -f /etc/rc.d/S25tr181-dhcpv6client

# IP for device upgrades, operational tests, Boardfarm data network, ...
ubus wait_for IP.Interface
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"br-lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.168.1.130" } }'

# VLAN interface to control the device separatly:
uci batch << 'EOF'
set network.UCC=interface
set network.UCC.ifname='eth0_1.200'
set network.UCC.proto='static'
set network.UCC.netmask='255.255.255.0'
set network.UCC.ipaddr='192.168.200.130'
EOF

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth0_1'

# For now there is no way to disable the firewall (see PCF-590).
# Instead, wait for it in the datamodel, then set the whole INPUT
# chain to ACCEPT:
ubus wait_for Firewall
iptables -P INPUT ACCEPT

uci batch << 'EOF'
# TODO: The current channel selection does not work correctly when 80Mhz bandwidths are involved.
# This temporary workaround forces the use of 20Mhz bands, and will need to be reverted when the 
# issue is fixed (see https://jira.prplfoundation.org/browse/PPM-258)
set wireless.radio0.htmode='HT20'
set wireless.radio2.htmode='HT20'

################ needed for R2 certification #################
# Enable action/managment frames hostapd notifiecations
set wireless.radio0.notify_action_frame='1'
set wireless.radio2.notify_action_frame='1'
##############################################################

# Add backhaul STAs:
set wireless.default_radio26=wifi-iface
set wireless.default_radio26.device=radio0
set wireless.default_radio26.ifname=wlan1
set wireless.default_radio26.mode=sta
set wireless.default_radio26.config_methods=push_button
set wireless.default_radio26.wds=1
set wireless.default_radio26.multi_ap_profile=2
set wireless.default_radio26.pmf1

set wireless.default_radio58=wifi-iface
set wireless.default_radio58.device=radio2
set wireless.default_radio58.ifname=wlan3
set wireless.default_radio58.mode=sta
set wireless.default_radio58.config_methods=push_button
set wireless.default_radio58.wds=1
set wireless.default_radio58.multi_ap_profile=2
set wireless.default_radio58.pmf1

# radios are disabled by default in prplwrt
set wireless.radio0.disabled=0
set wireless.default_radio100.start_disabled=0
set wireless.radio2.disabled=0
set wireless.default_radio102.start_disabled=0

# Make guest interfaces part of lan again until prplMesh supports it (PPM-2019):
set wireless.default_radio11.network='lan'
set wireless.default_radio11.ssid='prplOS'
set wireless.default_radio43.network='lan'
set wireless.default_radio43.ssid='prplOS'
EOF

# Generate a MAC address for the new bSTA interfaces:
sh /rom/etc/uci-defaults/15_wireless-generate-macaddr || true

uci commit
/etc/init.d/system restart
/etc/init.d/network restart
