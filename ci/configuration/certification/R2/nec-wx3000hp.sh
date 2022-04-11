#!/bin/sh

set -e

# Start with a new log file:
rm -f /var/log/messages && syslog-ng-ctl reload

# One of the LAN ports is used for control, and the WAN port for data:
uci batch << 'EOF'
set network.cert=interface
set network.cert.proto='static'
set network.cert.ifname='eth0_4'
set network.cert.ipaddr='192.168.250.171'
set network.cert.netmask='255.255.255.0'
set network.lan.ipaddr='192.165.100.171'
set network.lan.ifname='eth0_1 eth0_2 eth0_3 eth1'
EOF

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth1'

# Stop and disable the firewall:
/etc/init.d/tr181-firewall stop
rm -f /etc/rc.d/S22tr181-firewall

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
