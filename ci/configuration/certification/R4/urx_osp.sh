#!/bin/sh

set -e

# Start with a new log file:
rm -f /var/log/messages ; syslog-ng-ctl reload || true

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
sleep 25

ubus wait_for IP.Interface

# Stop and disable the DHCP clients:
/etc/init.d/tr181-dhcpv4client stop
rm -f /etc/rc.d/S27tr181-dhcpv4client
/etc/init.d/tr181-dhcpv6client stop
rm -f /etc/rc.d/S25tr181-dhcpv6client

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

# For now there is no way to disable the firewall (see PCF-590).
# Instead, wait for it in the datamodel, then set the whole INPUT
# chain to ACCEPT:
ubus wait_for Firewall
iptables -P INPUT ACCEPT

# wireless.radio0.band='2.4GHz'
# wireless.radio2.band='5GHz'
# wireless.radio4.band='6GHz'
# wireless.radio6.band='5GHz'

uci batch << 'EOF'
# TODO: The current channel selection does not work correctly when 80Mhz bandwidths are involved.
# This temporary workaround forces the use of 20Mhz bands, and will need to be reverted when the 
# issue is fixed (see https://jira.prplfoundation.org/browse/PPM-258)
set wireless.radio0.htmode='HT20'
set wireless.radio2.htmode='HT20'
set wireless.radio4.htmode='HT20'
set wireless.radio6.htmode='HT20'

################ needed for R2 certification #################
# Enable action/managment frames hostapd notifiecations
set wireless.radio0.notify_action_frame='1'
set wireless.radio2.notify_action_frame='1'
set wireless.radio4.notify_action_frame='1'
set wireless.radio6.notify_action_frame='1'
##############################################################

# Add backhaul STAs:
set wireless.default_radio26=wifi-iface
set wireless.default_radio26.device=radio0
set wireless.default_radio26.ifname=wlan0
set wireless.default_radio26.mode=sta
set wireless.default_radio26.config_methods=push_button
set wireless.default_radio26.wds=1
set wireless.default_radio26.multi_ap_profile=2
set wireless.default_radio26.pmf=1

set wireless.default_radio58=wifi-iface
set wireless.default_radio58.device=radio2
set wireless.default_radio58.ifname=wlan2
set wireless.default_radio58.mode=sta
set wireless.default_radio58.config_methods=push_button
set wireless.default_radio58.wds=1
set wireless.default_radio58.multi_ap_profile=2
set wireless.default_radio58.pmf=1

set wireless.default_radio68=wifi-iface
set wireless.default_radio68.device=radio6
set wireless.default_radio68.ifname=wlan6
set wireless.default_radio68.mode=sta
set wireless.default_radio68.config_methods=push_button
set wireless.default_radio68.wds=1
set wireless.default_radio68.multi_ap_profile=2
set wireless.default_radio68.pmf=1

# Make guest interfaces part of lan again until prplMesh supports it (PPM-2019):
# set wireless.default_radio11.network='lan'
# set wireless.default_radio11.ssid='prplOS'
# set wireless.default_radio43.network='lan'
# set wireless.default_radio43.ssid='prplOS'
EOF

# Generate a MAC address for the new bSTA interfaces:
# sh /rom/etc/uci-defaults/15_wireless-generate-macaddr || true

uci commit
/etc/init.d/system restart
#/etc/init.d/network restart
sleep 10

# Try to work around PCF-681: if we don't have a connectivity, restart
# tr181-bridging
# Check the status of the LAN bridge
ip a |grep "br-lan:" |grep "state UP" >/dev/null || (echo "LAN Bridge DOWN, restarting bridge manager" && /etc/init.d/tr181-bridging restart && sleep 15)
# If we can't ping the UCC, restart the IP manager
ping -i 1 -c 2 192.168.250.199 || (/etc/init.d/ip-manager restart && sleep 12)

# Restart the ssh server
# /etc/init.d/ssh-server restart
# sleep 10

# Start an ssh server on the control interfce
# The ssh server that is already running will only accept connections from 
# the IP interface that was configured with the IP-Manager
dropbear -F -T 10 -p192.168.250.120:22 &
