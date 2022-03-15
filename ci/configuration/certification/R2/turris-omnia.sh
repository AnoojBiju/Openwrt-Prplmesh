#!/bin/sh

set -e

# We use WAN for the control interface:
uci batch << 'EOF'
set network.control=interface
set network.control.type='bridge'
set network.control.proto='static'
set network.control.netmask='255.255.255.0'
set network.control.ipaddr='192.168.250.170'
set network.control.ifname='eth2'
del network.wan
set network.lan.ipaddr=192.165.100.170
EOF

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='lan0'

# Stop and disable the firewall:
/etc/init.d/tr181-firewall stop
rm -f /etc/rc.d/S22tr181-firewall

uci commit
/etc/init.d/network restart
