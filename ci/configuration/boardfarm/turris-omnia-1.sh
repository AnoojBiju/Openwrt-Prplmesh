#!/bin/sh

set -e

# IP for device upgrades, operational tests, Boardfarm data network, ...
# Note that this device uses the WAN interface (as on some Omnias the
# others don't work in the bootloader):
uci batch << 'EOF'
set network.wan.proto='static'
set network.wan.netmask='255.255.255.0'
set network.wan.ipaddr='192.168.1.100'
set network.lan.ipaddr='192.168.0.100'
EOF

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth2'

# Stop and disable the firewall:
/etc/init.d/tr181-firewall stop
rm -f /etc/rc.d/S22tr181-firewall

uci commit
/etc/init.d/network restart
