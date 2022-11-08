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

ubus wait_for IP.Interface

# Stop and disable the DHCP clients:
/etc/init.d/tr181-dhcpv4client stop
rm -f /etc/rc.d/S27tr181-dhcpv4client
/etc/init.d/tr181-dhcpv6client stop
rm -f /etc/rc.d/S25tr181-dhcpv6client

# IP for device upgrades, operational tests, Boardfarm data network, ...
# Note that this device uses the WAN interface (as on some Omnias the
# others don't work in the bootloader):
# Add the IP address if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.[Alias == \"wan\"]." }' || {
    echo "Adding IP address $IP"
    ubus call "IP.Interface" _add '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.", "parameters": { "Alias": "wan", "AddressingType": "Static" } }'
}
# Configure it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].IPv4Address.1", "parameters": { "IPAddress": "192.168.1.100", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Enable" : true } }'
# Enable it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"wan\"].", "parameters": { "IPv4Enable": true } }'

# Set a LAN IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.0.100" } }'

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth2'

# VLAN interface to control the device separatly:
uci batch << 'EOF'
set network.UCC=interface
set network.UCC.ifname='eth2.200'
set network.UCC.proto='static'
set network.UCC.netmask='255.255.255.0'
set network.UCC.ipaddr='192.168.200.100'
EOF

uci batch << 'EOF'
add network switch_vlan
set network.@switch_vlan[-1].device='switch0'
set network.@switch_vlan[-1].vlan='200'
set network.@switch_vlan[-1].ports='0'
EOF

# For now there is no way to disable the firewall (see PCF-590).
# Instead, wait for it in the datamodel, then set the whole INPUT
# chain to ACCEPT:
ubus wait_for Firewall
iptables -P INPUT ACCEPT

# Required for config_load:
. /lib/functions/system.sh
# Required for config_foreach:
. /lib/functions.sh

# Regenerate configuration:
# Delete wireless configuration and create a fresh new one from scratch to make sure there is no
# side effect due to an existing setting.

#logger -t prplmesh -p daemon.info "Applying wifi configuration."
#rm -f /etc/config/wireless
#wifi config

uci commit
