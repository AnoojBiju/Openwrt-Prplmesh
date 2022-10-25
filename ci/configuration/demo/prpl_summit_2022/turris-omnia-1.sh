#!/bin/sh

# Set the LAN IP::
dmcli eRT setvalues Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanIPAddress string 192.168.250.170 true
dmcli eRT setvalues Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanNetwork string 192.168.250.0

# There is a script that hard-codes the brlan0 IP at boot time.
# Replace the default IP with our IP:
sed -ri 's/ifconfig brlan0 10.0.0.1/ifconfig brlan0 192.168.250.170/g' /lib/rdk/hostapd-init.sh

# Allow SSH on LAN:
iptables -D INPUT -i brlan0 -p tcp -m tcp --dport 22 -j DROP
# Make sure it's not applied again after a reboot:
# shellcheck disable=SC2016
sed -i '/iptables -A INPUT -i $lan_ifname -p tcp --dport 22 -j DROP/d' /etc/utopia/utopia_init.sh

# Configure the wired backhaul interface:
sed -ri 's/backhaul_wire_iface=erouter0/backhaul_wire_iface=lan0/' /opt/prplmesh/share/prplmesh_platform_db

# Configure the device as an agent:
sed -ri 's/management_mode=.*$/management_mode=Multi-AP-Agent/g' /opt/prplmesh/share/prplmesh_platform_db
sed -ri 's/management_mode=.*$/operating_mode=WDS-Repeater/g' /opt/prplmesh/share/prplmesh_platform_db

# The init script doesn't handle the mode properly.
# Override it to start the agent only:
printf >/tmp/prplmesh-override.conf '
[Service]
ExecStart=
ExecStart=/opt/prplmesh/scripts/prplmesh_utils.sh start -m a
'
env SYSTEMD_EDITOR="cp /tmp/prplmesh-override.conf" systemctl edit prplmesh
systemctl daemon-reload
