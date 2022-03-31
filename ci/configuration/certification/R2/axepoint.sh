#!/bin/sh

set -e

# Start with a new log file:
rm -f /var/log/messages && syslog-ng-ctl reload

# One of the LAN ports is used for control, and the WAN port for data:
uci batch << 'EOF'
set network.cert=interface
set network.cert.proto='static'
set network.cert.ifname='eth0_4'
set network.cert.ipaddr='192.168.250.173'
set network.cert.netmask='255.255.255.0'
set network.lan.ipaddr='192.165.100.173'
set network.lan.ifname='eth1 eth0_1 eth0_2 eth0_3'
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

# set protected managment frames capability (pmf) to optional for wireless interfaces (supplicants)
set wireless.default_radio26.pmf='1'
set wireless.default_radio58.pmf='1'

##############################################################

# radios are disabled by default in prplwrt
set wireless.radio0.disabled=0
set wireless.radio2.disabled=0
EOF

uci commit
/etc/init.d/system restart
/etc/init.d/network restart
