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

# Stop and disable the DHCP clients:
/etc/init.d/tr181-dhcpv4client stop
rm -f /etc/rc.d/S27tr181-dhcpv4client
/etc/init.d/tr181-dhcpv6client stop
rm -f /etc/rc.d/S25tr181-dhcpv6client

# Since for the GL-inet eth0 (LAN) is always detected as UP, eth1 (WAN) will be configured as a backhaul interface
# This allows prplMesh to detect the state of the backhaul interface
# WAN and LAN interfaces are effectively switched

# Remove the physical LAN interface from the LAN-bridge; it will become the control interface
# Also add the WAN interface to the LAN-bridge
# Set the LAN bridge IP:
ubus wait_for IP.Interface
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"br-lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.100.172" } }'

# Move the WAN port into the LAN bridge if it's not there yet (to use it for data):
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth1\"]." }' || {
    echo "Adding WAN interface to LAN-bridge"
    ubus call "Bridging.Bridge" _add '{ "rel_path": ".[Alias == \"lan\"].Port.",  "parameters": { "Name": "eth1", "Alias": "ETH1", "Enable": true } }'
}

# One of the LAN ports is used for control. Create a section for it:
uci set network.cert=interface
# Setting ifname is not supported in the current version of the TR-181
# IP manager (v1.11.1), set it in UCI instead:
uci set network.cert.ifname='eth0'

# Remove the control interface from the LAN bridge if it's not already the case:
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth0\"]." }' && {
    echo "Removing LAN interface from LAN-bridge"
    echo "It will be used as control interface"
    ubus call "Bridging.Bridge" _del '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth0\"]." }'
}

# To set the IP on the control interface, we first need to find the
# corresponding Ethernet.Interface:
ETH_IF="$(ubus call Ethernet.Interface _list | jsonfilter -e '@.instances[@.name="ETH0"].index')"
# Then if there is no corresponding Ethernet.Link yet, we need to add
# one:
ubus call Ethernet.Link _get '{ "rel_path": ".[Name == \"eth0\"]." }' || {
    echo "Adding Ethernet Link for LAN interface"
    ETH_LINK="$(ubus call Ethernet.Link _add "{ \"parameters\": { \"Name\": \"eth0\", \"Alias\": \"eth0\",\"LowerLayers\": \"Device.Ethernet.Interface.$ETH_IF.\", \"Enable\": true } }" | jsonfilter -e '@.index')"
}
# We can now create an IP.Interface if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Name == \"eth0\"]." }' || {
    echo "Adding IP.Interface"
    ubus call IP.Interface _add "{ \"parameters\": { \"Name\": \"eth0\", \"UCISectionNameIPv4\": \"cert\", \"Alias\": \"eth0\", \"LowerLayers\": \"Device.Ethernet.Link.$ETH_LINK.\", \"Enable\": true } }"
}
# We can now add the IP address if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Name == \"eth0\"].IPv4Address.[Alias == \"eth0\"]." }' || {
    echo "Adding IP address $IP"
    ubus call "IP.Interface" _add '{ "rel_path": ".[Name == \"eth0\"].IPv4Address.", "parameters": { "IPAddress": "192.168.250.172", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Alias": "eth0", "Enable" : true } }'
}
# Finally, we can enable it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"eth0\"].", "parameters": { "IPv4Enable": true } }'

# Wired backhaul interface:
# Set the WAN interface as backhaul interface
uci set prplmesh.config.backhaul_wire_iface='eth1'

# Stop and disable the firewall:
/etc/init.d/tr181-firewall stop
rm -f /etc/rc.d/S22tr181-firewall

# Required for config_load:
. /lib/functions/system.sh
# Required for config_foreach:
. /lib/functions.sh

# Regenerate configuration:
# Delete wireless configuration and create a fresh new one from scratch to make sure there is no
# side effect due to an existing setting.

logger -t prplmesh -p daemon.info "Applying wifi configuration."
rm -f /etc/config/wireless
wifi config

uci batch << 'EOF'
set wireless.default_radio0=wifi-iface
set wireless.default_radio0.device='radio0'
set wireless.default_radio0.network='lan'
set wireless.default_radio0.mode='ap'
set wireless.default_radio0.key='prplmesh_pass'
set wireless.default_radio0.encryption='psk2'
set wireless.default_radio0.ssid='prplmesh'
set wireless.default_radio0.wps_pushbutton='1'
set wireless.default_radio0.ieee80211v='1'
set wireless.default_radio0.bss_transition='1'

set wireless.default_radio1=wifi-iface
set wireless.default_radio1.device='radio1'
set wireless.default_radio1.network='lan'
set wireless.default_radio1.mode='ap'
set wireless.default_radio1.key='prplmesh_pass'
set wireless.default_radio1.encryption='psk2'
set wireless.default_radio1.ssid='prplmesh'
set wireless.default_radio1.wps_pushbutton='1'
set wireless.default_radio1.ieee80211v='1'
set wireless.default_radio1.bss_transition='1'

set wireless.default_radio10=wifi-iface
set wireless.default_radio10.device='radio0'
set wireless.default_radio10.network='lan'
set wireless.default_radio10.mode='ap'
set wireless.default_radio10.key='prplmesh_pass'
set wireless.default_radio10.encryption='psk2'
set wireless.default_radio10.ssid='prplmesh'
set wireless.default_radio10.ieee80211v='1'
set wireless.default_radio10.bss_transition='1'

set wireless.default_radio20=wifi-iface
set wireless.default_radio20.device='radio1'
set wireless.default_radio20.network='lan'
set wireless.default_radio20.mode='ap'
set wireless.default_radio20.key='prplmesh_pass'
set wireless.default_radio20.encryption='psk2'
set wireless.default_radio20.ssid='prplmesh'
set wireless.default_radio20.ieee80211v='1'
set wireless.default_radio20.bss_transition='1'

set wireless.default_radio11=wifi-iface
set wireless.default_radio11.device='radio0'
set wireless.default_radio11.mode='sta'
set wireless.default_radio11.wps_pushbutton='1'
set wireless.default_radio11.wps_config='push_button'
set wireless.default_radio11.network='lan'
set wireless.default_radio11.multi_ap='1'
set wireless.default_radio11.default_disabled='1'

set wireless.default_radio21=wifi-iface
set wireless.default_radio21.device='radio1'
set wireless.default_radio21.mode='sta'
set wireless.default_radio21.wps_pushbutton='1'
set wireless.default_radio21.wps_config='push_button'
set wireless.default_radio21.network='lan'
set wireless.default_radio21.multi_ap='1'
set wireless.default_radio21.default_disabled='1'

# Use the interface names that are automatically assigned by OpenWrt
set prplmesh.radio0.hostap_iface='wlan0-1'
set prplmesh.radio0.sta_iface='wlan0'
set prplmesh.radio0.hostap_iface_steer_vaps='wlan0-2'
set prplmesh.radio1.sta_iface='wlan1'
set prplmesh.radio1.hostap_iface='wlan1-1'
set prplmesh.radio1.hostap_iface_steer_vaps='wlan1-2'

set wireless.radio0.disabled=0
set wireless.radio1.disabled=0
EOF

# Delete the guest network interfaces, they're not supported by
# prplMesh yet (PPM-2019):
uci del wireless.guest_radio0
uci del wireless.guest_radio1

# Make sure specific channels are configured. If channel is set to 0,
# ACS will be configured. If ACS is configured hostapd will refuse to
# switch channels when we ask it to. Channels 1 and 48 were chosen
# because they are NOT used in the WFA certification tests (this
# allows to verify that the device actually switches channel as part
# of the test).
# See also PPM-1928.
set_channel() {
    if [ "$(uci get "wireless.${1}.hwmode")" = "11g" ] ; then
        uci set "wireless.${1}.channel"=1
    else
        uci set "wireless.${1}.channel"=48
        # TODO: The current channel selection does not work correctly when
        # 80Mhz bandwidths are involved.  This temporary workaround forces
        # the use of 20Mhz bands, and will need to be reverted when the
        # issue is fixed (see
        # https://jira.prplfoundation.org/browse/PPM-258)
        uci set "wireless.${1}.htmode"=HT20
    fi

    logger "Channel for ${1} set to \"$(uci get "wireless.${1}.channel")\""
}

config_load wireless
config_foreach set_channel wifi-device

uci commit
/etc/init.d/system restart
/etc/init.d/network restart
