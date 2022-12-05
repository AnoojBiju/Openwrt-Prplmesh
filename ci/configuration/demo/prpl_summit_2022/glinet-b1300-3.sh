#!/bin/sh

# We need to source some files which are only available on prplWrt
# devices, so prevent shellcheck from trying to read them:
# shellcheck disable=SC1091

set -e

# Stop and disable the DHCP clients and servers:
ubus wait_for DHCPv4.Client.1
ubus call DHCPv4.Client.1 _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv6.Client.1
ubus call DHCPv6.Client.1 _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv4.Server
ubus call DHCPv4.Server _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv6.Server
ubus call DHCPv6.Server _set '{"parameters": { "Enable": False }}'

# We don't want to save the credentials obtained through WPS (because of PPM-1717 we can't make use of them anyway, we have to re-do WPS after reboot):
sed -ri '/\|\| wps_catch_credentials \&/d' /etc/rc.button/wps

# Save the IP settings persistently:
ubus wait_for IP.Interface
sed -ri 's/(dm-save.*) = false/\1 = true/g' /etc/amx/ip-manager/ip-manager.odl
/etc/init.d/ip-manager restart

ubus wait_for Firewall
iptables -P INPUT ACCEPT

# Set the LAN bridge IP:
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"br-lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.165.100.175" } }'

# Move the WAN port into the LAN bridge if it's not there yet (to use it for data):
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth1\"]." }' || {
    echo "Adding interface to bridge"
    ubus call "Bridging.Bridge" _add '{ "rel_path": ".[Alias == \"lan\"].Port.",  "parameters": { "Name": "eth1", "Alias": "ETH1", "Enable": true } }'
}

# One of the LAN ports is used for control. Create a section for it:
uci set network.cert=interface
# Setting ifname is not supported in the current version of the TR-181
# IP manager (v1.11.1), set it in UCI instead:
uci set network.cert.ifname='eth0'
uci commit

# Remove the control interface from the LAN bridge if it's not already the case:
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth0\"]." }' && {
    echo "Removing interface from bridge"
    ubus call "Bridging.Bridge" _del '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth0\"]." }'
}

# To set the IP on the control interface, we first need to find the
# corresponding Ethernet.Interface:
ETH_IF="$(ubus call Ethernet.Interface _list | jsonfilter -e '@.instances[@.name="ETH0"].index')"
# Then if there is no corresponding Ethernet.Link yet, we need to add
# one:
ubus call Ethernet.Link _get '{ "rel_path": ".[Name == \"eth0\"]." }' || {
    echo "Adding Ethernet Link"
    ETH_LINK="$(ubus call Ethernet.Link _add "{ \"parameters\": { \"Name\": \"eth0\", \"Alias\": \"eth0\",\"LowerLayers\": \"Device.Ethernet.Interface.$ETH_IF.\", \"Enable\": true } }" | jsonfilter -e '@.index')"
}

/etc/init.d/ip-manager restart
# We can now create an IP.Interface if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Name == \"eth0\"]." }' || {
    echo "Adding IP.Interface"
    ubus call IP.Interface _add "{ \"parameters\": { \"Name\": \"eth0\", \"UCISectionNameIPv4\": \"cert\", \"Alias\": \"eth0\", \"LowerLayers\": \"Device.Ethernet.Link.$ETH_LINK.\", \"Enable\": true } }"
}
# We can now add the IP address if there is none yet:
ubus call IP.Interface _get '{ "rel_path": ".[Name == \"eth0\"].IPv4Address.[Alias == \"eth0\"]." }' || {
    echo "Adding IP address $IP"
    ubus call "IP.Interface" _add '{ "rel_path": ".[Name == \"eth0\"].IPv4Address.", "parameters": { "IPAddress": "192.168.250.175", "SubnetMask": "255.255.255.0", "AddressingType": "Static", "Alias": "eth0", "Enable" : true } }'
}
# Finally, we can enable it:
ubus call "IP.Interface" _set '{ "rel_path": ".[Name == \"eth0\"].", "parameters": { "IPv4Enable": true } }'

# Wired backhaul interface:
uci set prplmesh.config.backhaul_wire_iface='eth1'

uci set system.@system[0].hostname='glinet-b1300-3'
uci commit
/etc/init.d/system restart

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

# Be careful to have only one backhaul STA. Since we don't have any
# backhaul management yet, leaving it enabled would create a loop
# since the two wireless interfaces would connect.  Also don't set
# default_disabled to 1 on the backhaul STA, as otherwise it won't
# reconnect after a reboot.
uci batch << 'EOF'
set wireless.default_radio0=wifi-iface
set wireless.default_radio0.device='radio0'
set wireless.default_radio0.network='lan'
set wireless.default_radio0.mode='ap'
set wireless.default_radio0.key='prplmesh_pass'
set wireless.default_radio0.encryption='psk2'
set wireless.default_radio0.ssid='prplmesh_demo'
set wireless.default_radio0.wps_pushbutton='1'
set wireless.default_radio0.ieee80211v='1'
set wireless.default_radio0.bss_transition='1'

set wireless.default_radio1=wifi-iface
set wireless.default_radio1.device='radio1'
set wireless.default_radio1.network='lan'
set wireless.default_radio1.mode='ap'
set wireless.default_radio1.key='prplmesh_pass'
set wireless.default_radio1.encryption='psk2'
set wireless.default_radio1.ssid='prplmesh_demo'
set wireless.default_radio1.wps_pushbutton='1'
set wireless.default_radio1.ieee80211v='1'
set wireless.default_radio1.bss_transition='1'

set wireless.default_radio10=wifi-iface
set wireless.default_radio10.device='radio0'
set wireless.default_radio10.network='lan'
set wireless.default_radio10.mode='ap'
set wireless.default_radio10.key='prplmesh_pass'
set wireless.default_radio10.encryption='psk2'
set wireless.default_radio10.ssid='prplmesh_demo'
set wireless.default_radio10.ieee80211v='1'
set wireless.default_radio10.bss_transition='1'

set wireless.default_radio20=wifi-iface
set wireless.default_radio20.device='radio1'
set wireless.default_radio20.network='lan'
set wireless.default_radio20.mode='ap'
set wireless.default_radio20.key='prplmesh_pass'
set wireless.default_radio20.encryption='psk2'
set wireless.default_radio20.ssid='prplmesh_demo'
set wireless.default_radio20.ieee80211v='1'
set wireless.default_radio20.bss_transition='1'

set wireless.default_radio11=wifi-iface
set wireless.default_radio11.device='radio0'
set wireless.default_radio11.mode='sta'
set wireless.default_radio11.wps_pushbutton='1'
set wireless.default_radio11.wps_config='push_button'
set wireless.default_radio11.network='lan'
set wireless.default_radio11.multi_ap='1'

# Use the interface names that are automatically assigned by OpenWrt
set prplmesh.radio0.hostap_iface='wlan0-1'
set prplmesh.radio0.sta_iface='wlan0'
set prplmesh.radio0.hostap_iface_steer_vaps='wlan0-2'
set prplmesh.radio1.hostap_iface='wlan1-1'
set prplmesh.radio1.hostap_iface_steer_vaps='wlan1-2'
del prplmesh.radio1.sta_iface
prplmesh.config.backhaul_wire_iface='eth1'

set wireless.radio0.disabled=0
set wireless.radio1.disabled=0
EOF

uci set prplmesh.config.management_mode='Multi-AP-Agent'
uci set prplmesh.config.operating_mode='WDS-Repeater'
uci set prplmesh.config.wired_backhaul=1
uci set prplmesh.config.master=0
uci set prplmesh.config.gateway=0
uci commit

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

echo CONFIG_ENDED
