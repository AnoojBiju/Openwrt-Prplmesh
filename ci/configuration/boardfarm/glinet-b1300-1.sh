#!/bin/sh

# We need to source some files which are only available on prplWrt
# devices, so prevent shellcheck from trying to read them:
# shellcheck disable=SC1091

set -e

# Stop and disable the DHCP clients and servers:
ubus call DHCPv4.Client.1 _set '{"parameters": { "Enable": False }}'
ubus call DHCPv6.Client.1 _set '{"parameters": { "Enable": False }}'
ubus call DHCPv4.Server _set '{"parameters": { "Enable": False }}'
ubus call DHCPv6.Server _set '{"parameters": { "Enable": False }}'

uci set network.lan.ipaddr='192.168.1.1/24'
uci del network.lan.netmask
uci commit network

uci changes; uci show network.lan.ipaddr
ip link show br-lan
ip addr show br-lan
ubus call "IP.Interface" _get '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"]." }'
ubus call "NetDev.Link" _get '{ "rel_path": ".br-lan.IPv4Addr." }'
ubus call "NetModel.Intf" _get '{ "rel_path": ".ip-lan.", "depth":5 }'
ubus call "NetModel.Intf" _get '{ "rel_path": ".lan.", "depth":5 }'
ubus call "NetModel.Intf" _get '{ "rel_path": ".bridge-lan_bridge.", "depth":5 }'

# IP for device upgrades, operational tests, Boardfarm data network, ...
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.168.1.110" } }'

# Try to work around PCF-681: if we don't have a connectivity, restart
# tr181-bridging
time ping 192.168.1.2 -c 10 || {
  logger -t prplmesh -p daemon.crit "Unable to ping 192.168.1.2, restarting tr181-bridging"
  /etc/init.d/tr181-bridging restart
}

uci changes; uci show network.lan.ipaddr
ip link show br-lan
ip addr show br-lan
ubus call "IP.Interface" _get '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"]." }'
ubus call "NetDev.Link" _get '{ "rel_path": ".br-lan.IPv4Addr." }'
ubus call "NetModel.Intf" _get '{ "rel_path": ".ip-lan.", "depth":5 }'
ubus call "NetModel.Intf" _get '{ "rel_path": ".lan.", "depth":5 }'
ubus call "NetModel.Intf" _get '{ "rel_path": ".bridge-lan_bridge.", "depth":5 }'

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

uci changes; uci show network.lan.ipaddr

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

logger -t prplmesh -p daemon.info "Stoping network"
/etc/init.d/network stop

uci changes; uci show network.lan.ipaddr

sleep 10
logger -t prplmesh -p daemon.info "Network should be stopped."
uci changes; uci show network.lan.ipaddr

logger -t prplmesh -p daemon.info "Starting network"
/etc/init.d/network start

time ubus -t 60 wait_for network.interface.lan || logger -t prplmesh -p daemon.crit "netifd: waiting for lan network interface failed!"

# For now there is no way to disable the firewall (see PCF-590).
# Instead, wait for it in the datamodel, then set the whole INPUT
# chain to ACCEPT:
time ubus wait_for Firewall
iptables -P INPUT ACCEPT
sed -i 's/:INPUT DROP/:INPUT ACCEPT/' /etc/amx/tr181-firewall/firewall.defaults

uci changes; uci show network.lan.ipaddr
