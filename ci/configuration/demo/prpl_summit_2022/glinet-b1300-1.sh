#!/bin/sh

# We need to source some files which are only available on prplWrt
# devices, so prevent shellcheck from trying to read them:
# shellcheck disable=SC1091

set -e

# Stop and disable the DHCP clients:
ubus wait_for DHCPv4.Client.1
ubus call DHCPv4.Client.1 _set '{"parameters": { "Enable": False }}'
ubus wait_for DHCPv6.Client.1
ubus call DHCPv6.Client.1 _set '{"parameters": { "Enable": False }}'

# We keep the DHCP server enabled, as this device will be used as a controller.

# Stop and disable CWMPD or it will slowly fill the tmpfs with core
# files (PPM-2251):
/etc/init.d/cwmp_plugin stop || true
rm -f /etc/init.d/cwmp_plugin

# Save the IP settings persistently:
sed -ri 's/(dm-save.*) = false/\1 = true/g' /etc/amx/ip-manager/ip-manager.odl
/etc/init.d/ip-manager restart

ubus wait_for IP.Interface
# IP for device upgrades, operational tests, Boardfarm data network, ...
ubus call "IP.Interface" _set '{ "rel_path": ".[Alias == \"lan\"].IPv4Address.[Alias == \"lan\"].", "parameters": { "IPAddress": "192.168.250.171" } }'

# Open a hole for lighttpd:
ubus-cli Firewall.X_Prpl_Service.+{Alias="serviceelements",Action="Accept",DestinationPort="8080",Enable=1,IPVersion=4,Interface="br-lan",Protocol="TCP"}

# Move the WAN port into the LAN bridge, so that it can also be used to connect other agents:
ubus wait_for Bridging.Bridge
ubus call "Bridging.Bridge" _get '{ "rel_path": ".[Alias == \"lan\"].Port.[Name == \"eth1\"]." }' || {
    echo "Adding interface to bridge"
    ubus call "Bridging.Bridge" _add '{ "rel_path": ".[Alias == \"lan\"].Port.",  "parameters": { "Name": "eth1", "Alias": "ETH1", "Enable": true } }'
}

uci set system.@system[0].hostname='glinet-b1300-1'
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
set wireless.default_radio0.multi_ap='3'

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
set wireless.default_radio1.multi_ap='3'

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
