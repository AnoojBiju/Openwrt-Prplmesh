#!/bin/sh

# Delete all wifi-iface to make sure we only have the ones we want:
while uci delete wireless.@wifi-iface[-1] 2> /dev/null ; do :; done

# TODO: prplmesh requires the second radio to be named 'radio2'
# instead of the default 'radio1'. Remove once it's fixed (and update
# the sections below).
uci rename wireless.radio1=radio2 2>/dev/null || true

uci batch << 'EOF'
set wireless.default_radio0=wifi-iface
set wireless.default_radio0.device='radio0'
set wireless.default_radio0.network='lan'
set wireless.default_radio0.mode='ap'
set wireless.default_radio0.key='prplmesh_pass'
set wireless.default_radio0.encryption='psk2'
set wireless.default_radio0.ssid='prplmesh'
set wireless.default_radio0.wps_pushbutton='1'

set wireless.default_radio2=wifi-iface
set wireless.default_radio2.device='radio2'
set wireless.default_radio2.network='lan'
set wireless.default_radio2.mode='ap'
set wireless.default_radio2.key='prplmesh_pass'
set wireless.default_radio2.encryption='psk2'
set wireless.default_radio2.ssid='prplmesh'
set wireless.default_radio2.wps_pushbutton='1'

set wireless.default_radio10=wifi-iface
set wireless.default_radio10.device='radio0'
set wireless.default_radio10.network='lan'
set wireless.default_radio10.mode='ap'
set wireless.default_radio10.key='prplmesh_pass'
set wireless.default_radio10.encryption='psk2'
set wireless.default_radio10.ssid='prplmesh'

set wireless.default_radio20=wifi-iface
set wireless.default_radio20.device='radio2'
set wireless.default_radio20.network='lan'
set wireless.default_radio20.mode='ap'
set wireless.default_radio20.key='prplmesh_pass'
set wireless.default_radio20.encryption='psk2'
set wireless.default_radio20.ssid='prplmesh'

set wireless.default_radio11=wifi-iface
set wireless.default_radio11.device='radio0'
set wireless.default_radio11.mode='sta'
set wireless.default_radio11.wps_pushbutton='1'
set wireless.default_radio11.wps_config='push_button'
set wireless.default_radio11.network='lan'
set wireless.default_radio11.multi_ap='1'

set wireless.default_radio21=wifi-iface
set wireless.default_radio21.device='radio2'
set wireless.default_radio21.mode='sta'
set wireless.default_radio21.wps_pushbutton='1'
set wireless.default_radio21.wps_config='push_button'
set wireless.default_radio21.network='lan'
set wireless.default_radio21.multi_ap='1'

# TODO: prplmesh currently rely on the interface names to be like this.
#       Remove the next block once it's fixed.
set wireless.default_radio0.ifname='wlan0'
set wireless.default_radio2.ifname='wlan2'
set wireless.default_radio10.ifname='wlan0.0'
set wireless.default_radio20.ifname='wlan2.0'
set wireless.default_radio11.ifname='wlan1'
set wireless.default_radio21.ifname='wlan3'

# TODO: same issue, for prplmesh settings this time:
set prplmesh.radio0.hostap_iface='wlan0'
set prplmesh.radio0.sta_iface='wlan1'
set prplmesh.radio0.hostap_iface_steer_vaps='wlan0.0'
set prplmesh.radio1.sta_iface='wlan3'
set prplmesh.radio1.hostap_iface='wlan2'
set prplmesh.radio1.hostap_iface_steer_vaps='wlan2.0'

# TODO: channel switching does not work yet, remove when it does:
set wireless.radio0.channel=auto
set wireless.radio2.channel=auto
EOF

uci commit

/etc/init.d/network restart
