#!/bin/bash
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# This POC script allows to manually validate that the basic features
# needed for VBSS are working (e.g. retrieving and setting keys and
# key sequences). It can also be used to better understand what
# implications a VBSS move has on other components (e.g. hostapd).
#
# Note that for now some part are missing (e.g. have hostapd ignore a
# station until keys are configured, properly sending a DELBA from
# hostapd instead of using debugfs, etc). The script might be updated
# in the future, when more of the missing parts are implemented.
#
# Two GL.iNet B1300 devices running prplOS are required,
# pre-configured with only one BSS whose interface is named wlan0, and
# reachable over SSH with the glinet-b1300-1 and glinet-b1300-2 names
# (configure them in your local SSH config). 'socat' is also needed on
# the devices (not installed by default in prplOS).
#
# It also requires a station to connect to the BSS of glinet-b1300-1
# (the source VBSS). It's easier to use a Linux device running
# wpa_supplicant, as it makes it easier to see reauthentications on
# the station side for example.

set -e

if [ "$#" != 1 ] ; then
    echo "Usage: ./move.sh <STATION_MAC>"
    exit 1
fi

export -- STATION_MAC="$1"

if ! echo "$STATION_MAC" | grep -Eq "^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$" ; then
    echo "The format of the station MAC address is invalid!"
    echo "Please use the 01:02:03:04:05:06 format."
    exit 1
fi

# The TX PN patch reads the least significant bytes first, so we have
# to first reverse the key sequence if we want to increment it
# properly:
reverse() {
    export -- "$2"="$(echo "$1" | fold -w2 | tac | tr -d '\n')"
}

# Increment the key by an arbitrary number.  This is done in order to
# make sure the new key sequence is still higher than the original one
# by the time the station talks to the target VBSS.
inc_key(){
    local tmp
    reverse "$1" tmp
    tmp="$(printf '%012x' $((0x$tmp + 0x90)))"
    reverse "$tmp" tmp
    export -- "$2"="$tmp"
}

# Not strictly needed, but it can be useful to have full hostapd logs
# for debugging purposes:
ssh -q glinet-b1300-1 "hostapd_cli -i wlan0 log_level debug"
ssh -q glinet-b1300-2 "hostapd_cli -i wlan0 log_level debug"

# Send the DELBA very early to make sure the station receives it by the time we teardown the AP:
ssh -q glinet-b1300-1 "echo 1 > /sys/kernel/debug/ieee80211/phy0/netdev:wlan0/stations/$STATION_MAC/aggr_mode"
ssh -q glinet-b1300-1 "echo 0 1 37 > /sys/kernel/debug/ieee80211/phy0/netdev:wlan0/stations/$STATION_MAC/delba"

# Retrieve the original keys from the source agent:
KEY="$(ssh glinet-b1300-1 -q "iw dev wlan0 key get 0 $STATION_MAC | head -n 1 | tr -d ' ' | cut -d : -f 2 | tr -d '\n'")"
GKEY="$(ssh glinet-b1300-1 -q "iw dev wlan0 key get 1 | head -n 1 | tr -d ' ' | cut -d : -f 2 | tr -d '\n'")"
printf 'Key: %s\n' "$KEY"
printf 'Group key: %s\n' "$GKEY"

# Retrieve the original sequence counters:
KEY_SEQ="$(ssh glinet-b1300-1 -q "iw dev wlan0 key get 0 $STATION_MAC | head -n 3 | tail -n 1 | tr -d ' ' | cut -d : -f 2 | tr -d '\n'")"
GKEY_SEQ="$(ssh glinet-b1300-1 -q "iw dev wlan0 key get 1 | head -n 3 | tail -n 1 | tr -d ' ' | cut -d : -f 2 | tr -d '\n'")"
echo "KEY_SEQ=$KEY_SEQ"
echo "GKEY_SEQ=$GKEY_SEQ"

# Increment the sequence counters:
inc_key "$KEY_SEQ" NEW_KEY_SEQ
inc_key "$GKEY_SEQ" NEW_GKEY_SEQ
echo "NEW_KEY_SEQ=$NEW_KEY_SEQ"
echo "NEW_GKEY_SEQ=$NEW_GKEY_SEQ"


# We don't stop the AP on the source device before setting up the new
# one. Otherwise the station might detect beacon loss, and
# disassociate on its own.

# To create the station on the target agent, We need a station ID that
# is not already used. In the future, this will be handled by
# hostapd. Since it's just for testing, use a pseudo-random ID (and
# add 5 to decreases the chances that we get one that already exists):
RAN="$((RANDOM % 250 + 5))"
echo "AID: $RAN"

# Add the station on the target AP and set its keys. We initially add
# ebtables rules because we currently don't have any way to add the
# station before hostapd starts beaconing, and we don't want it to
# talk with the same BSSID until the station is configured.  iw's
# station dump output is printed only for debugging.  For the RX PN we
# use a zero value, as we have no idea what the original RX PN
# was. The RX PN will be set to the right value when the target BSS
# receives the first frame from the station.
# shellcheck disable=SC2087
ssh -q glinet-b1300-2 <<EOF
ebtables -A OUTPUT -d $STATION_MAC  -j DROP
ebtables -A INPUT -s $STATION_MAC  -j DROP
ebtables -t nat -A PREROUTING -s $STATION_MAC -i wlan0 -j DROP
ebtables -t nat -A POSTROUTING -d $STATION_MAC -j DROP
hostapd_cli -i wlan0 UPDATE_BEACON
iw dev wlan0 station new $STATION_MAC 0 02040b16 $RAN 166
iw dev wlan0 station set_flags $STATION_MAC 747324309678
iw dev wlan0 station dump | tr -d '\t' | grep 'associated:yes'
iw dev wlan0 station dump
iw dev wlan0 key del 0 $STATION_MAC 2>/dev/null
iw dev wlan0 key add 0 $STATION_MAC $KEY 000000000000${NEW_KEY_SEQ}
iw dev wlan0 key get 0 $STATION_MAC
iw dev wlan0 key del 1 2>/dev/null
iw dev wlan0 key add 1 $GKEY 000000000000${NEW_GKEY_SEQ}
iw dev wlan0 key set_default 1
EOF

# We don't have a way for hostapd to stop beaconing and ignore
# stations yet (DISABLE would deauthenticate the station), use STOP_AP
# in the meantime:
ssh -q glinet-b1300-1 "rm -f /tmp/my_socket && printf STOP_AP | socat STDIO UNIX-CONNECT:/var/run/hostapd/wlan0,type=2,bind=/tmp/my_socket" &
# Remove ebtables rules from the target agent so that it can talk to
# the station:
ssh -q glinet-b1300-2 "ebtables -F ; ebtables -t nat -F" &

# Prevent the source agent from talking to the station:
# shellcheck disable=SC2087
>/dev/null ssh -q glinet-b1300-1 <<EOF
ebtables -A OUTPUT -d $STATION_MAC  -j DROP
ebtables -A INPUT -s $STATION_MAC  -j DROP
ebtables -t nat -A PREROUTING -s $STATION_MAC -i wlan0 -j DROP
ebtables -t nat -A POSTROUTING -d $STATION_MAC -j DROP
EOF

# hostapd seems to resume beaconing some time after STOP_AP was sent,
# so send it in a loop.  This won't be needed anymore once we have a
# way to tell hostapd to stop beaconing and talking to the station,
# but without deauthenticating it.
while true ; do
ssh -q glinet-b1300-1 "rm -f /tmp/my_socket && printf STOP_AP | socat STDIO UNIX-CONNECT:/var/run/hostapd/wlan0,type=2,bind=/tmp/my_socket"
done
