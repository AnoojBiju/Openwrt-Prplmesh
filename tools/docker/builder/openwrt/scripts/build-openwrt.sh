#!/bin/bash -e
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

printf '\033[1;35m%s Configuring prplWrt\n\033[0m' "$(date --iso-8601=seconds --universal)"
mkdir -p files/etc
#   We need to keep the hashes in the firmware, to later know if an upgrade is needed:
printf '%s=%s\n' "OPENWRT_REPOSITORY" "$OPENWRT_REPOSITORY" >> files/etc/prplwrt-version
printf '%s=%s\n' "OPENWRT_VERSION" "$OPENWRT_VERSION" >> files/etc/prplwrt-version

# Arguments to gen_config.py:
args=("$TARGET_SYSTEM")

# The additional profiles that will be used. 'debug' contains
# additional packages that are useful when developing:
args+=("debug")

./scripts/gen_config.py "$TARGET_DEVICE" "${args[@]}"
cat profiles_feeds/netgear-rax40.yml >> files/etc/prplwrt-version

# test hostapd fix to cac termination flow 
cp patches/0001-add-an-option-to-set-secondary-channel.patch \
    feeds/feed_intel/wlan_6x/wlan_wave_feed/iwlwav-hostap-uci/patches
cat profiles_feeds/netgear-rax40.yml >> files/etc/prplwrt-version

if [ "$TARGET_SYSTEM" = "intel_mips" ]; then
    # intel_mips depends on iwlwav-iw, which clashes with iw-full:
    sed -i '/iw-full$/d' "profiles/debug.yml"
fi

# feed-prpl is in the prpl profile:
args+=("prpl")

# prplMesh is not yet in the prpl profile, so add it
# manually. TODO: remove once PPM-1112 is done:
sed -i "s/packages:/packages:\n  - prplmesh${PRPLMESH_VARIANT}/g" "profiles/prpl.yml"

# Add the SAH feed and its packages:
cp profiles_feeds/sah.yml profiles/sah.yml
args+=("sah")

if [ -n "$MMX_FEED" ] ; then
    cp profiles_feeds/mmx.yml profiles/mmx.yml
    args+=("mmx")
fi

./scripts/gen_config.py "${args[@]}"

for profile in "${args[@]}" ; do
    printf "\nProfile %s:\n" "${profile}" >> files/etc/prplwrt-version
    cat "profiles/${profile}.yml" >> files/etc/prplwrt-version
done

printf '\033[1;35m%s Building prplWrt\n\033[0m' "$(date --iso-8601=seconds --universal)"
make -j"$(nproc)" V=sc

printf '\033[1;35m%s Cleaning prplMesh\n\033[0m' "$(date --iso-8601=seconds --universal)"
make package/prplmesh/clean
