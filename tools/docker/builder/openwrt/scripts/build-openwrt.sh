#!/bin/sh -e
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
case $TARGET_DEVICE in
    netgear-rax40|axepoint|nec-wx3000hp|intel_mips)
        # Add prplmesh to the list of packages of the profile:
        sed -i 's/packages:/packages:\n  - prplmesh-dwpal/g' profiles/"$TARGET_DEVICE".yml
        # First replace the profiles
        yq write --inplace profiles/"$TARGET_DEVICE".yml feeds -f profiles_feeds/netgear-rax40.yml
        # Then merge adding to  the packages for amx
        yq merge --append --inplace profiles/"$TARGET_DEVICE".yml profiles_feeds/packages-rax40.yml
        ./scripts/gen_config.py "$TARGET_DEVICE" debug
        cat profiles_feeds/netgear-rax40.yml >> files/etc/prplwrt-version
    ;;
    *)
        cp feeds.conf.default feeds.conf
        echo "src-git prpl $PRPL_FEED" >> feeds.conf
        echo "src-git sah  $SAH_FEED" >> feeds.conf
        scripts/feeds update -a
        scripts/feeds install -a
        # Add optional prplMesh dependencies (or a different toolchain
        # for example) from our 'configs' directory:
        cat configs/* > .config
        printf '%s=%s\n' "PRPL_FEED" "$PRPL_FEED" >> files/etc/prplwrt-version
        printf '%s=%s\n' "SAH_FEED" "$SAH_FEED" >> files/etc/prplwrt-version
        # Include our optional dependencies in prplwrt-version so that
        # prplwrt is flashed again if those dependencies are changes.
        printf 'custom packages:\n' >> files/etc/prplwrt-version
        cat .config >> files/etc/prplwrt-version
        {
            # note that the result from diffconfig.sh with a minimal
            # configuration has the 3 CONFIG_TARGET items we set here, but NOT
            # the individual CONFIG_TARGET_${SUBTARGET} and
            # CONFIG_TARGET_${TARGET_PROFILE}, which means we don't need to
            # set them.
            echo "CONFIG_TARGET_${TARGET_SYSTEM}=y"
            echo "CONFIG_TARGET_${TARGET_SYSTEM}_${SUBTARGET}=y"
            echo "CONFIG_TARGET_${TARGET_SYSTEM}_${SUBTARGET}_${TARGET_PROFILE}=y"
            echo "CONFIG_PACKAGE_prplmesh${PRPLMESH_VARIANT}=y"
            echo "CONFIG_PACKAGE_libamxb=y"
            echo "CONFIG_PACKAGE_libamxc=y"
            echo "CONFIG_PACKAGE_libamxd=y"
            echo "CONFIG_PACKAGE_libamxj=y"
            echo "CONFIG_PACKAGE_libamxm=y"
            echo "CONFIG_PACKAGE_libamxo=y"
            echo "CONFIG_PACKAGE_libamxp=y"
            echo "CONFIG_PACKAGE_uriparser=y"
            echo "CONFIG_PACKAGE_amxb-ubus=y"
            echo "CONFIG_PACKAGE_yajl=y"
            echo "CONFIG_PACKAGE_amxo-cg=y"
        } >> .config
        make defconfig
    ;;
esac

printf '\033[1;35m%s Building prplWrt\n\033[0m' "$(date --iso-8601=seconds --universal)"
make -j"$(nproc)" V=sc

printf '\033[1;35m%s Cleaning prplMesh\n\033[0m' "$(date --iso-8601=seconds --universal)"
make package/prplmesh/clean
