#!/bin/bash -e
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

scriptdir="$(cd "${0%/*}"; pwd)"
rootdir="${scriptdir%/*/*/*/*}"

# shellcheck source=functions.sh
. "${rootdir}/tools/functions.sh"

set -o pipefail

usage() {
    echo "usage: $(basename "$0") -d <target_device> [-hfiortv]"
    echo "  options:"
    echo "      -h|--help - show this help menu"
    echo "      -v|--verbose - increase the script's verbosity"
    echo "      -d|--target-device the device to build for"
    echo "      --docker-target-stage docker target build stage (implies -i)"
    echo "      -i|--image - build the docker image only"
    echo "      -o|--openwrt-version - the openwrt version to use"
    echo "      -r|--openwrt-repository - the openwrt repository to use"
    echo "      -t|--tag - the tag to use for the builder image"
    echo " -d is always required."
    echo ""
    echo "The following environment variables will affect the build:"
    echo " - PRPL_FEED: the prpl feed that will be used to install prplMesh."
    echo "   default: $PRPL_FEED"
    echo " - SAH_FEED: the SAH feed that will be used to install bus agnostic API."
    echo "   default: $SAH_FEED"

}

build_image() {
    build_dir="$1"
    mkdir -p "$build_dir"
    docker build --tag "$image_tag" \
           --build-arg OPENWRT_REPOSITORY="$OPENWRT_REPOSITORY" \
           --build-arg OPENWRT_VERSION="$OPENWRT_VERSION" \
           --build-arg TARGET_SYSTEM="$TARGET_SYSTEM" \
           --build-arg SUBTARGET="$SUBTARGET" \
           --build-arg TARGET_DEVICE="$TARGET_DEVICE" \
           --build-arg TARGET_PROFILE="$TARGET_PROFILE" \
           --build-arg PRPL_FEED="$PRPL_FEED" \
           --build-arg SAH_FEED="$SAH_FEED" \
           --build-arg PRPLMESH_VARIANT="$PRPLMESH_VARIANT" \
           --target="$DOCKER_TARGET_STAGE" \
           "$scriptdir/" \
      | awk -v LOGFILE="$build_dir/openwrt-build.log" '
          BEGIN { p = 1; }
          /Cleaning prplMesh/ { p = 1; }
          p || /^make\[[0-3]\]|time:/ { print; }
          !p { print >> LOGFILE; }
          /Building prplWrt/ { p = 0; }'
}

build_prplmesh() {
    build_dir="$1"
    container_name="prplmesh-builder-${TARGET_DEVICE}-$(uuidgen)"
    dbg "Container name will be $container_name"
    trap 'docker rm -f $container_name' EXIT
    docker run -i \
           --name "$container_name" \
           -e TARGET_SYSTEM \
           -e SUBTARGET \
           -e TARGET_DEVICE \
           -e TARGET_PROFILE \
           -e OPENWRT_VERSION \
           -e PRPLMESH_VERSION \
           -v "$scriptdir/scripts:/home/openwrt/openwrt/build_scripts/:ro" \
           -v "${rootdir}:/home/openwrt/prplMesh_source:ro" \
           "$image_tag" \
           ./build_scripts/build.sh
    mkdir -p "$build_dir"
    # Note: docker cp does not support globbing, so we need to copy the folder
    docker cp "${container_name}:/home/openwrt/openwrt/artifacts/" "$build_dir"
    mv "$build_dir/artifacts/"* "$build_dir"
    rm -r "$build_dir/artifacts/"
}

main() {

    if ! command -v uuidgen > /dev/null ; then
        err "You need uuidgen to use this script. Please install it and try again."
        exit 1
    fi

    if ! OPTS=$(getopt -o 'hvd:io:r:t:' --long help,verbose,target-device:,docker-target-stage:,image,openwrt-version:,openwrt-repository:,tag: -n 'parse-options' -- "$@"); then
        err "Failed parsing options." >&2
        usage
        exit 1
    fi

    eval set -- "$OPTS"

    SUPPORTED_TARGETS="turris-omnia glinet-b1300 netgear-rax40 axepoint nec-wx3000hp intel_mips"

    while true; do
        case "$1" in
            -h | --help)               usage; exit 0; shift ;;
            -v | --verbose)            VERBOSE=true; shift ;;
            -d | --target-device)      TARGET_DEVICE="$2"; shift ; shift ;;
            --docker-target-stage)     DOCKER_TARGET_STAGE="$2"; IMAGE_ONLY=true; shift 2 ;;
            -i | --image)              IMAGE_ONLY=true; shift ;;
            -o | --openwrt-version)    OPENWRT_VERSION="$2"; shift; shift ;;
            -r | --openwrt-repository) OPENWRT_REPOSITORY="$2"; shift; shift ;;
            -t | --tag)                TAG="$2"; shift ; shift ;;
            -- ) shift; break ;;
            * ) err "unsupported argument $1"; usage; exit 1 ;;
        esac
    done

    case "$TARGET_DEVICE" in
        turris-omnia)
            TARGET_SYSTEM=mvebu
            SUBTARGET=cortexa9
            TARGET_PROFILE=DEVICE_cznic_turris-omnia
            ;;
        glinet-b1300)
            TARGET_SYSTEM=ipq40xx
            SUBTARGET=generic
            TARGET_PROFILE=DEVICE_glinet_gl-b1300
            ;;
        netgear-rax40|axepoint|intel_mips|nec-wx3000hp)
            TARGET_SYSTEM=intel_mips
            SUBTARGET=xrx500
            TARGET_PROFILE=
            ;;
        *)
            err "Unknown target device: $TARGET_DEVICE"
            info "Currently supported targets are:"
            for i in $SUPPORTED_TARGETS ; do
                info "$i"
            done
            exit 1
            ;;
    esac

    dbg "OPENWRT_REPOSITORY=$OPENWRT_REPOSITORY"
    dbg "OPENWRT_VERSION=$OPENWRT_VERSION"
    dbg "PRPL_FEED=$PRPL_FEED"
    dbg "SAH_FEED=$SAH_FEED"
    dbg "IMAGE_ONLY=$IMAGE_ONLY"
    dbg "TARGET_DEVICE=$TARGET_DEVICE"
    dbg "TAG=$TAG"
    dbg "TARGET_SYSTEM=$TARGET_SYSTEM"
    dbg "SUBTARGET=$SUBTARGET"
    dbg "TARGET_PROFILE=$TARGET_PROFILE"
    dbg "PRPLMESH_VARIANT=$PRPLMESH_VARIANT"

    if [ -n "$TAG" ] ; then
        image_tag="$TAG"
    else
        image_tag="${DOCKER_TARGET_STAGE}-${TARGET_DEVICE}:${OPENWRT_VERSION}"
        dbg "image tag not set, using default value $image_tag"
    fi

    export OPENWRT_REPOSITORY
    export OPENWRT_VERSION
    export TARGET_SYSTEM
    export SUBTARGET
    export TARGET_PROFILE
    # We want to exclude tags from the git-describe output because we
    # have no relevant tags to use at the moment.
    # The '--exclude' option of git-describe is not available on older
    # git version, so we use sed instead.
    PRPLMESH_VERSION="$(git describe --always --dirty | sed -e 's/.*-g//')"
    export PRPLMESH_VERSION
    export PRPL_FEED
    export SAH_FEED
    export PRPLMESH_VARIANT

    if [ $IMAGE_ONLY = true ] ; then
        build_image
        exit $?
    fi

    build_image "$rootdir/build/$TARGET_DEVICE"
    build_prplmesh "$rootdir/build/$TARGET_DEVICE"

}

VERBOSE=false
IMAGE_ONLY=false
OPENWRT_REPOSITORY='https://gitlab.com/prpl-foundation/prplwrt/prplwrt.git'
OPENWRT_VERSION='b69b71d0a3d4eac25357b546a7e847501c053912'
PRPL_FEED='https://gitlab.com/prpl-foundation/prplwrt/feed-prpl.git^ee7c1bbce5209cc7b6f12c01a99759c45528f506'
SAH_FEED='https://gitlab.com/soft.at.home/buildsystems/openwrt/sah-packages.git^3c8fef0f760b26d3c54cc518dd71f6bc5f79680a'
PRPLMESH_VARIANT="-nl80211"
DOCKER_TARGET_STAGE="prplmesh-builder"

main "$@"
