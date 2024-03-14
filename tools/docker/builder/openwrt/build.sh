#!/bin/bash -e
# shellcheck disable=SC2076
# shellcheck disable=SC2016
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
    echo "      -u|--openwrt-toolchain-version - the openwrt version to use for toolchain"
    echo "      -r|--openwrt-repository - the openwrt repository to use"
    echo "      -s|--shell-only - don't build prplMesh, drop into a shell instead"
    echo "      -t|--tag - the tag to use for the builder image"
    echo "      --whm - use a WHM enabled prplOS sidebranch to build"
    echo " -d is always required."
    echo ""
}

build_image() {
    build_dir="$1"
    mkdir -p "$build_dir"
    docker build --tag "$image_tag" \
           --build-arg OPENWRT_REPOSITORY="$OPENWRT_REPOSITORY" \
           --build-arg OPENWRT_VERSION="$OPENWRT_VERSION" \
           --build-arg OPENWRT_TOOLCHAIN_VERSION="$OPENWRT_TOOLCHAIN_VERSION" \
           --build-arg TARGET_SYSTEM="$TARGET_SYSTEM" \
           --build-arg WHM_ENABLE="$WHM_ENABLE" \
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
    local command interactive
    if [ "$SHELL_ONLY" == true ] ; then
        command="bash"
        # to get an interactive shell, we have to use `-it`:
        interactive="-it"
    else
        command="./build_scripts/build.sh"
        # when doing non-interactive builds (e.g. in CI), `-t` can't
        # be used:
        interactive="-i"
    fi
    dbg "Container name will be $container_name"
    trap 'docker rm -f $container_name' EXIT
    docker run "$interactive" \
           --name "$container_name" \
           -e TARGET_SYSTEM \
           -e OPENWRT_VERSION \
           -e OPENWRT_TOOLCHAIN_VERSION \
           -e PRPLMESH_VERSION \
           -v "$scriptdir/scripts:/home/openwrt/openwrt/build_scripts/:ro" \
           -v "${rootdir}:/home/openwrt/prplMesh_source:ro" \
           "$image_tag" \
           "$command"
    mkdir -p "$build_dir"
    # Note: docker cp does not support globbing, so we need to copy the folder
    docker cp "${container_name}:/home/openwrt/openwrt/artifacts/" "$build_dir"
    mv "$build_dir/artifacts/"* "$build_dir"
    rm -r "$build_dir/artifacts/"
    if [ "$TARGET_SYSTEM" = "intel_mips" ] ; then
        #TODO: remove once PPM-1121 is done
        for device in axepoint nec-wx3000hp ; do
            ln -s intel_mips "$build_dir/../$device"
        done
    fi
}

main() {

    if ! command -v uuidgen > /dev/null ; then
        err "You need uuidgen to use this script. Please install it and try again."
        exit 1
    fi

    if ! OPTS=$(getopt -o 'hvd:io:r:st:' --long help,verbose,target-device:,docker-target-stage:,whm,image,openwrt-version:,openwrt-repository:,shell,tag: -n 'parse-options' -- "$@"); then
        err "Failed parsing options." >&2
        usage
        exit 1
    fi

    eval set -- "$OPTS"

    SUPPORTED_TARGETS="turris-omnia glinet-b1300 axepoint nec-wx3000hp intel_mips haze urx_osp"

    while true; do
        case "$1" in
            -h | --help)                      usage; exit 0; shift ;;
            -v | --verbose)                   VERBOSE=true; shift ;;
            -d | --target-device)             TARGET_DEVICE="$2"; shift ; shift ;;
            --docker-target-stage)            DOCKER_TARGET_STAGE="$2"; IMAGE_ONLY=true; shift 2 ;;
            -i | --image)                     IMAGE_ONLY=true; shift ;;
            -o | --openwrt-version)           OPENWRT_VERSION="$2"; shift; shift ;;
            -u | --openwrt-toolchain-version) OPENWRT_TOOLCHAIN_VERSION="$2"; shift; shift ;;
            -r | --openwrt-repository)        OPENWRT_REPOSITORY="$2"; shift; shift ;;
            -s | --shell)                     SHELL_ONLY=true; shift ;;
            -t | --tag)                       TAG="$2"; shift ; shift ;;
            --whm)                            WHM_ENABLE=true; shift ;;
            -- ) shift; break ;;
            * ) err "unsupported argument $1"; usage; exit 1 ;;
        esac
    done

    if [ "$SHELL_ONLY" == true ] && [ "$IMAGE_ONLY" == true ] ; then
        err "--shell and --image cannot be used together."
        usage
        exit 1
    fi

    case "$TARGET_DEVICE" in
        turris-omnia)
            TARGET_SYSTEM=mvebu
            ;;
        glinet-b1300)
            TARGET_SYSTEM=ipq40xx
            ;;
        axepoint|intel_mips|nec-wx3000hp)
            TARGET_SYSTEM=intel_mips
            ;;
        haze)
            TARGET_SYSTEM=ipq807x
            ;;
        urx_osp)
            TARGET_SYSTEM=mxl_x86_osp_tb341
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

    legacy_platforms=("glinet-b1300" "axepoint" "intel_mips" "nec-wx3000hp")
    if [[ " ${legacy_platforms[*]} " =~ " $TARGET_DEVICE " ]] ; then
        dbg "Legacy platform, building on prplOS(-old)"
        OPENWRT_TOOLCHAIN_VERSION='21169344e223c5e02e8afedc3cc5648acd42f6cc'
        OPENWRT_VERSION='21169344e223c5e02e8afedc3cc5648acd42f6cc'
    elif [[ "haze" == "$TARGET_DEVICE" ]] ; then
        dbg "Haze platform, build on prplos master (wps fix)"
        OPENWRT_TOOLCHAIN_VERSION='833823239904b80e15dd4286a3891c68055bb0a0'
        OPENWRT_VERSION='833823239904b80e15dd4286a3891c68055bb0a0'
    elif [[ "urx_osp" == "$TARGET_DEVICE" ]] ; then
        dbg "OSP platform, build on prplos UPDK 9.1.50 + pWHM 6.11.0"
        OPENWRT_TOOLCHAIN_VERSION='621c083b4a7bc5c2bbc1e4f121157bbae995e002'
        OPENWRT_VERSION='621c083b4a7bc5c2bbc1e4f121157bbae995e002'
    else
        dbg "Building on prplOS-next"
    fi

    dbg "OPENWRT_REPOSITORY=$OPENWRT_REPOSITORY"
    dbg "OPENWRT_TOOLCHAIN_VERSION=$OPENWRT_TOOLCHAIN_VERSION"
    dbg "OPENWRT_VERSION=$OPENWRT_VERSION"
    dbg "WHM_ENABLE=$WHM_ENABLE"
    dbg "IMAGE_ONLY=$IMAGE_ONLY"
    dbg "TAG=$TAG"
    dbg "TARGET_SYSTEM=$TARGET_SYSTEM"
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
    PRPLMESH_VERSION="$(git describe --always --dirty)"
    export PRPLMESH_VERSION
    export WHM_ENABLE
    export PRPLMESH_VARIANT

    if [ -n "$WHM_ENABLE" ] ; then
        build_directory="$rootdir/buildWHM"
    else
        build_directory="$rootdir/build"
    fi

    build_image "$build_directory/$TARGET_DEVICE"
    [ $IMAGE_ONLY = true ] && exit $?

    build_prplmesh "$build_directory/$TARGET_DEVICE"

}

VERBOSE=false
IMAGE_ONLY=false
OPENWRT_REPOSITORY='https://gitlab.com/prpl-foundation/prplos/prplos.git'
# prplOS 3.0.1 (after M2.1 merge)
OPENWRT_TOOLCHAIN_VERSION='51bbbf78fbabd7c2f242298403b0eb38748ed9c4'
OPENWRT_VERSION='51bbbf78fbabd7c2f242298403b0eb38748ed9c4'
PRPLMESH_VARIANT="-nl80211"
DOCKER_TARGET_STAGE="prplmesh-builder"
SHELL_ONLY=false

main "$@"
