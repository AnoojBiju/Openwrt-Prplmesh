#! /bin/bash
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2019-2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

set -e

printf '\033[1;35m%s Configuring RDK-B\n\033[0m' "$(date --iso-8601=seconds --universal)"

export MACHINE=raspberrypi-rdk-broadband

# Not part of this repository
# shellcheck disable=SC1091
source meta-cmf-raspberrypi/setup-environment

echo "BBLAYERS += \"\${RDKROOT}/meta-prplmesh\"" >> conf/bblayers.conf

# Copy in prplmesh. The build tries to write in the source directory, so we can't use mount
# directly.
rsync -a --exclude-from=/home/rdk/prplMesh_source/.gitignore \
    /home/rdk/prplMesh_source/ /home/rdk/prplMesh

# Update prplmesh feed to use already check-out source instead of download from git
cat >> conf/local.conf <<EOF

INHERIT += "externalsrc"
EXTERNALSRC_pn-prplmesh = "/home/rdk/prplMesh"
EOF

printf '\033[1;35m%s Building RDK-B\n\033[0m' "$(date --iso-8601=seconds --universal)"

bitbake rdk-generic-broadband-image

# Collect the artifacts
cp tmp/deploy/images/raspberrypi-rdk-broadband/rdk-generic-broadband-image-raspberrypi-rdk-broadband.rpi-sdimg ~/artifacts/
cp tmp/deploy/ipk/cortexa7t2hf-neon-vfpv4/prplmesh* ~/artifacts

