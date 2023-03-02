#!/bin/bash
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# Save logs from a target.

set -o errexit
set -o nounset
set -o pipefail

scriptdir=$(dirname "$(readlink -f "$0")")
rootdir=$(realpath "$scriptdir/../..")

usage() {
    echo "usage: $(basename "$0") <target>"
}

if [ -z "$1" ] ; then
    usage
    exit 1
fi

TARGET="$1"

if [ -z "${LOG_DIR:-}" ] ; then
    LOG_DIR="$rootdir/logs/${TARGET}"
fi

mkdir -p "$LOG_DIR"

echo "Collecting logs into $LOG_DIR"

ssh "$TARGET" <<"EOF" > "$LOG_DIR/${TARGET}_diags.log"
date
echo "Release:"
cat /etc/*_release
echo "Version:"
cat /etc/*version
echo
echo "UCI Configuration (prplMesh, network and wireless):"
uci export prplmesh
uci export network
uci export wireless
echo
echo "ip addr output:"
ip addr
echo "'iw list' output:"
iw list
echo "'iw dev' output:"
iw dev
EOF

ssh "$TARGET" "logread" > "$LOG_DIR/logread.txt"

# Capture the logs
echo "Capturing the prplMesh logs..."
scp -r "$TARGET:/tmp/beerocks/logs/*" "$LOG_DIR"

scp "$TARGET:/var/run/hostapd-phy*.conf" "$LOG_DIR"
