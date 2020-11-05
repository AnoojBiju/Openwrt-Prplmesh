#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.

scriptdir=$(dirname "$(readlink -f "${0}")")
bf_plugins_dir=${scriptdir}/boardfarm_plugins
resultdir=${scriptdir}/../logs/

# parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --dut)
            shift
            [[ "$#" -eq 0 ]] && echo "no device specified" && exit 1
            DUT="$1"
            shift
            ;;
        *)
            echo "unsupported arg: $1"
            ;;
    esac
done

if [ -n "${PYTHONPATH}" ]; then
   PYTHONPATH="${bf_plugins_dir}:${scriptdir}:${PYTHONPATH}"
else
   PYTHONPATH="${bf_plugins_dir}:${scriptdir}"
fi
echo "$PYTHONPATH"
export PYTHONPATH
export BFT_DEBUG=y

bft -c "${bf_plugins_dir}"/boardfarm_prplmesh/prplmesh_config.json \
        -n "$DUT" -x test_flows -o "${resultdir}" || exit 255

failed_test_count=$(jq '.tests_fail' "${resultdir}"/test_results.json)
re='^[0-9]+$'
if ! [[ "$failed_test_count" =~ $re ]]; then
   echo "Unable to parse failed test count:" "$failed_test_count" \
   && exit 255
fi
if [[ "$failed_test_count" -gt 0 ]]; then
   printf '\033[1;31m%s\033[0m\n' "$failed_test_count tests failed!" \
   && exit 1
fi
