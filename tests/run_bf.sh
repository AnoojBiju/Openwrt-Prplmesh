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
        --test-suite)
            shift
            [[ "$#" -eq 0 ]] && echo "no test suite specified" && exit 1
            TEST_SUITE="$1"
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
        -n "$DUT" -x "$TEST_SUITE" -o "${resultdir}" || exit 255

mapfile -t failed <<< "$(jq -c '.test_results[] | select(.grade == "FAIL") | .name' "${resultdir}"/test_results.json)"
mapfile -t passed <<< "$(jq -c '.test_results[] | select(.grade == "OK") | .name' "${resultdir}"/test_results.json)"
mapfile -t skipped <<< "$(jq -c '.test_results[] | select(.grade == "SKIP") | .name' "${resultdir}"/test_results.json)"

if [[ -n "${passed[*]/$'\n'/}" ]]; then
if [[ -n "${failed[*]/$'\n'/}" ]]; then
    printf '\n\033[2;32m%s\033[0m\n' "${#passed[@]} tests passed!"
    for test in ${passed[*]};do
	    printf '%s\n' "$test"
    done
else
    printf '\n\033[2;32mAll tests passed!\033[0m\n\n'
fi
fi

if [[ -n "${skipped[*]/$'\n'/}" ]]; then
    printf '\n\033[1;36m%s\033[0m\n' "${#skipped[@]} tests skipped!" 
for test in ${skipped[*]};do
	printf '%s\n' "$test"
done
fi

if [[ -n "${failed[*]/$'\n'/}" ]]; then
    printf '\n\033[1;31m%s\033[0m\n' "${#failed[@]} tests failed!" 
for test in ${failed[*]};do
	printf '%s\n' "$test"
done
exit 1
fi
