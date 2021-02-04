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
            TEST_ARGS=(-x "$1")
            shift
            ;;
        --test)
            shift
            [[ "$#" -eq 0 ]] && echo "no test specified" && exit 1
            # "connect" is a predefined boardfarm test suite that acts as
            # an empty one.
            #
            # Not supplying test suite (-x option) results in "flash" test
            # suite that is not empty.
            #
            # BUG:
            # Adding individual tests via -e option always implicitly adds
            # a predefined "Interact" test in the end of the test list.
            # This behaviour is hardcoded in the boardfarm code.
            TEST_ARGS=(-x connect -e "$1")
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

echo "TEST_ARGS = ${TEST_ARGS[@]}"

bft -c "${bf_plugins_dir}"/boardfarm_prplmesh/prplmesh_config.json \
        -n "$DUT" "${TEST_ARGS[@]}" -o "${resultdir}" || exit 255

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
