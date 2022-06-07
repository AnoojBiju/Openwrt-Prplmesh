#!/usr/bin/env python3
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################
"""Gitlab CI yaml generator.."""

# Standard library
import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List

DESCRIPTION = """Generate Gitlab CI yaml for certification tests.
The tests are grouped by variant in the CI pipeline graphs.
"""

JOB_TEMPLATE = """
{revision}:{device_under_test}:{test_name}:
  extends: .certification:{revision}:{device_under_test}
  rules:
    # If the last commit description contains the test name and we're not on master, run it.
    # Otherwise, make it a manual job
    - if: '$CI_COMMIT_DESCRIPTION =~ /.*{test_name}:{device_under_test}.*/ && $CI_COMMIT_REF_NAME != "master"'
      when: on_success
    - when: manual
      allow_failure: true
""" # noqa E501 # pylint: disable=line-too-long

scriptdir = Path(__file__).resolve().parent
rootdir = scriptdir.parent.parent


def read_file(test_file: Path) -> List[str]:
    """Read a test file and return a list of tests.

    Note that the complete list of tests is stored in memory, we don't
    expect it to be bigger than a few hundred tests.
    """
    test_file = Path(test_file)
    if not test_file.is_file():
        raise ValueError("f{test_file} is not a file!")
    with open(test_file, "r", encoding="utf-8") as t_file:
        return [line.strip() for line in t_file.readlines()]


def read_test_files(test_files: List[str]) -> List[str]:
    """Read a list of test files (paths), and return the tests they contain."""
    tests = []
    for t_file in test_files:
        tests.extend(read_file(t_file))
    return tests


def sort_tests(tests: List[str]) -> List[str]:
    """Sort lists of test."""
    return sorted(tests, key=lambda test:
                  [int(t) if t.isdigit() else t for t in re.split('([0-9]+)', test)])


def basename(test: str):
    """Returns the base name of a test.

    For example, the base name of "MAP-4.10.5_BH24G_FH5GL" is
    "MAP-4.10.5".
    """
    return re.split(r"(MAP-\d+\.\d+\.\d+)", test)[1]


def get_test_groups(tests: List[str]) -> Dict[str, str]:
    """Group tests by their base name.

    The tests are first sorted so that they can be grouped even if they
    were not initially successive in the input list.

    For example, MAP-4.10.5_BH24G_FH5GL and MAP-4.10.5_BH24G_FH5GH are
    different variants of the same test, and belong to the same group.

    Returns
    -------
    A dictionary where keys are group names, and values are lists of
    tests within the group.
    """
    tests = sort_tests(tests)
    groups = {}  # List[str, str]
    for test in tests:
        bname = basename(test)
        if bname in groups:
            groups[bname].append(test)
        else:
            groups[bname] = [test]
    return groups


def main():
    """Entrypoint."""
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description=DESCRIPTION,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', '--device-under-test', required=True,
                        help="The name of the DUT.")
    parser.add_argument('-r', '--revision',
                        help="The easymesh revision to run for.", required=True)

    parser.add_argument('test_files', nargs="+",
                        help="Files containing the test names.")

    args = parser.parse_args()

    tests = read_test_files(args.test_files)

    groups = get_test_groups(tests)

    # Only one test per group to reduce the overall number of jobs:
    for _, tests in groups.items():
        test_name = tests[0]
        print(JOB_TEMPLATE.format(test_name=test_name,
                                  revision=args.revision,
                                  device_under_test=args.device_under_test))


if __name__ == '__main__':
    main()
