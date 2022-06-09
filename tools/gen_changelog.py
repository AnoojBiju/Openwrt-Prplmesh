#!/usr/bin/env python3
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

import sys
import subprocess
import re
import datetime
import argparse

generation_datetime = datetime.datetime.now().isoformat(sep=' ', timespec='minutes')
preamble = f"""\
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Note that this file is generated by the script `{sys.argv[0]}`,
which can be found in the prplMesh repository.
Please do not edit this file by hand, simply re-run the script.

Generated on {generation_datetime}

"""


def get_log_entry(current_version: str, prev_version: str):
    items = []
    version_filter = f"{prev_version}..{current_version}" if prev_version else current_version
    # For each 'git log' line between the two versions ...
    with subprocess.Popen(["git", "log", "--oneline", "--merges", version_filter],
                          stdout=subprocess.PIPE,
                          universal_newlines=True) as log:
        for line in log.stdout.readlines():
            # ... look for merge commits that merge a bugfix, feature or hotfix branch ...
            item = re.match("([0-9a-f]+) Merge branch '(bugfix|feature)/(PPM-\\d+)", line)
            if not item:
                item = re.match("([0-9a-f]+) Merge branch '(hotfix)/", line)
            if item:
                # ... extract the hash, type (bugfix, feature, hotfix) and JIRA from it ...
                githash = item.group(1)
                itemtype = item.group(2).title()
                jira = item.group(3) if len(item.groups()) > 2 else ''
                # ... use the hash to obtain the full description text ...
                change_desc = subprocess.run(['git', 'show', '--format=%b', '-s', githash],
                                             capture_output=True,
                                             text=True).stdout
                # ... only add the first line, and sanitize it for inclusion in markdown ...
                change = change_desc.split('\n')[0].strip()
                bad_char = r"\*_()[]<>{}!@#$%^&~|"
                for c in bad_char:
                    change = change.replace(c, '\\'+c)
                if not change:
                    continue    # Purge merges with empty descriptions here.
                items += [(itemtype, change, jira)]
    return items


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0],
                                     description="Generate a changelog in Markdown format.")
    parser.add_argument('-s', '--start-version', type=str, default=None,
                        help="Display the changelog since this version")
    parser.add_argument('-l', '--latest-version', action='store_true',
                        help="Only show the changes in the latest version (since latest-1)")
    parser.add_argument('-U', '--no-unreleased', action='store_true',
                        help="By default, we start with 'unreleased' changes."
                             "This option suppresses that.")
    args = parser.parse_args()

    # Get all tags in logical order, remove ones that are not releases (x.y.z)
    tags = subprocess.run(['git', 'tag', '--sort=upstream'], capture_output=True, text=True).stdout
    versions = [tag for tag in tags.split('\n') if re.match(r'^\d+.\d+.\d+$', tag)]

    if args.start_version and args.latest_version:
        raise argparse.ArgumentError('-s', "-s and -l are mutually exclusive options!")
    if args.latest_version:
        versions = versions[-2:]
    if args.start_version and args.start_version not in versions:
        raise argparse.ArgumentError('-s', f"{args.start_version} is not a valid version!"
                                           f"Must be one of: {str(versions)}")
    if args.start_version:
        versions = versions[versions.index(args.start_version):]
    if not args.no_unreleased:
        # Pretend 'HEAD' is also a version, so we can get stats about unreleased changes from git
        versions.append('HEAD')

    prev = None
    output = []
    for version in versions:
        # Skip the first version, since otherwise we would list ALL changes
        # before the first selected version as belonging to that version, which is usually wrong
        if version == versions[0]:
            prev = version
            continue

        release_date = subprocess.run(
                            ['git', 'tag', '-l', '--format=%(taggerdate:iso8601)', version],
                            capture_output=True,
                            text=True).stdout
        o = f"\n## [{version}]"\
            f"(https://gitlab.com/prpl-foundation/prplmesh/prplMesh/-/releases/{version})"\
            f" - {release_date}\n"\
            if version != "HEAD" else "## Unreleased\n"
        changes = get_log_entry(version, prev)
        bugs = [c for c in changes if c[0] in ('Bugfix', 'Hotfix')]
        features = [c for c in changes if c[0] == 'Feature']

        o += "\n### Changed\n\n"
        for f in features:
            o += "- [{}]({})\n".format(f[1], 'https://jira.prplfoundation.org/browse/' + f[2])

        o += "\n### Fixed\n\n"
        for b in bugs:
            if b[2]:
                o += "- [{}]({})\n".format(b[1], 'https://jira.prplfoundation.org/browse/' + b[2])
            else:
                o += "- {}\n".format(b[1])

        output.append(o)
        prev = version

    print(preamble)
    print('\n'.join(reversed(output)))


main()
