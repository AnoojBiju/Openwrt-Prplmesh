#! /bin/sh
###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2021 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

# In prplmesh, we make use of a number of other repositories. To make builds reproducible, we refer
# to these repositories at a specific hash. In order to avoid spreading out these references all
# over the tree, and to avoid duplicating references, this file collects all the different
# repositories and their hashes in one place.
# In addition, this file is a script that clones one of the repositories at the specified hash.
# It is intentionally written as a shell script and not Python because it is used as part of docker
# build steps which may have no or an incomplete python installation.

usage() {
    echo "usage: $(basename "$0") <reponame> [<dir>]"
    echo "  Clone/checkout the repository <reponame> at its configured hash."
    echo "  If [<dir>] is given, it is checked out in that directory instead of in <reponame>"
}


# Get the list of repositories and their hashes. Each line specifies a repository. Format:
# <reponame>=<url>^<hash>
repos() {
    cat <<EOF
meta-prplmesh=https://gitlab.com/prpl-foundation/prplmesh/meta-prplmesh.git^a82d8f8cbfb1cd0df293ab380425b12ec403204c
meta-amx=https://gitlab.com/prpl-foundation/components/ambiorix/meta-amx.git^1b871c0d7871d15a4653c4b5bb30a656c36c432b
EOF
}

reponame="$1"
if [ -z "$reponame" ]; then
    usage
    exit 1
fi

dir="$2"
# Default output directory is the reponame
[ -z "$dir" ] && dir="$reponame"

spec="$(repos | sed -n "/^$reponame=\\(.*\\)\$/s//\\1/p")"

if [ -z "$spec" ]; then
    echo "Repository '$reponame' not found"
    usage
    exit 1
fi

url="${spec%^*}"
hash="${spec##*^}"

if [ -e "$dir" ]; then
    printf '\033[1;35m%s Updating %s\n\033[0m' "$(date --iso-8601=seconds --universal)" "$reponame"
    cd "$dir" || exit $?
    git remote set-url origin "$url" || exit $?
    git fetch origin || exit $?
else
    printf '\033[1;35m%s Cloning %s\n\033[0m' "$(date --iso-8601=seconds --universal)" "$reponame"
    git clone "$url" "$dir" || exit $?
    cd "$dir" || exit $?
fi

git checkout "$hash" || exit $?
