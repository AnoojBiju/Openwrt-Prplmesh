#!/bin/bash

set -e

if [ "$#" != 1 ] ; then
    echo "Usage: ./release.sh <release_version>"
    exit 1
fi

VERSION="$1"
VERSION_FILE="cmake/multiap-helpers.cmake"

if [[ ! "$VERSION" =~ [0-9]+.[0-9]+.[0-9]+  ]] ; then
    echo "The release version must follow semantic versioning."
    exit 1
fi


sed -ri "s/prplmesh_VERSION \"[0-9]+\.[0-9]+\.[0-9]+\"/prplmesh_VERSION \"$VERSION\"/g" cmake/multiap-helpers.cmake

# The gen_changelog.py script relies on the tag to exist to be able to
# generate the changelog. However, we need to include the new
# changelog in the version that we tag, which leaves us with a
# chicken-and-egg problem. To work around it, create a first tag only
# for gen_changelog.py to use, then move the tag once the new
# changelog has been commited.  Note that because of this, the release
# date gen_changelog.py will use at the next invocation will not be
# the same as the one stored in the CHANGELOG.md file (as the tag will
# have been moved a few seconds later).
git tag "$VERSION" -m "prplMesh release $VERSION"
tools/gen_changelog.py -U > CHANGELOG.md

git add "$VERSION_FILE"
git add CHANGELOG.md
git commit -s -m "Prepare release $VERSION"
# Move the tag to our final commit:
git tag -f "$VERSION" -m "prplMesh release $VERSION"
echo "The release has been created, check the result before pushing it."
