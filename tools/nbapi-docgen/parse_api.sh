#!/bin/bash

scriptdir="$(cd "${0%/*}" || exit 1; pwd)"
rootdir="${scriptdir%/*/*}"

PPM_VERSION=$(grep -E -o "prplmesh_VERSION \"[0-9]\.[0-9]\.[0-9]\"" "${rootdir}/cmake/multiap-helpers.cmake" | cut -d\" -f2)

[ -z "$VERSION" ] && VERSION="${PPM_VERSION}-custom-$(date -Iminutes)"

mkdir -p "${rootdir}/build"
amxo-cg -G xml,"${rootdir}/build" "${rootdir}/build/install/config/odl/controller.odl" "${rootdir}/build/install/config/odl/agent.odl" "${rootdir}/build/install/config/odl/"

if [ ! -r "${rootdir}/build/controller.odl.xml" ]; then
    echo -e "\\033[1;31mXML generation failed -- ODL syntax issue?\\033[0m"
    exit 1
fi

mkdir -p "${rootdir}/build/html/prplMesh"
amxo-xml-to -x html\
                  -o output-dir="${rootdir}/build/html/prplMesh"\
                  -o title="prplMesh"\
                  -o sub-title="Northbound API"\
                  -o version="$VERSION"\
                  -o stylesheet="prpl_style.css"\
                  -o copyrights="Prpl"\
                  "${rootdir}/build/controller.odl.xml"

