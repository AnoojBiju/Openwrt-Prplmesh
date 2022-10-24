#!/bin/bash

scriptdir="$(cd "${0%/*}" || exit 1; pwd)"
rootdir="${scriptdir%/*/*}"

[ -z "$VERSION" ] && VERSION="custom-$(date -Iminutes)"

mkdir -p "${rootdir}/build" && pushd "${rootdir}/build" || exit 1
amxo-cg -G xml "${rootdir}/controller/nbapi/odl/controller.odl"
popd || exit 1
if [ ! -r "${rootdir}/build/controller.odl.xml" ]; then
    echo -e "\\033[1;31mXML generation failed -- ODL syntax issue?\\033[0m"
    exit 1
fi

mkdir -p "${rootdir}/build/html/controller"
amxo-xml-to -x html\
                  -o output-dir="${rootdir}/build/html/controller"\
                  -o title="prplMesh"\
                  -o sub-title="Northbound API"\
                  -o version="$VERSION"\
                  -o stylesheet="prpl_style.css"\
                  -o copyrights="Prpl"\
                  "${rootdir}/build/controller.odl.xml"
