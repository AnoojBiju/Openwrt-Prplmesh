#!/bin/bash

if [ "$(basename "$(pwd)")" != "nbapi-docgen" ]; then
    echo "Please execute this file from its own directory"
    exit
fi

# Make a build dir
mkdir -p build/usr/lib
# amx components look for input variables (include files, libs) in a "staging dir" ...
STAGINGDIR="$(cd build && pwd)"
# ... and they put their files in a DEST dir. We need those to be the same
DEST="$STAGINGDIR"
# amx components try to install libs to machine-dependent dirs, but then don't include those directories in their linker paths ...
MACHINE=
# This is needed so that the amx libraries are found during execution of amxo-cg and amxo-xml-to
LD_LIBRARY_PATH="${STAGINGDIR}/usr/lib"

export STAGINGDIR DEST MACHINE LD_LIBRARY_PATH

for COMPONENT in libamxc libamxj libamxp libamxd libamxo amxo-cg amxo-xml-to; do
    if [ ! -d $COMPONENT ]; then
        if [ ${COMPONENT:0:3} == "lib" ]; then
            git clone --single-branch https://gitlab.com/prpl-foundation/components/ambiorix/libraries/$COMPONENT $COMPONENT
        else
            git clone --single-branch https://gitlab.com/prpl-foundation/components/ambiorix/applications/$COMPONENT $COMPONENT
        fi
    fi
    pushd $COMPONENT || exit 1
    if [ -f ../patches/${COMPONENT}.patch ]; then
        echo "*** running git apply ***"
        git apply ../patches/${COMPONENT}.patch;
    fi
    make && make install;
    popd || exit 1
done

./build/usr/bin/amxo-cg -G xml ../../controller/nbapi/odl/controller.odl
if [ ! -r controller.odl.xml ]; then
    echo -e "\\033[1;31mXML generation failed -- ODL syntax issue?\\033[0m"
    exit 1
fi
# install conversion files
ln -s "$(pwd)/build/etc/amx" /etc/amx
mkdir -p build/html
pushd build/html || exit 1
../usr/bin/amxo-xml-to -x html ../../controller.odl.xml
popd || exit 1
zip -r ppm_controller_nbapi_docs.zip build/html

