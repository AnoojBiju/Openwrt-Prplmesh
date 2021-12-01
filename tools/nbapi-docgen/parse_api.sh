#!/bin/sh

if [ $(basename $(pwd)) != nbapi-docgen ]; then
    echo "Please execute this file from its own directory"
    exit
fi

# Dependency: yajl
# Make a build dir
mkdir -p build
# amx components look for input variables (include files, libs) in a "staging dir" ...
export STAGINGDIR=$(cd build && pwd)
# ... and they put their files in a DEST dir. We need those to be the same
export DEST=$STAGINGDIR
# amx components try to install libs to machine-dependent dirs, but then don't include those directories in their linker paths ...
export MACHINE= 

for COMPONENT in libamxc libamxj libamxp libamxd libamxo amxo-cg amxo-xml-to; do
    if [ -d $COMPONENT ]; then 
        #rm -rf $COMPONENT;
        (cd $COMPONENT && git pull)
    else
        #mkdir $COMPONENT; 
        if [ ${COMPONENT:0:3} == "lib" ]; then
            git clone --progress --single-branch git@gitlab.com:prpl-foundation/components/ambiorix/libraries/$COMPONENT $COMPONENT
        else
            git clone --progress --single-branch git@gitlab.com:prpl-foundation/components/ambiorix/applications/$COMPONENT $COMPONENT
        fi
    fi
    pushd $COMPONENT;
    if [ -f ../patches/${COMPONENT}.patch ]; then
        echo "*** running git apply ***"
        git apply ../patches/${COMPONENT}.patch;
    fi
    make && make install;
    popd;
done

export LD_LIBRARY_PATH=${STAGINGDIR}/usr/lib
./build/usr/bin/amxo-cg -G xml ../../controller/nbapi/odl/controller.odl
if [ ! -r controller.odl.xml ]; then
    echo -e "\033[1;31mXML generation failed -- ODL syntax issue?\033[0m"
    exit
fi
mkdir -p build/html
pushd build/html
../usr/bin/amxo-xml-to -x html ../../controller.odl.xml
popd
zip -r ppm_controller_nbapi_docs.zip build/html

