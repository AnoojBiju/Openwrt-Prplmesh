#!/bin/sh -e

# We have to copy the source directory, because we may not have
# write access to it, and openwrt needs to at least write '.source_dir':
cp -r /home/openwrt/prplMesh_source /home/openwrt/prplMesh
# We want to make sure that we do not keep anything built from the host:
(cd /home/openwrt/prplMesh && \
    rm -rf build ipkg-* .built* .configured* .pkgdir .prepared .quilt_checked .source_dir)

make package/prplmesh/prepare USE_SOURCE_DIR="/home/openwrt/prplMesh" V=s
# Rebuild the full image:

if ! make -j"$(nproc)" ; then
    # Building failed. Rebuild with V=sc, but exit immediately even if
    # the second build succeeds (to let the user/CI know that the
    # parallel build failed).
    echo "Build failed. Rebuilding with -j1."
    make V=sc
    exit 1
fi

mkdir -p artifacts
cat << EOT >> artifacts/prplmesh.buildinfo
TARGET_SYSTEM=${TARGET_SYSTEM}
OPENWRT_VERSION=${OPENWRT_VERSION}
OPENWRT_TOOLCHAIN_VERSION=${OPENWRT_TOOLCHAIN_VERSION}
PRPLMESH_VERSION=${PRPLMESH_VERSION}
EOT
find bin -name 'prplmesh*.ipk' -exec cp -v {} "artifacts/prplmesh.ipk" \;
find bin/targets/"$TARGET_SYSTEM"/*/ -type f -maxdepth 1 -exec cp -v {} "artifacts/" \;
cp .config artifacts/openwrt.config
cp files/etc/prplwrt-version artifacts/
