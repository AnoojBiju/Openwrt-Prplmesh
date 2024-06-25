FROM alpine:3.20

# prplMesh build
RUN apk add --update --no-cache \
    autoconf \
    binutils \
    bridge-utils \
    coreutils \
    cmake \
    curl \
    gcc \
    g++ \
    git \
    json-c-dev \
    libnl3-dev \
    libtool \
    musl-dev \
    zeromq-dev \
    linux-headers \
    make \
    ncurses-dev \
    ninja \
    openssl-dev \
    pkgconf \
    py3-yaml \
    python3 \
    sed \
    clang-extra-tools

# Ambiorix build
RUN apk add --update --no-cache \
    bison \
    flex \
    libevent-dev \
    libxslt-dev \
    lua5.1 \
    lua5.1-dev \
    libxml2-dev \
    liburiparser \
    openssh-client-default \
    ruby \
    uriparser-dev

# libyajl is not in the alpine repos, so build from src
RUN \
    git clone https://github.com/lloyd/yajl -b 2.1.0 && \
    cd yajl && ./configure && make install

RUN \
    git clone git://git.openwrt.org/project/libubox.git && \
    cd libubox && git checkout 9e52171d70def760a6949676800d0b73f85ee22d && \
    cmake -H"$(pwd)"/. -B"$(pwd)"/build/. -DCMAKE_INSTALL_PREFIX=/usr && \
    make install -C build

# Get and install repo
RUN \
    curl https://storage.googleapis.com/git-repo-downloads/repo > ./repo && \
    chmod a+rx ./repo

# Fetch and install Bus Agnostic API libs, applications.
# As they have some internal dependencies - we should build & install
# them in specific order.
RUN \
    ./repo init -u https://gitlab.com/prpl-foundation/components/ambiorix/ambiorix.git \
    -b refs/tags/v6.5.3 < /dev/null && \
    ./repo sync && \
    make install -C libraries/libamxc && \
    make install -C libraries/libamxp && \
    make install -C libraries/libamxd && \
    make install -C libraries/libamxj && \
    make install -C libraries/libamxo && \
    make install -C libraries/libamxb && \
    make install -C applications/amxb-inspect && \
    make install -C applications/amxo-cg && \
    make install -C applications/amxo-xml-to && \
    make -C bus_adaptors/amxb_ubus && \
    make install -C bus_adaptors/amxb_ubus

