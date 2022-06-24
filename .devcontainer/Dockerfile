#-------------------------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
#-------------------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/vscode/devcontainers/base:ubuntu-18.04

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Install build essintials
RUN apt-get update && apt-get -y upgrade \
    #
    # Install C++ tools
    && apt-get -y install build-essential cmake cppcheck valgrind \
    # Libraries
    libjson-c-dev python-yaml python3-pip python3-yaml libssl-dev \
    libnl-3-dev libnl-route-3-dev libnl-genl-3-dev \
    # Install Helper tools
    bash-completion locales ninja-build pkg-config shellcheck \
    flake8 clang-format vim bridge-utils \
    # Ambiorix dependecies
    bison curl flex libevent-dev libyajl-dev libxslt1-dev lua5.1 liblua5.1-0-dev liburiparser-dev libxml2-dev \
    # Network capturing
    tcpdump tshark wireshark-common openssh-server

# Install python dependencies
RUN pip3 install pylint autopep8 pycodestyle==2.3

# # Install podman
# RUN echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_$(lsb_release -sr)/ /" \
#     > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list \
#     && curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_$(lsb_release -sr)/Release.key" | apt-key add - \
#     && apt-get update && apt-get install -y podman dnsmasq \
#     && ln -s /usr/bin/podman /usr/bin/docker

# Install docker-ce
RUN apt-get -y install apt-transport-https ca-certificates \
    curl gnupg-agent software-properties-common \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && apt-key fingerprint 0EBFCD88 \
    && add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) \
    stable" \
    && apt update \
    && apt -y install docker-ce docker-ce-cli containerd.io

# Install docker compose
RUN curl -L "https://github.com/docker/compose/releases/download/1.28.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

# We need liburiparser-dev > v. 9.0 which isn't avalaible in default
# 18.04 Ubuntu repos. So add Ubuntu 19.10 repo which has v. 0.9.3-2
RUN echo "deb http://old-releases.ubuntu.com/ubuntu eoan main universe" | tee -a /etc/apt/sources.list.d/eoan.list && \
    apt-get update && apt-get install -y --only-upgrade liburiparser-dev && \
    rm /etc/apt/sources.list.d/eoan.list

RUN curl https://storage.googleapis.com/git-repo-downloads/repo > /usr/bin/repo && \
    chmod +x /usr/bin/repo

# Install Ambiorix libraries
WORKDIR /tmp/ambiorix

# Fetch, checkout on fixed commit which works and install libubox
RUN git clone git://git.openwrt.org/project/libubox.git && \
    cd libubox && git checkout 9e52171d70def760a6949676800d0b73f85ee22d && \
    cmake -H"$(pwd)"/. -B"$(pwd)"/build/. -DCMAKE_INSTALL_PREFIX=/usr && \
    make install -C build

# Fetch, checkout on fixed commit which works and install Ubus daemon
RUN git clone git://git.openwrt.org/project/ubus.git && \
    cd ubus && git checkout 13a4438b4ebdf85d301999e0a615640ac4c9b0a8 && \
    cmake -H"$(pwd)"/. -B"$(pwd)"/build/. -DCMAKE_INSTALL_PREFIX=/usr && \
    make install -C build

# Fetch and intall Bus Agnostic API libs, applications.
# As they have some internal dependencies - we should build & install
# them in specific order.
RUN repo init -u https://gitlab.com/prpl-foundation/components/ambiorix/ambiorix.git \
    -b refs/tags/v1.15.2 < /dev/null && \
    repo sync && \
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

# Switch back into the workspace directory
WORKDIR /workspace

# Clean up
RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/ambiorix

# Update locale
RUN locale-gen en_US.UTF-8 && update-locale

# Add GitHub SSH fingerprint to the known_hosts file
RUN mkdir -p /root/.ssh && ssh-keyscan github.com >> /root/.ssh/known_hosts
RUN mkdir -p /root/.ssh && ssh-keyscan gitlab.com >> /root/.ssh/known_hosts

# Set default 'root' password
RUN echo 'root:prplmesh' | chpasswd

# Install configuration files
COPY scripts/etc/ssh/sshd_config /etc/ssh/
COPY scripts/etc/containers/libpod.conf /etc/containers/

# Install shell config files
COPY scripts/root/.bashrc /root/
COPY scripts/root/.inputrc /root/

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Default user is root
ENV USER=root

# SSH Server
EXPOSE 2222
