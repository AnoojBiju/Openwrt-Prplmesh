###############################################################
# SPDX-License-Identifier: BSD-2-Clause-Patent
# SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
###############################################################

FROM ubuntu:18.04

####
## Yocto pre-requisites and "rdk" user
####

# Building tlvfs currently uses the docker
# container's python (not the one from yocto)
# python-yaml is needed to build the tlvfs
# vim and less are there to debug builds at run time
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        build-essential \
        chrpath \
        cpio \
        debianutils \
        diffstat \
        file \
        gawk \
        gcc-multilib \
        git-core \
        gnupg \
        iputils-ping \
        less \
        locales \
        pylint3 \
        python \
        python-yaml \
        python3 \
        python3-git \
        python3-jinja2 \
        python3-pexpect \
        python3-pip \
        python3-yaml \
        rsync \
        socat \
        texinfo \
        unzip \
        vim \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    # Ubuntu has a repo package, but it's too old
    && wget -O /usr/bin/repo https://storage.googleapis.com/git-repo-downloads/repo \
    && chmod +x /usr/bin/repo \
    # https://wiki.yoctoproject.org/wiki/TipsAndTricks/ResolvingLocaleIssues
    # https://serverfault.com/questions/362903/how-do-you-set-a-locale-non-interactively-on-debian-ubuntu/801162#801162
    && echo "en_US.UTF-8 UTF-8" > /etc/locale.gen \
    && dpkg-reconfigure --frontend=noninteractive locales \
    && update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8

COPY git-askpass /usr/bin/git-askpass

ARG UID
ARG GID

RUN groupadd --gid $GID --non-unique rdk \
    && useradd --create-home --shell /bin/bash --non-unique --uid $UID --gid $GID rdk
USER rdk

ENV GIT_ASKPASS=/usr/bin/git-askpass

####
## Clone RDK-B repositories
####

ARG RDK_GIT_USER
ARG RDK_GIT_TOKEN
RUN git config --global \
        "url.https://$RDK_GIT_USER@code.rdkcentral.com/.insteadOf" https://code.rdkcentral.com/ \
    && git config --global user.email "prplmesh@prplfoundation.org" \
    && git config --global user.name "prplMesh RDK-B Build Bot" \
    && mkdir /home/rdk/rdk-b /home/rdk/cache
WORKDIR /home/rdk/rdk-b

RUN printf '\033[1;35m%s Cloning RDK-B\n\033[0m' "$(date --iso-8601=seconds --universal)" \
    && yes | repo init -u https://code.rdkcentral.com/r/manifests -b rdk-next -m rdkb-extsrc.xml \
    && repo sync

RUN printf '\033[1;35m%s Cloning meta-prplmesh\n\033[0m' "$(date --iso-8601=seconds --universal)" \
    && git clone https://gitlab.com/prpl-foundation/prplmesh/meta-prplmesh \
    && cd meta-prplmesh \
    && git checkout b70faeda76379313eb785727d5d74d3dd69c0490
