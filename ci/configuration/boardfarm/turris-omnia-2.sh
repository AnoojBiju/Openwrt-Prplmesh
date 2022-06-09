#!/bin/sh

set -e

# VLAN interface to control the device separatly:
ip link add link lan4 name lan4.200 type vlan id 200
ip addr add 192.168.200.140/24 dev lan4.200
