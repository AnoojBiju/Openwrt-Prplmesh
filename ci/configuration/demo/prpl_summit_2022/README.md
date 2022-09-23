# Demo devices configuration

The files in this directory are meant to configure the devices used for the prpl summit 2022 demo.

## Devices

### glinet-b1300-1

This device is meant to be the controller, and have a local agent as well.
It configures one combined fronthaul+backhaul interface on each radio.

A DHCP server is also running on the devices, so that WiFi clients that connect get an IP.

For ethernet ports, all of them are part of the LAN bridge so that all physical ports can be used to connect an agent.

## glinet-b1300-2

This devices is meant to be an agent connected over wireless backhaul.

It only has one backhaul STA interface defined, to make sure we can onboarding using WPS without creating a loop in the network (as prplMesh doesn't currently handle multiple backhaul links).

Like `glinet-b1300-1`, all of its ethernet ports can be used to connect other agents.

## turris-omnia-1

This device is meant to run RDK-B, connected over wired backhaul to another agent.
