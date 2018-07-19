# IPMI command cheat sheet

This document is intended to provide a set of IPMI commands for quick reference.

Note: If the ipmitool is on the BMC then set the interface as "-I dbus" and
if the ipmitool is outside the BMC (i.e on the network) then set the interface as
"-I lanplus".

## Network Configuration

### Set the interface mode

ipmitool lan set `<channel>` ipsrc static

### Set the IP Address

ipmitool lan set `<channel>` ipaddr `<ip>`

### Set the network mask

ipmitool lan set `<channel>` netmask `<mask>`

### Set the default gateway

ipmitool lan set `<channel>` defgw ipaddr `<ip>`

### Set the VLAN

ipmitool lan set `<channel>` vlan id `<id>`

### Delete the VLAN

ipmitool lan set `<channel>` vlan id off

NOTE: The user can group multiple set operations since the IPMI daemon
waits for 10 seconds after each set operation before applying the configuration.
