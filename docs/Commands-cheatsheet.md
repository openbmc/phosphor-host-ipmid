# IPMI command cheat sheet

This document is intended to provide a set of IPMI commnads for quick reference.

## Network Configuration

### Set the interface mode

ipmitool -I dbus lan set <channel> ipsrc static

### Set the IP Address

ipmitool -I dbus lan set <channel> ipaddr <ip>

### Set the network mask

ipmitool -I dbus lan set <channel> netmask <mask>

### Set the default gateway

ipmitool -I dbus lan set <channel> defgw ipaddr <ip>

### Set the VLAN

ipmitool -I dbus lan set <channel> vlan id <id>

### Delete the VLAN

ipmitool -I dbus lan set <channel> vlan id off

NOTE:- IPMI daemon waits for 10sec after any set operation
before apply the configuration.User can group multiple set opeartion in the
interval of 10 sec.
