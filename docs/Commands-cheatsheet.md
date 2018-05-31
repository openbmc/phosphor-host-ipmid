# IPMI command cheat sheet

This document is intended to provide a set of IPMI commands for quick reference.

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

NOTE:- User can group multiple set operations as
IPMI daemon waits for 10 second after each set operation
before applying the configuration.
