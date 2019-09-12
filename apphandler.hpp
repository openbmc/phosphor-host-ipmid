#pragma once

#include <stdint.h>

// IPMI commands for App net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_DEVICE_ID = 0x01,
    IPMI_CMD_GET_SELF_TEST_RESULTS = 0x04,
    IPMI_CMD_SET_ACPI = 0x06,
    IPMI_CMD_GET_ACPI = 0x07,
    IPMI_CMD_GET_DEVICE_GUID = 0x08,
    IPMI_CMD_RESET_WD = 0x22,
    IPMI_CMD_SET_WD = 0x24,
    IPMI_CMD_GET_WD = 0x25,
    IPMI_CMD_GET_CAP_BIT = 0x36,
    IPMI_CMD_GET_SYS_GUID = 0x37,
    IPMI_CMD_SET_CHAN_ACCESS = 0x40,
    IPMI_CMD_GET_CHANNEL_ACCESS = 0x41,
    IPMI_CMD_GET_CHAN_INFO = 0x42,
    IPMI_CMD_GET_CHAN_CIPHER_SUITES = 0x54,
    IPMI_CMD_SET_SYSTEM_INFO = 0x58,
    IPMI_CMD_GET_SYSTEM_INFO = 0x59,
};
