#pragma once

#include <stdint.h>

enum ipmi_app_sysinfo_params
{
    IPMI_SYSINFO_SET_STATE = 0x00,
    IPMI_SYSINFO_SYSTEM_FW_VERSION = 0x01,
    IPMI_SYSINFO_SYSTEM_NAME = 0x02,
    IPMI_SYSINFO_PRIMARY_OS_NAME = 0x03,
    IPMI_SYSINFO_OS_NAME = 0x04,
    IPMI_SYSINFO_OS_VERSION = 0x05,
    IPMI_SYSINFO_BMC_URL = 0x06,
    IPMI_SYSINFO_OS_HYP_URL = 0x07,
    IPMI_SYSINFO_OEM_START = 0xC0, // Start of range of OEM parameters
};
