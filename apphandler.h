#ifndef __HOST_IPMI_APP_HANDLER_H__
#define __HOST_IPMI_APP_HANDLER_H__

#include <stdint.h>

// IPMI commands for App net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_DEVICE_ID          = 0x01,
    IPMI_CMD_GET_SELF_TEST_RESULTS  = 0x04,
    IPMI_CMD_SET_ACPI               = 0x06,
    IPMI_CMD_GET_DEVICE_GUID        = 0x08,
    IPMI_CMD_RESET_WD               = 0x22,
    IPMI_CMD_SET_WD                 = 0x24,
    IPMI_CMD_GET_CAP_BIT            = 0x36,
    IPMI_CMD_GET_SYS_GUID           = 0x37,
    IPMI_CMD_SET_CHAN_ACCESS        = 0x40,
    IPMI_CMD_GET_CHANNEL_ACCESS     = 0x41,
    IPMI_CMD_GET_CHAN_INFO          = 0x42,
};

/**
 * @struct Format of the GUID data
 */
struct ipmi_guid_t
{
    uint32_t timeLow;      ///< timestamp low field
    uint16_t timeMid;      ///< timestamp middle field
    uint16_t timeHiAndVersion; ///< timestamp high field and version number
    uint8_t clockSeqHiVariant; ///< clock sequence high field and variant
    uint8_t clockSeqLow;  ///< clock sequence low field
    uint8_t node[6];      ///< node
} __attribute__((packed));

#endif
