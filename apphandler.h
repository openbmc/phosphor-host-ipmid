#ifndef __HOST_IPMI_APP_HANDLER_H__
#define __HOST_IPMI_APP_HANDLER_H__

#include <stdint.h>

// These are per skiboot ipmi-sel code

// OEM_SEL type with Timestamp
#define SEL_OEM_ID_0		0x55
// SEL type is OEM and -not- general SEL
#define SEL_RECORD_TYPE_OEM	0xC0
// Minor command for soft shurdown
#define SOFT_OFF			0x00
// Major command for Any kind of power ops
#define CMD_POWER			0x04

// IPMI commands for App net functions.
enum ipmi_netfn_app_cmds
{
    // Get capability bits
    IPMI_CMD_GET_DEVICE_ID          = 0x01,
    IPMI_CMD_SET_ACPI               = 0x06,
    IPMI_CMD_GET_DEVICE_GUID        = 0x08,
    IPMI_CMD_RESET_WD               = 0x22,
    IPMI_CMD_SET_WD                 = 0x24,
    IPMI_CMD_SET_BMC_GLOBAL_ENABLES = 0x2E,
    IPMI_CMD_GET_MSG_FLAGS          = 0x31,
    IPMI_CMD_READ_EVENT             = 0x35,
    IPMI_CMD_GET_CAP_BIT            = 0x36,
    IPMI_CMD_SET_CHAN_ACCESS        = 0x40,
    IPMI_CMD_GET_CHAN_INFO          = 0x42,

};

// A Mechanism to tell host to shtudown hosts by sending this PEM SEL. Really
// the only used fields by skiboot are:
// id[0] / id[1] for ID_0 , ID_1
// type : SEL_RECORD_TYPE_OEM as standard SELs are ignored by skiboot
// cmd : CMD_POWER for power functions
// data[0], specific commands.  example Soft power off. power cycle, etc.
struct oem_sel_timestamped
{
	/* SEL header */
	uint8_t id[2];
	uint8_t type;
	uint8_t manuf_id[3];
	uint8_t timestamp[4];
	/* OEM SEL data (6 bytes) follows */
	uint8_t netfun;
	uint8_t cmd;
	uint8_t data[4];
};
#endif
