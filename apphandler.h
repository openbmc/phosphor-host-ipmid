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
    IPMI_CMD_SET_CHAN_ACCESS        = 0x40,
    IPMI_CMD_GET_CHANNEL_ACCESS     = 0x41,
    IPMI_CMD_GET_CHAN_INFO          = 0x42,
};

/** @struct GetChannelAccessRequest
 *
 *  IPMI payload for Get Channel access command request.
 */
struct GetChannelAccessRequest
{
    uint8_t channelNumber;      //!< Channel number.
    uint8_t volatileSetting;    //!< Get non-volatile or the volatile setting.
} __attribute__((packed));

/** @struct GetChannelAccessResponse
 *
 *  IPMI payload for Get Channel access command response.
 */
struct GetChannelAccessResponse
{
    uint8_t settings;          //!< Channel settings.
    uint8_t privilegeLimit;    //!< Channel privilege level limit.
} __attribute__((packed));

/* @struct DevIdInfo
 *
 * deviceid system specific fields.
 */
struct IpmiDevIdInfo
{
    uint8_t systemId;
    uint8_t sysRevisionId;
    uint8_t ipmiVersion;
    uint8_t addnDevSupport;
    uint32_t manufId;
    uint16_t productId[2];
};

#endif
