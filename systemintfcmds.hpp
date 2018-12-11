#pragma once

#include <stdint.h>
#include <host-ipmid/ipmid-api.h>

// These are per skiboot ipmi-sel code

// OEM_SEL type with Timestamp
#define SEL_OEM_ID_0 0x55
// SEL type is OEM and -not- general SEL
#define SEL_RECORD_TYPE_OEM 0xC0
// Minor command for soft shurdown
#define SOFT_OFF 0x00
// Major command for Any kind of power ops
#define CMD_POWER 0x04
// Major command for the heartbeat operation (verify host is alive)
#define CMD_HEARTBEAT 0xFF


// global enables
// bit0   - Message Receive Queue enable
// bit1   - Enable Event Message Buffer Full Interrupt
// bit2   - Enable Event Message Buffer
// bit3   - Enable System Event Logging
// bit4   - reserved
// bit5-7 - OEM 0~2 enables
static constexpr uint8_t globalEnablesDefault = 0x09;
static constexpr uint8_t selEnable = 0x08;
static constexpr uint8_t recvMsgQueueEnable = 0x01;

// IPMI commands used via System Interface functions.
enum ipmi_netfn_system_intf_cmds
{
    IPMI_CMD_SET_BMC_GLOBAL_ENABLES = 0x2E,
    IPMI_CMD_GET_BMC_GLOBAL_ENABLES = 0x2F,
    IPMI_CMD_GET_MSG_FLAGS = 0x31,
    IPMI_CMD_READ_EVENT = 0x35,
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
