#pragma once

#include <cstdint>

// IPMI commands for Storage net functions.
enum ipmi_netfn_storage_cmds
{
    // Get capability bits
    IPMI_CMD_GET_FRU_INV_AREA_INFO = 0x10,
    IPMI_CMD_GET_REPOSITORY_INFO = 0x20,
    IPMI_CMD_READ_FRU_DATA = 0x11,
    IPMI_CMD_RESERVE_SDR = 0x22,
    IPMI_CMD_GET_SDR = 0x23,
    IPMI_CMD_GET_SEL_INFO = 0x40,
    IPMI_CMD_RESERVE_SEL = 0x42,
    IPMI_CMD_GET_SEL_ENTRY = 0x43,
    IPMI_CMD_ADD_SEL = 0x44,
    IPMI_CMD_DELETE_SEL = 0x46,
    IPMI_CMD_CLEAR_SEL = 0x47,
    IPMI_CMD_GET_SEL_TIME = 0x48,
    IPMI_CMD_SET_SEL_TIME = 0x49,

};

/**
 * @struct Read FRU Data command request data
 */
struct ReadFruDataRequest
{
    uint8_t fruID;    ///< FRU Device ID. FFh = reserved
    uint8_t offsetLS; ///< FRU Inventory Offset to read, LS Byte
    uint8_t offsetMS; ///< FRU Inventory Offset ro read, MS Byte
    uint8_t count;    ///< Count to read
} __attribute__((packed));

/**
 * @struct Read FRU Data command response data
 */
struct ReadFruDataResponse
{
    uint8_t count;  ///< Response data Count.
    uint8_t data[]; ///< Response data.
} __attribute__((packed));

/**
 * @struct Get Repository info command response
 */
struct GetRepositoryInfoResponse
{
    uint8_t sdrVersion;           //< SDR version
    uint8_t recordCountLs;        //< Record count LS byte
    uint8_t recordCountMs;        //< Record count MS bte
    uint8_t freeSpace[2];         //< Free space in bytes, LS first
    uint8_t additionTimestamp[4]; //< Most recent addition timestamp LS first
    uint8_t deletionTimestamp[4]; //< Most recent deletion timestamp LS first
    uint8_t operationSupport;     //< Operation support
} __attribute__((packed));
