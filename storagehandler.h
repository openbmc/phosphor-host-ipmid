#ifndef __HOST_IPMI_STORAGE_HANDLER_H__
#define __HOST_IPMI_STORAGE_HANDLER_H__

// IPMI commands for Storage net functions.
enum ipmi_netfn_storage_cmds
{
    // Get capability bits
    IPMI_CMD_GET_FRU_INV_AREA_INFO  = 0x10,
    IPMI_CMD_GET_REPOSITORY_INFO = 0x20,
    IPMI_CMD_READ_FRU_DATA  = 0x11,
    IPMI_CMD_GET_SEL_INFO   = 0x40,
    IPMI_CMD_RESERVE_SEL    = 0x42,
    IPMI_CMD_GET_SEL_ENTRY  = 0x43,
    IPMI_CMD_ADD_SEL        = 0x44,
    IPMI_CMD_DELETE_SEL     = 0x46,
    IPMI_CMD_CLEAR_SEL      = 0x47,
    IPMI_CMD_GET_SEL_TIME   = 0x48,
    IPMI_CMD_SET_SEL_TIME   = 0x49,

};

struct ipmi_add_sel_request_t {

	uint8_t recordid[2];
	uint8_t recordtype;
	uint8_t timestampe[4];
	uint8_t generatorid[2];
	uint8_t evmrev;
	uint8_t sensortype;
	uint8_t sensornumber;
	uint8_t eventdir;
	uint8_t eventdata[3];
};

/**
 * @struct Read FRU Data command request data
 */
struct ReadFruDataRequest
{
    uint8_t  fruID; ///< FRU Device ID. FFh = reserved
    uint8_t  offsetLS; ///< FRU Inventory Offset to read, LS Byte
    uint8_t  offsetMS; ///< FRU Inventory Offset ro read, MS Byte
    uint8_t  count; ///< Count to read
}__attribute__ ((packed));

/**
 * @struct Get FRU inventory area info command request data
 */
struct FruInvenAreaInfoRequest
{
    uint8_t fruID; ///< FRU Device ID. FFH = reserved.
}__attribute__ ((packed));


/**
 * @struct Get FRU inventory area info command response
 */
struct FruInvenAreaInfoResponse
{
    uint8_t  completionCode;  ///< Completion code
    uint8_t  sizels;          ///< Fru Inventory area size in bytes, LS Byte
    uint8_t  sizems;          ///< Fru Inventory are size in bytes, MS Byte
    uint8_t  access;    ///< 0b Devices is accessed by bytes, 1b - by words
}__attribute__ ((packed));

/**
 * @struct Get Repository info command response
 */
struct GetRepositoryInfoResponse
{
    uint8_t sdrVersion;  //< SDR version
    uint8_t recordCountLs; //< Record count LS byte
    uint8_t recordCountMs; //< Record count MS bte
    uint8_t freeSpace[2];  //< Free space in bytes, LS first
    uint8_t additionTimestamp[4]; //< Most recent addition timestamp LS first
    uint8_t deletionTimestamp[4]; //< Most recent deletion timestamp LS first
    uint8_t operationSupport; //< Operation support
}__attribute__ ((packed));
#endif
