#ifndef __HOST_IPMI_STORAGE_HANDLER_H__
#define __HOST_IPMI_STORAGE_HANDLER_H__

#include <stdint.h>
#include <stddef.h>

// IPMI commands for Storage net functions.
enum ipmi_netfn_storage_cmds
{
    // Get capability bits
    IPMI_CMD_WRITE_FRU_DATA = 0x12,
    IPMI_CMD_GET_SEL_INFO   = 0x40,
    IPMI_CMD_RESERVE_SEL    = 0x42,
    IPMI_CMD_ADD_SEL        = 0x44,
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

// Format of write fru data command
struct write_fru_data_t 
{
    uint8_t  frunum;
    uint8_t  offsetls;
    uint8_t  offsetms;
    uint8_t  data;
}__attribute__ ((packed));

// Per IPMI v2.0 FRU specification
struct common_header
{
    uint8_t fixed;
    uint8_t internal_offset;
    uint8_t chassis_offset;
    uint8_t board_offset;
    uint8_t product_offset;
    uint8_t multi_offset;
    uint8_t pad;
    uint8_t crc;
}__attribute__((packed));

// Contains key info about a particular area.
typedef struct
{
    uint8_t type;
    uint8_t *offset;
    size_t  len;
}__attribute__((packed)) fru_area_t;

// first byte in header is 1h per IPMI V2 spec.
#define IPMI_FRU_HDR_BYTE_ZERO   1
#define IPMI_FRU_INTERNAL_OFFSET offsetof(struct common_header, internal_offset)
#define IPMI_FRU_CHASSIS_OFFSET  offsetof(struct common_header, chassis_offset)
#define IPMI_FRU_BOARD_OFFSET    offsetof(struct common_header, board_offset)
#define IPMI_FRU_PRODUCT_OFFSET  offsetof(struct common_header, product_offset)
#define IPMI_FRU_MULTI_OFFSET    offsetof(struct common_header, multi_offset)
#define IPMI_FRU_HDR_CRC_OFFSET  offsetof(struct common_header, crc)
#define IPMI_EIGHT_BYTES         8

#endif
