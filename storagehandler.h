#ifndef __HOST_IPMI_STORAGE_HANDLER_H__
#define __HOST_IPMI_STORAGE_HANDLER_H__

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
#endif
