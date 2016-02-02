#ifndef __HOST_IPMI_GLOBAL_HANDLER_H__
#define __HOST_IPMI_GLOBAL_HANDLER_H__

#include <stdint.h>

// Various GLOBAL operations under a single command.
enum ipmi_global_control_cmds : uint8_t
{
IPMI_CMD_WARM_RESET 			   = 0x02,
};

#endif
