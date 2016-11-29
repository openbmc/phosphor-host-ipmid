#ifndef __HOST_IPMID_IPMI_H__
#define __HOST_IPMID_IPMI_H__
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include "host-services.h"

// When the requester sends in a netfn and a command along with data, this
// function will look for registered handlers that will handle that [netfn,cmd]
// and will make a call to that plugin implementation and send back the response.
ipmi_ret_t ipmi_netfn_router(const ipmi_netfn_t, const ipmi_cmd_t, ipmi_request_t,
                             ipmi_response_t, unsigned int *data_len);

// Plugin libraries need to _end_ with .so
#define IPMI_PLUGIN_EXTN ".so"
// Plugin libraries can be versioned with suffix .so.*
#define IPMI_PLUGIN_SONAME_EXTN ".so."

extern FILE *ipmiio, *ipmidbus, *ipmicmddetails;

#endif
