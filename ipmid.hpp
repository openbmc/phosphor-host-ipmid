#ifndef __HOST_IPMID_IPMI_H__
#define __HOST_IPMID_IPMI_H__
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>
#include "host-services.h"

// Plugin libraries need to _end_ with .so
#define IPMI_PLUGIN_EXTN ".so"
// Plugin libraries can be versioned with suffix .so.*
#define IPMI_PLUGIN_SONAME_EXTN ".so."

// The BT FIFO in the AST2400 can only handle 64 bytes.  
// Can only allow 63 because the BT interface still 
// needs 1 byte for the length field. 
#define MAX_IPMI_BUFFER 64

extern FILE *ipmiio, *ipmidbus, *ipmicmddetails;

#endif
