#ifndef __HOST_IPMID_IPMI_H__
#define __HOST_IPMID_IPMI_H__
#include "host-ipmid/ipmid-api.h"
#include <stdio.h>

// The BT FIFO in the AST2400 can only handle 64 bytes.
// Can only allow 63 because the BT interface still
// needs 1 byte for the length field.
#define MAX_IPMI_BUFFER 64

#endif
