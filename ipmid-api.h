#ifndef __HOST_IPMID_IPMI_COMMON_H__
#define __HOST_IPMID_IPMI_COMMON_H__
#include <stdlib.h>

// length of Completion Code and its ALWAYS _1_
#define IPMI_CC_LEN 1

// IPMI Net Function number as specified by IPMI V2.0 spec.
// Example : 
// NETFUN_APP      =   (0x06 << 2),
typedef unsigned char   ipmi_netfn_t;

// IPMI Command for a Net Function number as specified by IPMI V2.0 spec.
typedef unsigned char   ipmi_cmd_t;

// Buffer containing data from sender of netfn and command as part of request
typedef void*           ipmi_request_t;

// This is the response buffer that the provider of [netfn,cmd] will send back
// to the caller. Provider will allocate the memory inside the handler and then
// will do a memcpy to this response buffer and also will set the data size
// parameter to the size of the buffer.
// EXAMPLE :
// unsigned char str[] = {0x00, 0x01, 0xFE, 0xFF, 0x0A, 0x01};
// *data_len = 6;
// memcpy(response, &str, *data_len);
typedef void*           ipmi_response_t;

// This buffer contains any *user specific* data that is of interest only to the
// plugin. For a ipmi function router, this data is opaque. At the time of
// registering the plugin handlers, plugin may optionally allocate a memory and
// fill in whatever needed that will be of help during the actual handling of
// command. IPMID will just pass the netfn, cmd and also this data to plugins
// during the command handler invocation.
typedef void*           ipmi_context_t;

// Length of request / response buffer depending on whether the data is a
// request or a response from a plugin handler.
typedef size_t*   ipmi_data_len_t;

// Plugin function return the status code
typedef unsigned char ipmi_ret_t;

// This is the callback handler that the plugin registers with IPMID. IPMI
// function router will then make a call to this callback handler with the
// necessary arguments of netfn, cmd, request, response, size and context.
typedef ipmi_ret_t (*ipmid_callback_t)(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                       ipmi_response_t, ipmi_data_len_t, ipmi_context_t);

// This is the constructor function that is called into by each plugin handlers.
// When ipmi sets up the callback handlers, a call is made to this with
// information of netfn, cmd, callback handler pointer and context data.
// Making this a extern "C" so that plugin libraries written in C can also use
// it.
extern "C" void ipmi_register_callback(ipmi_netfn_t, ipmi_cmd_t, 
                                       ipmi_context_t, ipmid_callback_t);

// These are the command network functions, the response
// network functions are the function + 1. So to determine
// the proper network function which issued the command
// associated with a response, subtract 1.
// Note: these are also shifted left to make room for the LUN.
enum ipmi_net_fns
{
    NETFUN_CHASSIS  =   0x00,
    NETFUN_BRIDGE   =   0x02,
    NETFUN_SENSOR   =   0x04,
    NETFUN_APP      =   0x06,
    NETFUN_FIRMWARE =   0x08,
    NETFUN_STORAGE  =   0x0a,
    NETFUN_TRANPORT =   0x0c,
    NETFUN_GRPEXT   =   0x2c,
    NETFUN_NONE     =   0x30,
    NETFUN_OEM      =   0x32
};

// IPMI commands for net functions. Since this is to be used both by the ipmi
// function router and also the callback handler registration function, its put
// in this .H file.
enum ipmi_netfn_wild_card_cmd
{
    IPMI_CMD_WILDCARD       = 0xFF,
};

// Return (completion) codes from a IPMI operation as needed by IPMI V2.0 spec.
enum ipmi_return_codes
{
    IPMI_CC_OK = 0x00,
    IPMI_DCMI_CC_NO_ACTIVE_POWER_LIMIT = 0x80,
    IPMI_CC_INVALID = 0xC1,
    IPMI_CC_SENSOR_INVALID = 0xCB,
    IPMI_CC_RESPONSE_ERROR = 0xCE,
    IPMI_CC_UNSPECIFIED_ERROR = 0xFF,
};

#endif
