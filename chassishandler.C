#include "chassishandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// OpenBMC Chassis Manager dbus framework
const char  *chassis_bus_name      =  "org.openbmc.control.Chassis";
const char  *chassis_object_name   =  "/org/openbmc/control/chassis0";
const char  *chassis_intf_name     =  "org.openbmc.control.Chassis";

void register_netfn_chassis_functions() __attribute__((constructor));

struct get_sys_boot_options_t {
    uint8_t parameter;
    uint8_t set;
    uint8_t block;
}  __attribute__ ((packed));

ipmi_ret_t ipmi_chassis_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling CHASSIS WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

//------------------------------------------------------------
// Calls into Chassis Control Dbus object to do the power off
//------------------------------------------------------------
int ipmi_chassis_power_off()
{
	// sd_bus error
	int rc = 0;

    // SD Bus error report mechanism.
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

	// Response from the call. Although there is no response for this call,
	// obligated to mention this to make compiler happy.
	sd_bus_message *response = NULL;

	// Gets a hook onto either a SYSTEM or SESSION bus
	sd_bus *bus_type = ipmid_get_sd_bus_connection();

	rc = sd_bus_call_method(bus_type,        		 // On the System Bus
							chassis_bus_name,        // Service to contact
							chassis_object_name,     // Object path 
							chassis_intf_name,       // Interface name
							"powerOff",      		 // Method to be called
							&bus_error,      		 // object to return error
							&response,		 		 // Response buffer if any
							NULL);			 		 // No input arguments
	if(rc < 0)
	{
		fprintf(stderr,"ERROR initiating Power Off:[%s]\n",bus_error.message);
	}
	else
	{
		printf("Chassis Power Off initiated successfully\n");
	}

    sd_bus_error_free(&bus_error);
    sd_bus_message_unref(response);

	return rc;
}

//----------------------------------------------------------------------
// Chassis Control commands
//----------------------------------------------------------------------
ipmi_ret_t ipmi_chassis_control(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                        ipmi_request_t request, ipmi_response_t response, 
                        ipmi_data_len_t data_len, ipmi_context_t context)
{
	// Error from power off.
	int rc = 0;

	// No response for this command.
    *data_len = 0;

	// Catch the actual operaton by peeking into request buffer
	uint8_t chassis_ctrl_cmd = *(uint8_t *)request;
	printf("Chassis Control Command: Operation:[0x%X]\n",chassis_ctrl_cmd);

	switch(chassis_ctrl_cmd)
	{
		case CMD_POWER_OFF:
		case CMD_HARD_RESET:
		{
			rc = ipmi_chassis_power_off();
			break;
		}
		default:
		{
			fprintf(stderr, "Invalid Chassis Control command:[0x%X] received\n",chassis_ctrl_cmd);
			rc = -1;
		}
	}

	return ( (rc < 0) ? IPMI_CC_INVALID : IPMI_CC_OK);
}

ipmi_ret_t ipmi_chassis_get_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    printf("IPMI GET_SYS_BOOT_OPTIONS\n");

    get_sys_boot_options_t *reqptr = (get_sys_boot_options_t*) request;

    // TODO Return default values to OPAL until dbus interface is available

    if (reqptr->parameter == 5) // Parameter #5
    {
        uint8_t buf[] = {0x1,0x5,80,0,0,0,0};
        *data_len = sizeof(buf);
        memcpy(response, &buf, *data_len);
    }
    else
    {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        return IPMI_CC_PARM_NOT_SUPPORTED;        
    }

    return rc;
}

void register_netfn_chassis_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_WILDCARD, NULL, ipmi_chassis_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_GET_SYS_BOOT_OPTIONS, NULL, ipmi_chassis_get_sys_boot_options);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_CHASSIS, IPMI_CMD_CHASSIS_CONTROL);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_CHASSIS_CONTROL, NULL, ipmi_chassis_control);
}
