#include "chassishandler.h"
#include "ipmid-api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>
#include <string>
#include <sstream>
#include <array>
using namespace std;
//Defines
#define SET_PARM_VERSION                     0x01
#define SET_PARM_BOOT_FLAGS_PERMANENT        0x40 //boot flags data1 7th bit on
#define SET_PARM_BOOT_FLAGS_VALID_ONE_TIME   0x80 //boot flags data1 8th bit on
#define SET_PARM_BOOT_FLAGS_VALID_PERMANENT  0xC0 //boot flags data1 7 & 8 bit on 

constexpr size_t SIZE_MAC  = 18;
constexpr size_t SIZE_HOST_NETWORK_DATA = 26;
constexpr size_t SIZE_BOOT_OPTION = SIZE_HOST_NETWORK_DATA;
constexpr size_t SIZE_PREFIX = 7;

// OpenBMC Chassis Manager dbus framework
const char  *chassis_bus_name      =  "org.openbmc.control.Chassis";
const char  *chassis_object_name   =  "/org/openbmc/control/chassis0";
const char  *chassis_intf_name     =  "org.openbmc.control.Chassis";


void register_netfn_chassis_functions() __attribute__((constructor));

// Host settings in dbus
// Service name should be referenced by connection name got via object mapper
const char *settings_object_name  =  "/org/openbmc/settings/host0";
const char *settings_intf_name    =  "org.freedesktop.DBus.Properties";
const char *host_intf_name        =  "org.openbmc.settings.Host";

const char *objmapper_service_name =  "org.openbmc.ObjectMapper";
const char *objmapper_object_name  =  "/org/openbmc/ObjectMapper";
const char *objmapper_intf_name    =  "org.openbmc.ObjectMapper";

int object_mapper_get_connection(char **buf, const char *obj_path)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char *temp_buf = NULL, *intf = NULL;
    size_t buf_size = 0;
    int r;

    // Get the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
                           objmapper_service_name,                      /* service to contact */
                           objmapper_object_name,                       /* object path */
                           objmapper_intf_name,                         /* interface name */
                           "GetObject",                                 /* method name */
                           &error,                                      /* object to return error in */
                           &m,                                          /* return message on success */
                           "s",                                         /* input signature */
                           obj_path                                     /* first argument */
                          );

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    // Get the key, aka, the connection name
    sd_bus_message_read(m, "a{sas}", 1, &temp_buf, 1, &intf);

    /*
     * TODO: check the return code. Currently for no reason the message
     * parsing of object mapper is always complaining about
     * "Device or resource busy", but the result seems OK for now. Need
     * further checks.
     * TODO: The following code is preserved in the comments so that it can be
     * resumed after the problem aforementioned is resolved.
     *r = sd_bus_message_read(m, "a{sas}", 1, &temp_buf, 1, &intf);
     *if (r < 0) {
     *    fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
     *    goto finish;
     *}
     */

    buf_size = strlen(temp_buf) + 1;
    printf("IPMID connection name: %s\n", temp_buf);
    *buf = (char *)malloc(buf_size);

    if (*buf == NULL) {
        fprintf(stderr, "Malloc failed for get_sys_boot_options");
        r = -1;
        goto finish;
    }

    memcpy(*buf, temp_buf, buf_size);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return r;
}

int dbus_get_property(const char *name, char **buf)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char *temp_buf = NULL;
    char *connection = NULL;
    int r;

    r = object_mapper_get_connection(&connection, settings_object_name);

    if (r < 0) {
        fprintf(stderr, "Failed to get connection, return value: %d.\n", r);
        goto finish;
    }

    printf("connection: %s\n", connection);

    // Get the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
                           connection,                                 /* service to contact */
                           settings_object_name,                       /* object path */
                           settings_intf_name,                         /* interface name */
                           "Get",                                      /* method name */
                           &error,                                     /* object to return error in */
                           &m,                                         /* return message on success */
                           "ss",                                       /* input signature */
                           host_intf_name,                             /* first argument */
                           name);                                      /* second argument */

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    /*
     * The output should be parsed exactly the same as the output formatting
     * specified.
     */
    r = sd_bus_message_read(m, "v", "s", &temp_buf);
    if (r < 0) {
        fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

    asprintf(buf, "%s", temp_buf);
/*    *buf = (char*) malloc(strlen(temp_buf));
    if (*buf) {
        strcpy(*buf, temp_buf);
    }
*/
    printf("IPMID boot option property get: {%s}.\n", (char *) temp_buf);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    free(connection);

    return r;
}

int dbus_set_property(const char * name, const char *value)
{
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    char *connection = NULL;
    int r;

    r = object_mapper_get_connection(&connection, settings_object_name);

    if (r < 0) {
        fprintf(stderr, "Failed to get connection, return value: %d.\n", r);
        goto finish;
    }

    printf("connection: %s\n", connection);

    // Get the system bus where most system services are provided.
    bus = ipmid_get_sd_bus_connection();

    /*
     * Bus, service, object path, interface and method are provided to call
     * the method.
     * Signatures and input arguments are provided by the arguments at the
     * end.
     */
    r = sd_bus_call_method(bus,
                           connection,                                 /* service to contact */
                           settings_object_name,                       /* object path */
                           settings_intf_name,                         /* interface name */
                           "Set",                                      /* method name */
                           &error,                                     /* object to return error in */
                           &m,                                         /* return message on success */
                           "ssv",                                      /* input signature */
                           host_intf_name,                             /* first argument */
                           name,                                       /* second argument */
                           "s",                                        /* third argument */
                           value);                                     /* fourth argument */

    if (r < 0) {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    printf("IPMID boot option property set: {%s}.\n", value);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    free(connection);

    return r;
}

struct get_sys_boot_options_t {
    uint8_t parameter;
    uint8_t set;
    uint8_t block;
}  __attribute__ ((packed));

struct get_sys_boot_options_response_t {
    uint8_t version;
    uint8_t parm;
    uint8_t data[SIZE_BOOT_OPTION];
}  __attribute__ ((packed));

struct set_sys_boot_options_t {
    uint8_t parameter;
    uint8_t data[SIZE_BOOT_OPTION];
}  __attribute__ ((packed));

struct host_network_config_t {
     string ipaddress;
     string prefix;
     string gateway;
     string macaddress;
     string isDHCP;

     host_network_config_t()=default;
};

void fillNetworkConfig( host_network_config_t& host_config , string conf_str) {

    constexpr auto COMMA_DELIMITER = ",";
    constexpr auto EQUAL_DELIMITER = "=";
    //pos=CommaDelimeter position,pos1=EqualDelimetr position
    //prevPos= Prev Position of CommaDelimeter in the string
    size_t pos,pos1,prevPos = 0;
    string name,value;

    while ( pos < conf_str.length() ) {

        pos = conf_str.find(COMMA_DELIMITER,pos);

        //This condition is to extract the last
        //Substring as we will not be having the delimeter
        //at end. std::string::npos is -1

        if ( pos == std::string::npos ) {
            pos = conf_str.length();
        }

        pos1 = conf_str.substr(prevPos, pos).find (EQUAL_DELIMITER);

        if ( pos1 == std::string::npos ) {
            break;
        }

        name = conf_str.substr(prevPos,pos1);
        value = conf_str.substr(pos1+prevPos+1,(pos-(pos1+prevPos+1)));

#ifdef _IPMI_DEBUG_
        printf ("Name=[%s],Value=[%s]\n",name.c_str(),value.c_str());
#endif

        if ( name == "ipaddress" ) {
            host_config.ipaddress = value;
        }
        else if ( name == "prefix") {
            host_config.prefix = value;
        }
        else if ( name == "gateway" ) {
            host_config.gateway = value;
        }
        else if ( name == "mac" ) {
            host_config.macaddress = value;
        }
        else if ( name == "dhcp" ) {
            host_config.isDHCP = value;
        }

        pos++;
        prevPos= pos;
    }
}

int  getHostNetworkData(get_sys_boot_options_response_t* respptr)
{

    char *prop = nullptr;

    // Petitboot-specific
    std::array<uint8_t, SIZE_BOOT_OPTION> respData{0x80,0x21, 0x70 ,0x62 ,0x21,0x00 ,0x01 ,0x06 ,0x04};

    int rc = dbus_get_property("network_config",&prop);

    if ( rc < 0 ) {
        fprintf(stderr, "Dbus get property(boot_flags) failed for get_sys_boot_options.\n");
        return rc;
    }

    string conf_str(prop);

    if ( prop ) {

        free(prop);
        prop = nullptr;
    }

    /* network_config property Value would be in the form of
     * ipaddress=1.1.1.1,prefix=16,gateway=2.2.2.2,mac=11:22:33:44:55:66,dhcp=0
     */

    /* Parsing the string and fill the hostconfig structure with the
     * values */

    printf ("Configuration String[%s]\n ",conf_str.c_str());

    host_network_config_t host_config;

    // Fill the host_config from the configuration string
    fillNetworkConfig(host_config,conf_str);

    //Starting from index 9 as 9 bytes are prefilled.
    uint8_t index = 9;

    do{

        rc = sscanf(host_config.macaddress.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &respData[index], &respData[index+1], &respData[index+2],
                &respData[index+3], &respData[index+4], &respData[index+5]);

        if ( rc < 6 ){
            fprintf(stderr, "sscanf Failed in extracting mac address.\n");
            rc = -1;
            break;
        }

        index+=6;
        //Conevrt the dhcp,ipaddress,mask and gateway as hex number
        respData[index++]=0x00;
        rc = sscanf(host_config.isDHCP.c_str(),"%02X",&respData[index++]);

        if ( rc <= 0 ) {
            fprintf(stderr, "sscanf Failed in extracting dhcp.\n");
            rc = -1;
            break;
        }

        //ipaddress and gateway would be in IPv4 format
        rc = inet_pton(AF_INET,host_config.ipaddress.c_str(),(void *)&respData[index]);

        if ( rc <= 0 ) {
            fprintf(stderr, "inet_pton failed during ipaddress coneversion\n");
            rc = -1;
            break;
        }
        index+=4;

        rc = sscanf(host_config.prefix.c_str(),"%02d",&respData[index++]);

        if ( rc <= 0 ) {
            fprintf(stderr, "sscanf failed during prefix extraction.\n");
            rc = -1;
            break;
        }

        rc = inet_pton(AF_INET,host_config.gateway.c_str(),(void *)&respData[index]);

        if ( rc <= 0 ) {
            fprintf(stderr, "inet_pton failed during gateway conversion.\n");
            rc = -1;
            break;
        }
        index+=4;

    }while (0);

    if ( rc ) {

#ifdef _IPMI_DEBUG_
        printf ("\n===Printing the IPMI Formatted Data========\n");

        for (int j = 0;j<index;j++)
            printf("%02x ", respData[j]);
#endif
        //Once all the validation have been passed then
        //copy the data to the respData.
        memcpy(respptr->data,respData.data(),SIZE_BOOT_OPTION);
    }
    return rc;
}

uint8_t setHostNetworkData(set_sys_boot_options_t * reqptr)
{
    string host_network_config;
    char mac[SIZE_MAC] = {0};
    char ipAddress[INET_ADDRSTRLEN] = {0};
    char gateway[INET_ADDRSTRLEN] = {0};
    char dhcp[SIZE_PREFIX] = {0};
    char prefix[SIZE_PREFIX] = {0};
    uint32_t cookie = 0;

    memcpy(&cookie,(char *)&(reqptr->data[1]),sizeof(cookie));

    uint8_t index = 9;

    if ( cookie ) {

            snprintf(mac, SIZE_MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
            reqptr->data[index],
            reqptr->data[index+1],
            reqptr->data[index+2],
            reqptr->data[index+3],
            reqptr->data[index+4],
            reqptr->data[index+5]);

        snprintf(dhcp,SIZE_PREFIX, "%d", reqptr->data[index+7]);

        snprintf(ipAddress, INET_ADDRSTRLEN, "%d.%d.%d.%d",
            reqptr->data[index+8], reqptr->data[index+9], reqptr->data[index+10], reqptr->data[index+11]);

        snprintf(prefix,SIZE_PREFIX,"%d", reqptr->data[index+12]);

        snprintf(gateway, INET_ADDRSTRLEN, "%d.%d.%d.%d",
            reqptr->data[index+13], reqptr->data[index+14], reqptr->data[index+15], reqptr->data[index+16]);
    }

    host_network_config += "ipaddress="+string(ipAddress)+",prefix="+ \
                       string(prefix)+",gateway="+string(gateway)+\
                       ",mac="+string(mac)+",dhcp="+string(dhcp);

    printf ("Network configuration changed: %s\n",host_network_config.c_str());

    int rc = dbus_set_property("network_config",host_network_config.c_str());

    if ( rc < 0 ) {
        fprintf(stderr, "Dbus set property(network_config) failed for set_sys_boot_options.\n");
        rc = IPMI_CC_UNSPECIFIED_ERROR;
    }
    return rc;
}

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
int ipmi_chassis_power_control(const char *method)
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
							method,      		 // Method to be called
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
			rc = ipmi_chassis_power_control("powerOff");
			break;
		case CMD_HARD_RESET:
			rc = ipmi_chassis_power_control("reboot");
			break;
		default:
		{
			fprintf(stderr, "Invalid Chassis Control command:[0x%X] received\n",chassis_ctrl_cmd);
			rc = -1;
		}
	}

	return ( (rc < 0) ? IPMI_CC_INVALID : IPMI_CC_OK);
}

struct bootOptionTypeMap_t {
    uint8_t ipmibootflag;
    char    dbusname[8];
};

#define INVALID_STRING "Invalid"
// dbus supports this list of boot devices.
bootOptionTypeMap_t g_bootOptionTypeMap_t[] = {

    {0x01, "Network"},
    {0x02, "Disk"},
    {0x03, "Safe"},
    {0x05, "CDROM"},
    {0x06, "Setup"},
    {0x00, "Default"},
    {0xFF, INVALID_STRING}
};

uint8_t get_ipmi_boot_option(char *p) {

    bootOptionTypeMap_t *s = g_bootOptionTypeMap_t;

    while (s->ipmibootflag != 0xFF) {
        if (!strcmp(s->dbusname,p))
            break;
        s++;
    }

    if (!s->ipmibootflag)
        printf("Failed to find Sensor Type %s\n", p);

    return s->ipmibootflag;
}

char* get_boot_option_by_ipmi(uint8_t p) {

    bootOptionTypeMap_t *s = g_bootOptionTypeMap_t;

    while (s->ipmibootflag != 0xFF) {

        if (s->ipmibootflag == p)
            break;

        s++;
    }


    if (!s->ipmibootflag)
        printf("Failed to find Sensor Type 0x%x\n", p);

    return s->dbusname;
}

ipmi_ret_t ipmi_chassis_get_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_PARM_NOT_SUPPORTED;
    char *p = NULL;
    get_sys_boot_options_response_t *resp = (get_sys_boot_options_response_t *) response;
    get_sys_boot_options_t *reqptr = (get_sys_boot_options_t*) request;
    uint8_t s;

    printf("IPMI GET_SYS_BOOT_OPTIONS\n");

    memset(resp,0,sizeof(*resp));
    resp->version   = SET_PARM_VERSION;
    resp->parm      = 5;
    resp->data[0]   = SET_PARM_BOOT_FLAGS_VALID_ONE_TIME;

    *data_len = sizeof(*resp);

    /*
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */
    if (reqptr->parameter == 5) {

        /* Get the boot device */
        int r = dbus_get_property("boot_flags",&p);

        if (r < 0) {
            fprintf(stderr, "Dbus get property(boot_flags) failed for get_sys_boot_options.\n");
            rc = IPMI_CC_UNSPECIFIED_ERROR;

        } else {

            s = get_ipmi_boot_option(p);
            resp->data[1] = (s << 2);
            rc = IPMI_CC_OK;

        }

        if (p)
        {
          free(p);
          p = NULL;
        }

        /* Get the boot policy */
        r = dbus_get_property("boot_policy",&p);

        if (r < 0) {
            fprintf(stderr, "Dbus get property(boot_policy) failed for get_sys_boot_options.\n");
            rc = IPMI_CC_UNSPECIFIED_ERROR;

        } else {

            printf("BootPolicy is[%s]", p); 
            resp->data[0] = (strncmp(p,"ONETIME",strlen("ONETIME"))==0) ? 
                            SET_PARM_BOOT_FLAGS_VALID_ONE_TIME:
                            SET_PARM_BOOT_FLAGS_VALID_PERMANENT;
            rc = IPMI_CC_OK;

        }


    } else if ( reqptr->parameter == 0x61 ) {
       resp->parm      = 0x61;
       int ret = getHostNetworkData(resp);
       if (ret < 0) {
           fprintf(stderr, "getHostNetworkData failed for get_sys_boot_options.\n");
           rc = IPMI_CC_UNSPECIFIED_ERROR;

       }else
          rc = IPMI_CC_OK;
    }

    else {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
    }

    if (p)
        free(p);

    return rc;
}



ipmi_ret_t ipmi_chassis_set_sys_boot_options(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    char *s;
    set_sys_boot_options_t *reqptr = (set_sys_boot_options_t *) request;

    printf("IPMI SET_SYS_BOOT_OPTIONS reqptr->parameter =[%d]\n",reqptr->parameter);

    // This IPMI command does not have any resposne data
    *data_len = 0;

    /*  000101
     * Parameter #5 means boot flags. Please refer to 28.13 of ipmi doc.
     * This is the only parameter used by petitboot.
     */

    if (reqptr->parameter == 5) {

        s = get_boot_option_by_ipmi(((reqptr->data[1] & 0x3C) >> 2));

        printf("%d: %s\n", __LINE__, s);
        if (!strcmp(s,INVALID_STRING)) {

            rc = IPMI_CC_PARM_NOT_SUPPORTED;

        } else {

            int r = dbus_set_property("boot_flags",s);

            if (r < 0) {
                fprintf(stderr, "Dbus set property(boot_flags) failed for set_sys_boot_options.\n");
                rc = IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
      
        /* setting the boot policy */
        s = (char *)(((reqptr->data[0] & SET_PARM_BOOT_FLAGS_PERMANENT) == 
                       SET_PARM_BOOT_FLAGS_PERMANENT) ?"PERMANENT":"ONETIME");

        printf ( "\nBoot Policy is %s",s); 
        int r = dbus_set_property("boot_policy",s);

        if (r < 0) {
            fprintf(stderr, "Dbus set property(boot_policy) failed for set_sys_boot_options.\n");
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }

    }
    else if ( reqptr->parameter == 0x61 ) {
       printf("IPMI SET_SYS_BOOT_OPTIONS reqptr->parameter =[%d]\n",reqptr->parameter);
       int ret = setHostNetworkData(reqptr);
       if (ret < 0) {
           fprintf(stderr, "setHostNetworkData failed for set_sys_boot_options.\n");
           rc = IPMI_CC_UNSPECIFIED_ERROR;
       }
    }      
    else {
        fprintf(stderr, "Unsupported parameter 0x%x\n", reqptr->parameter);
        rc = IPMI_CC_PARM_NOT_SUPPORTED;
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

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_CHASSIS, IPMI_CMD_SET_SYS_BOOT_OPTIONS);
    ipmi_register_callback(NETFUN_CHASSIS, IPMI_CMD_SET_SYS_BOOT_OPTIONS, NULL, ipmi_chassis_set_sys_boot_options);
}

