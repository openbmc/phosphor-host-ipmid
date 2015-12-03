#include <stdio.h>
#include <dlfcn.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <systemd/sd-bus.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include "ipmid.H"
#include <sys/time.h>
#include <errno.h>
#include "sensorhandler.h"


sd_bus *bus = NULL;

FILE *ipmiio, *ipmidbus, *ipmicmddetails;

void print_usage(void) {
  fprintf(stderr, "Options:  [-d mask]\n");
  fprintf(stderr, "    mask : 0x01 - Print ipmi packets\n");
  fprintf(stderr, "    mask : 0x02 - Print DBUS operations\n");
  fprintf(stderr, "    mask : 0x04 - Print ipmi command details\n");
  fprintf(stderr, "    mask : 0xFF - Print all trace\n");
}



const char * DBUS_INTF = "org.openbmc.HostIpmi";

const char * FILTER = "type='signal',interface='org.openbmc.HostIpmi',member='ReceivedMessage'";


typedef std::pair<ipmi_netfn_t, ipmi_cmd_t> ipmi_fn_cmd_t;
typedef std::pair<ipmid_callback_t, ipmi_context_t> ipmi_fn_context_t;

// Global data structure that contains the IPMI command handler's registrations.
std::map<ipmi_fn_cmd_t, ipmi_fn_context_t> g_ipmid_router_map;


#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

void hexdump(FILE *s, void *mem, size_t len)
{
        unsigned int i, j;

        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        fprintf(s,"0x%06x: ", i);
                }

                /* print hex data */
                if(i < len)
                {
                        fprintf(s,"%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        fprintf(s,"   ");
                }

                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        fputc(' ', s);
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        fputc(0xFF & ((char*)mem)[j], s);
                                }
                                else /* other char */
                                {
                                        fputc('.',s);
                                }
                        }
                        fputc('\n',s);
                }
        }
}


// Method that gets called by shared libraries to get their command handlers registered
void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                       ipmi_context_t context, ipmid_callback_t handler)
{
    // Pack NetFn and Command in one.
    auto netfn_and_cmd = std::make_pair(netfn, cmd);

    // Pack Function handler and Data in another.
    auto handler_and_context = std::make_pair(handler, context);

    // Check if the registration has already been made..
    auto iter = g_ipmid_router_map.find(netfn_and_cmd);
    if(iter != g_ipmid_router_map.end())
    {
        fprintf(stderr,"ERROR : Duplicate registration for NetFn [0x%X], Cmd:[0x%X]\n",netfn, cmd);
    }
    else
    {
        // This is a fresh registration.. Add it to the map.
        g_ipmid_router_map.emplace(netfn_and_cmd, handler_and_context);
    }

    return;
}

// Looks at the map and calls corresponding handler functions.
ipmi_ret_t ipmi_netfn_router(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
                      ipmi_response_t response, ipmi_data_len_t data_len)
{
    // return from the Command handlers.
    ipmi_ret_t rc = IPMI_CC_INVALID;

    // Walk the map that has the registered handlers and invoke the approprite
    // handlers for matching commands.
    auto iter = g_ipmid_router_map.find(std::make_pair(netfn, cmd));
    if(iter == g_ipmid_router_map.end())
    {
        fprintf(stderr, "No registered handlers for NetFn:[0x%X], Cmd:[0x%X]"
               " trying Wilcard implementation \n",netfn, cmd);

        // Now that we did not find any specific [NetFn,Cmd], tuple, check for
        // NetFn, WildCard command present.
        iter = g_ipmid_router_map.find(std::make_pair(netfn, IPMI_CMD_WILDCARD));
        if(iter == g_ipmid_router_map.end())
        {
            fprintf(stderr, "No Registered handlers for NetFn:[0x%X],Cmd:[0x%X]\n",netfn, IPMI_CMD_WILDCARD);

            // Respond with a 0xC1
            memcpy(response, &rc, IPMI_CC_LEN);
            *data_len = IPMI_CC_LEN;
            return rc;
        }
    }

#ifdef __IPMI_DEBUG__
    // We have either a perfect match -OR- a wild card atleast,
    printf("Calling Net function:[0x%X], Command:[0x%X]\n", netfn, cmd);
#endif

    // Extract the map data onto appropriate containers
    auto handler_and_context = iter->second;

    // Creating a pointer type casted to char* to make sure we advance 1 byte
    // when we advance pointer to next's address. advancing void * would not
    // make sense.
    char *respo = &((char *)response)[IPMI_CC_LEN];

    // Response message from the plugin goes into a byte post the base response
    rc = (handler_and_context.first) (netfn, cmd, request, respo,
                                      data_len, handler_and_context.second);

    // Now copy the return code that we got from handler and pack it in first
    // byte.
    memcpy(response, &rc, IPMI_CC_LEN);

    // Data length is now actual data + completion code.
    *data_len = *data_len + IPMI_CC_LEN;

    return rc;
}




static int send_ipmi_message(sd_bus_message *req, unsigned char seq, unsigned char netfn, unsigned char lun, unsigned char cmd, unsigned char cc, unsigned char *buf, unsigned char len) {

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;
    const char *dest, *path;
    int r, pty;

    dest = sd_bus_message_get_sender(req);
    path = sd_bus_message_get_path(req);

    r = sd_bus_message_new_method_call(bus,&m,dest,path,DBUS_INTF,"sendMessage");
    if (r < 0) {
        fprintf(stderr, "Failed to add the method object: %s\n", strerror(-r));
        return -1;
    }


    // Responses in IPMI require a bit set.  So there ya go...
    netfn |= 0x01;


    // Add the bytes needed for the methods to be called
    r = sd_bus_message_append(m, "yyyyy", seq, netfn, lun, cmd, cc);
    if (r < 0) {
        fprintf(stderr, "Failed add the netfn and others : %s\n", strerror(-r));
        goto final;
    }

    r = sd_bus_message_append_array(m, 'y', buf, len);
    if (r < 0) {
        fprintf(stderr, "Failed to add the string of response bytes: %s\n", strerror(-r));
        goto final;
    }



    // Call the IPMI responder on the bus so the message can be sent to the CEC
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s\n", strerror(-r));
        goto final;
    }

    r = sd_bus_message_read(reply, "x", &pty);
    if (r < 0) {
       fprintf(stderr, "Failed to get a rc from the method: %s\n", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_message_unref(reply);


    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int handle_ipmi_command(sd_bus_message *m, void *user_data, sd_bus_error
                         *ret_error) {
    int r = 0;
    unsigned char sequence, netfn, lun, cmd;
    const void *request;
    size_t sz;
    size_t resplen =MAX_IPMI_BUFFER;
    unsigned char response[MAX_IPMI_BUFFER];

    memset(response, 0, MAX_IPMI_BUFFER);

    r = sd_bus_message_read(m, "yyyy",  &sequence, &netfn, &lun, &cmd);
    if (r < 0) {
        fprintf(stderr, "Failed to parse signal message: %s\n", strerror(-r));
        return -1;
    }

    r = sd_bus_message_read_array(m, 'y',  &request, &sz );
    if (r < 0) {
        fprintf(stderr, "Failed to parse signal message: %s\n", strerror(-r));
        return -1;
    }

    fprintf(ipmiio, "IPMI Incoming: Seq 0x%02x, NetFn 0x%02x, CMD: 0x%02x \n", sequence, netfn, cmd);
    hexdump(ipmiio, (void*)request, sz);

    // Allow the length field to be used for both input and output of the
    // ipmi call
    resplen = sz;

    // Now that we have parsed the entire byte array from the caller
    // we can call the ipmi router to do the work...
    r = ipmi_netfn_router(netfn, cmd, (void *)request, (void *)response, &resplen);
    if(r != 0)
    {
        fprintf(stderr,"ERROR:[0x%X] handling NetFn:[0x%X], Cmd:[0x%X]\n",r, netfn, cmd);
    }

    fprintf(ipmiio, "IPMI Response:\n");
    hexdump(ipmiio,  (void*)response, resplen);

    // Send the response buffer from the ipmi command
    r = send_ipmi_message(m, sequence, netfn, lun, cmd, response[0],
		    ((unsigned char *)response) + 1, resplen - 1);
    if (r < 0) {
        fprintf(stderr, "Failed to send the response message\n");
        return -1;
    }


    return 0;
}


//----------------------------------------------------------------------
// handler_select
// Select all the files ending with with .so. in the given diretcory
// @d: dirent structure containing the file name
//----------------------------------------------------------------------
int handler_select(const struct dirent *entry)
{
    // To hold ".so" from entry->d_name;
    char dname_copy[4] = {0};

    // We want to avoid checking for everything and isolate to the ones having
    // .so in them.
    if(strstr(entry->d_name, IPMI_PLUGIN_EXTN))
    {
        // It is possible that .so could be anywhere in the string but unlikely
        // But being careful here. Get the base address of the string, move
        // until end and come back 3 steps and that gets what we need.
        strcpy(dname_copy, (entry->d_name + strlen(entry->d_name)-strlen(IPMI_PLUGIN_EXTN)));
        if(strcmp(dname_copy, IPMI_PLUGIN_EXTN) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// This will do a dlopen of every .so in ipmi_lib_path and will dlopen everything so that they will
// register a callback handler
void ipmi_register_callback_handlers(const char* ipmi_lib_path)
{
    // For walking the ipmi_lib_path
    struct dirent **handler_list;
    int num_handlers = 0;

    // This is used to check and abort if someone tries to register a bad one.
    void *lib_handler = NULL;

    if(ipmi_lib_path == NULL)
    {
        fprintf(stderr,"ERROR; No handlers to be registered for ipmi.. Aborting\n");
        assert(0);
    }
    else
    {
        // 1: Open ipmi_lib_path. Its usually "/usr/lib/phosphor-host-ipmid"
        // 2: Scan the directory for the files that end with .so
        // 3: For each one of them, just do a 'dlopen' so that they register
        //    the handlers for callback routines.

        std::string handler_fqdn = ipmi_lib_path;

        // Append a "/" since we need to add the name of the .so. If there is
        // already a .so, adding one more is not any harm.
        handler_fqdn += "/";

        num_handlers = scandir(ipmi_lib_path, &handler_list, handler_select, alphasort);
	if (num_handlers < 0)
		return;

        while(num_handlers--)
        {
            handler_fqdn = ipmi_lib_path;
            handler_fqdn += handler_list[num_handlers]->d_name;
            printf("Registering handler:[%s]\n",handler_fqdn.c_str());

            lib_handler = dlopen(handler_fqdn.c_str(), RTLD_NOW);
            if(lib_handler == NULL)
            {
                fprintf(stderr,"ERROR opening [%s]: %s\n",
                        handler_fqdn.c_str(), dlerror());
            }
            // Wipe the memory allocated for this particular entry.
            free(handler_list[num_handlers]);
        }
        // Done with all registration.
        free(handler_list);
    }

    // TODO : What to be done on the memory that is given by dlopen ?.
    return;
}

sd_bus *ipmid_get_sd_bus_connection(void) {
    return bus;
}

int main(int argc, char *argv[])
{
    sd_bus_slot *slot = NULL;
    int r;
    unsigned long tvalue;
    int c;



    // This file and subsequient switch is for turning on levels
    // of trace
    ipmicmddetails = ipmiio = ipmidbus =  fopen("/dev/null", "w");

    while ((c = getopt (argc, argv, "h:d:")) != -1)
        switch (c) {
            case 'd':
                tvalue =  strtoul(optarg, NULL, 16);
                if (1&tvalue) {
                    ipmiio = stdout;
                }
                if (2&tvalue) {
                    ipmidbus = stdout;
                }
                if (4&tvalue) {
                    ipmicmddetails = stdout;
                }
                break;
          case 'h':
          case '?':
                print_usage();
                return 1;
        }


    /* Connect to system bus */
    r = sd_bus_open_system(&bus);
    if (r < 0) {
        fprintf(stderr, "Failed to connect to system bus: %s\n",
                strerror(-r));
        goto finish;
    }

    // Register all the handlers that provider implementation to IPMI commands.
    ipmi_register_callback_handlers(HOST_IPMI_LIB_PATH);

	// Start the Host Services Dbus Objects
	start_host_service(bus, slot);

	// Watch for BT messages
    r = sd_bus_add_match(bus, &slot, FILTER, handle_ipmi_command, NULL);
    if (r < 0) {
        fprintf(stderr, "Failed: sd_bus_add_match: %s : %s\n", strerror(-r), FILTER);
        goto finish;
    }


    for (;;) {
        /* Process requests */
        r = sd_bus_process(bus, NULL);
        if (r < 0) {
            fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
            goto finish;
        }
        if (r > 0) {
            continue;
        }

        r = sd_bus_wait(bus, (uint64_t) - 1);
        if (r < 0) {
            fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
            goto finish;
        }
    }

finish:
    sd_bus_slot_unref(slot);
    sd_bus_unref(bus);
    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}

// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_interface_property_fru_type(dbus_interface_t *interface, const char *property_name, char *property_value) {

    char  *str1;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;


    int r;

    r = sd_bus_message_new_method_call(bus,&m,interface->bus,interface->path,"org.freedesktop.DBus.Properties","Get");
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
        fprintf(stderr,"Bus: %s Path: %s Interface: %s \n",
                interface->bus, interface->path, interface->interface);
    }

    r = sd_bus_message_append(m, "ss", "org.openbmc.InventoryItem", property_name);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
        fprintf(stderr,"Bus: %s Path: %s Interface: %s \n",
                interface->bus, interface->path, interface->interface);
    }

    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
        goto final;
    }

    r = sd_bus_message_read(reply, "v",  "s", &str1) ;
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        goto final;
    }

    strcpy(property_value, str1);

final:

    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return r;
}


// Use a lookup table to find the interface name of a specific sensor
// This will be used until an alternative is found.  this is the first
// step for mapping IPMI
int find_openbmc_path(const char *type, const uint8_t num, dbus_interface_t *interface) {

    const char  *busname = "org.openbmc.managers.System";
    const char  *objname = "/org/openbmc/managers/System";

    char  *str1, *str2, *str3;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;


    int r;

    r = sd_bus_message_new_method_call(bus,&m,busname,objname,busname,"getObjectFromByteId");
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
    }

    r = sd_bus_message_append(m, "sy", type, num);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
    }

    // Call the IPMI responder on the bus so the message can be sent to the CEC
    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
        goto final;
    }


    r = sd_bus_message_read(reply, "(sss)", &str1, &str2, &str3);
    if (r < 0) {
        fprintf(stderr, "Failed to get a response: %s", strerror(-r));
        goto final;
    }

    strncpy(interface->bus, str1, MAX_DBUS_PATH);
    strncpy(interface->path, str2, MAX_DBUS_PATH);
    strncpy(interface->interface, str3, MAX_DBUS_PATH);

    interface->sensornumber = num;

final:

    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return r;
}


/////////////////////////////////////////////////////////////////////
//
// Routines used by ipmi commands wanting to interact on the dbus
//
/////////////////////////////////////////////////////////////////////


// Simple set routine because some methods are standard.
int set_sensor_dbus_state(uint8_t number, const char *method, const char *value) {


    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL, *m=NULL;

    fprintf(ipmidbus, "Attempting to set a dbus Sensor 0x%02x via %s with a value of %s\n",
        number, method, value);

    r = find_openbmc_path("SENSOR", number, &a);

    r = sd_bus_message_new_method_call(bus,&m,a.bus,a.path,a.interface,method);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
    }

    r = sd_bus_message_append(m, "s", value);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
    }

    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0) {
        fprintf(stderr, "Failed to call the method: %s", strerror(-r));
    }

    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return 0;
}

int set_sensor_dbus_state_v(uint8_t number, const char *method, char *value) {


    dbus_interface_t a;
    int r;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m=NULL;

    fprintf(ipmidbus, "Attempting to set a dbus Variant Sensor 0x%02x via %s with a value of %s\n",
        number, method, value);

    r = find_openbmc_path("SENSOR", number, &a);

    r = sd_bus_message_new_method_call(bus,&m,a.bus,a.path,a.interface,method);
    if (r < 0) {
        fprintf(stderr, "Failed to create a method call: %s", strerror(-r));
    }

    r = sd_bus_message_append(m, "v", "s", value);
    if (r < 0) {
        fprintf(stderr, "Failed to create a input parameter: %s", strerror(-r));
    }


    r = sd_bus_call(bus, m, 0, &error, NULL);
    if (r < 0) {
        fprintf(stderr, "12 Failed to call the method: %s", strerror(-r));
    }


    sd_bus_error_free(&error);
    sd_bus_message_unref(m);

    return 0;
}
