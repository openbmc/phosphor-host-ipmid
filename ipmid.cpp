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
#include "ipmid.hpp"
#include <sys/time.h>
#include <errno.h>
#include <mapper.h>
#include "sensorhandler.h"
#include <vector>
#include <algorithm>
#include <iterator>
#include <ipmiwhitelist.hpp>

sd_bus *bus = NULL;
sd_bus_slot *ipmid_slot = NULL;

// Initialise restricted mode to true
bool restricted_mode = true;

FILE *ipmiio, *ipmidbus, *ipmicmddetails;

void print_usage(void) {
  fprintf(stderr, "Options:  [-d mask]\n");
  fprintf(stderr, "    mask : 0x01 - Print ipmi packets\n");
  fprintf(stderr, "    mask : 0x02 - Print DBUS operations\n");
  fprintf(stderr, "    mask : 0x04 - Print ipmi command details\n");
  fprintf(stderr, "    mask : 0xFF - Print all trace\n");
}

// Host settings in DBUS
constexpr char settings_host_object[] = "/org/openbmc/settings/host0";
constexpr char settings_host_intf[] = "org.freedesktop.DBus.Properties";

const char * DBUS_INTF = "org.openbmc.HostIpmi";

const char * FILTER = "type='signal',interface='org.openbmc.HostIpmi',member='ReceivedMessage'";
constexpr char RESTRICTED_MODE_FILTER[] = "type='signal',interface='org.freedesktop.DBus.Properties',path='/org/openbmc/settings/host0'";

typedef std::pair<ipmi_netfn_t, ipmi_cmd_t> ipmi_fn_cmd_t;
typedef std::pair<ipmid_callback_t, ipmi_context_t> ipmi_fn_context_t;

// Global data structure that contains the IPMI command handler's registrations.
std::map<ipmi_fn_cmd_t, ipmi_fn_context_t> g_ipmid_router_map;

// IPMI Spec, shared Reservation ID.
unsigned short g_sel_reserve = 0xFFFF;

unsigned short get_sel_reserve_id(void)
{
    return g_sel_reserve;
}

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

    // If restricted mode is true and command is not whitelisted, don't
    // execute the command
    if(restricted_mode)
    {
        if (!std::binary_search(whitelist.cbegin(), whitelist.cend(),
                                        std::make_pair(netfn, cmd)))
        {
            printf("Net function:[0x%X], Command:[0x%X] is not whitelisted\n",
                                         netfn, cmd);
            rc = IPMI_CC_INSUFFICIENT_PRIVILEGE;
            memcpy(response, &rc, IPMI_CC_LEN);
            *data_len = IPMI_CC_LEN;
            return rc;
        }
    }

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
        fprintf(stderr, "Dest: %s, Path: %s\n", dest, path);
        goto final;
    }

    r = sd_bus_message_read(reply, "x", &pty);
    if (r < 0) {
       fprintf(stderr, "Failed to get a rc from the method: %s\n", strerror(-r));
    }

final:
    sd_bus_error_free(&error);
    m = sd_bus_message_unref(m);
    reply = sd_bus_message_unref(reply);

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

void cache_restricted_mode()
{
    sd_bus *bus = ipmid_get_sd_bus_connection();
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int rc = 0;
    char  *busname = NULL;

    rc = mapper_get_service(bus, settings_host_object, &busname);
    if (rc < 0) {
        fprintf(stderr, "Failed to get HOST busname: %s\n", strerror(-rc));
        goto cleanup;
    }
    rc = sd_bus_call_method(bus,
                            busname,
                            settings_host_object,
                            settings_host_intf,
                            "Get",
                            &error,
                            &reply,
                            "ss",
                            "org.openbmc.settings.Host",
                            "restricted_mode");
    if(rc < 0)
    {
        fprintf(stderr, "Failed sd_bus_call_method method for restricted mode: %s\n",
                        strerror(-rc));
        goto cleanup;
    }

    rc = sd_bus_message_read(reply, "v", "b", &restricted_mode);
    if(rc < 0)
    {
        fprintf(stderr, "Failed to parse response message for restricted mode: %s\n",
                       strerror(-rc));
        // Fail-safe to restricted mode
        restricted_mode = true;
    }

    printf("Restricted mode = %d\n", restricted_mode);

cleanup:
    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);
}

static int handle_restricted_mode_change(sd_bus_message *m, void *user_data,
                                                    sd_bus_error *ret_error)
{
    cache_restricted_mode();
    return 0;
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

        if(r < 0) {
           response[0] = IPMI_CC_UNSPECIFIED_ERROR;
        }
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
    // .so.* or .so in them.
    // Check for versioned libraries .so.*
    if(strstr(entry->d_name, IPMI_PLUGIN_SONAME_EXTN))
    {
        return 1;
    }
    // Check for non versioned libraries .so
    else if(strstr(entry->d_name, IPMI_PLUGIN_EXTN))
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

sd_bus_slot *ipmid_get_sd_bus_slot(void) {
    return ipmid_slot;
}

int main(int argc, char *argv[])
{
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

	// Watch for BT messages
    r = sd_bus_add_match(bus, &ipmid_slot, FILTER, handle_ipmi_command, NULL);
    if (r < 0) {
        fprintf(stderr, "Failed: sd_bus_add_match: %s : %s\n", strerror(-r), FILTER);
        goto finish;
    }

    // Wait for changes on Restricted mode
    r = sd_bus_add_match(bus, &ipmid_slot, RESTRICTED_MODE_FILTER, handle_restricted_mode_change, NULL);
    if (r < 0) {
        fprintf(stderr, "Failed: sd_bus_add_match: %s : %s\n", strerror(-r), RESTRICTED_MODE_FILTER);
        goto finish;
    }

    // Initialise restricted mode
    cache_restricted_mode();

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
    sd_bus_slot_unref(ipmid_slot);
    sd_bus_unref(bus);
    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}
