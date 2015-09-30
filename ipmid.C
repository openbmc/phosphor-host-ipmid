#include <stdio.h>
#include <dlfcn.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include "ipmid.H"

// Channel that is used for OpenBMC Barreleye
const char * DBUS_NAME = "org.openbmc.HostIpmi";
const char * OBJ_NAME = "/org/openbmc/HostIpmi/1";

typedef std::pair<ipmi_netfn_t, ipmi_cmd_t> ipmi_fn_cmd_t;
typedef std::pair<ipmid_callback_t, ipmi_context_t> ipmi_fn_context_t;

// Global data structure that contains the IPMI command handler's registrations.
std::map<ipmi_fn_cmd_t, ipmi_fn_context_t> g_ipmid_router_map;

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
        printf("No registered handlers for NetFn:[0x%X], Cmd:[0x%X]"
               " trying Wilcard implementation \n",netfn, cmd);

        // Now that we did not find any specific [NetFn,Cmd], tuple, check for
        // NetFn, WildCard command present.
        iter = g_ipmid_router_map.find(std::make_pair(netfn, IPMI_CMD_WILDCARD));
        if(iter == g_ipmid_router_map.end())
        {
            printf("No Registered handlers for NetFn:[0x%X],Cmd:[0x%X]\n",netfn, IPMI_CMD_WILDCARD);

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

// This gets called by Glib loop on seeing a Dbus signal 
static void handle_ipmi_command(GDBusProxy *proxy,
                        gchar      *sender_name,
                        gchar      *signal_name,
                        GVariant   *parameters,
                        gpointer    user_data)
{
    // Used to re-construct the message into IPMI specific ones.
    guchar *parameters_str;
    unsigned char sequence, netfn, cmd;

    // Request and Response buffer.
    unsigned char request[MAX_IPMI_BUFFER] = {0};
    unsigned char response[MAX_IPMI_BUFFER] = {0};

    size_t msg_length = 0;
    size_t data_len = 0;

    // Response from Net Function Router
    ipmi_ret_t rc = 0;

    // Variables to marshall and unmarshall the messages.
    GVariantIter *iter;
    guchar data;
    GVariant *dbus_response;
    GVariantBuilder *builder;

    // Pretty print the message that came on Dbus
    parameters_str = (guchar *) g_variant_print (parameters, TRUE);
    printf ("*** Received Signal: %s: %s :%s\n",
            signal_name,
            sender_name,
            parameters_str);

    // Consume the data pattern "<bYte><bYte><bYte><Array_of_bYtes>
    g_variant_get(parameters, "(yyyay)", &sequence, &netfn, &cmd, &iter);

    printf("Sequence: %x\n",sequence );
    printf("Netfn   : %x\n",netfn );
    printf("Cmd     : %x\n",cmd );

    // Further break down the GVariant byte array
    while (g_variant_iter_loop (iter, "y", &data))
    {
        request[msg_length++] = data;
    }

    // Done with consuming data.
    g_free (parameters_str);

    // Needed to see what we get back from the handlers.
    data_len = msg_length;

    // Now that we have parsed the entire byte array from the caller 
    // we can call the ipmi router to do the work...
    rc = ipmi_netfn_router(netfn, cmd, (void *)request, (void *)response, &data_len);
    if(rc == 0)
    {
        printf("SUCCESS handling NetFn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    }
    else
    {
        fprintf(stderr,"ERROR:[0x%X] handling NetFn:[0x%X], Cmd:[0x%X]\n",rc, netfn, cmd);
    }

    // Now build a response Gvariant package
    // This example may help
    // http://stackoverflow.com/questions/22937588/how-to-send-byte-array-over-gdbus

    printf("Bytes to return\n");
   // hexdump(response,data_len);

    // Now we need to put the data as "Array Of Bytes" as we got them.
    builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));

    for (uint out_data = 0; out_data < data_len; out_data++)
    {
        g_variant_builder_add (builder, "y", response[out_data]);
    }

    dbus_response = g_variant_new ("(yyyay)", sequence, netfn+1, cmd, builder);

    // Variant builder is no longer needed.
    g_variant_builder_unref (builder);

    parameters_str = (guchar *) g_variant_print (dbus_response, TRUE);
    printf (" *** Response Signal :%s\n", parameters_str);

    // Done packing the data.
    g_free (parameters_str);

    // NOW send the respone message in the Dbus calling "sendMessage" interface.
    g_dbus_proxy_call_sync (proxy,
            "sendMessage",
            dbus_response,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            NULL);
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
        while(num_handlers--)
        {
            printf("Registering handler:[%s]\n",handler_list[num_handlers]->d_name);

            handler_fqdn += handler_list[num_handlers]->d_name;
            lib_handler = dlopen(handler_fqdn.c_str(), RTLD_NOW);
            if(lib_handler == NULL)
            {
                fprintf(stderr,"ERROR opening:[%s]\n",handler_list[num_handlers]->d_name);
                dlerror();
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

int main(int argc, char *argv[])
{
    // Register all the handlers that provider implementation to IPMI commands.
    ipmi_register_callback_handlers(HOST_IPMI_LIB_PATH);

#ifdef __IPMI_DEBUG__
    printf("Registered Function handlers:\n");

    // Print the registered handlers and their arguments.
    for(auto& iter : g_ipmid_router_map)
    {
        ipmi_fn_cmd_t fn_and_cmd = iter.first;
        printf("NETFN:[0x%X], cmd[0x%X]\n", fn_and_cmd.first, fn_and_cmd.second);  
    }
#endif
       
    // Infrastructure that will wait for IPMi Dbus messages and will call 
    // into the corresponding IPMI providers.
    GDBusProxy *proxy;
    GMainLoop *loop;

    loop = g_main_loop_new (NULL, FALSE);

    // Proxy to use GDbus for OpenBMC channel.
    proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SESSION,
                                           G_DBUS_PROXY_FLAGS_NONE,
                                           NULL, /* GDBusInterfaceInfo */
                                           DBUS_NAME,
                                           OBJ_NAME,
                                           DBUS_NAME,
                                           NULL,
                                           NULL);

    // On receiving the Dbus Signal, handle_ipmi_command gets invoked.
    g_signal_connect (proxy,
                    "g-signal",
                    G_CALLBACK (handle_ipmi_command),
                    NULL);

    // This will not return unless we return false from the upmi_handler function.
    g_main_loop_run (loop);

    return 0;
}
