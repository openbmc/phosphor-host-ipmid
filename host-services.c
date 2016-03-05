#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <systemd/sd-bus.h>

#include "ipmid-api.h"

void register_host_services() __attribute__((constructor));

// OpenBMC Host IPMI dbus framework
const char  *bus_name      =  "org.openbmc.HostIpmi";
const char  *object_name   =  "/org/openbmc/HostIpmi/1";
const char  *intf_name     =  "org.openbmc.HostIpmi";

//-------------------------------------------------------------------
// Gets called by PowerOff handler when a Soft Power off is requested
//-------------------------------------------------------------------
static int soft_power_off(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    int64_t bt_resp = -1;
    int rc = 0;

    // Steps to be taken when we get this.
    //  1: Send a SMS_ATN to the Host
    //  2: Host receives it and sends a GetMsgFlags IPMI command
    //  3: IPMID app handler will respond to that with a MSgFlag with bit:0x2
    //     set indicating we have a message for Host
    //  4: Host sends a GetMsgBuffer command and app handler will respond to
    //     that with a OEM-SEL with certain fields packed indicating to the
    //     host that it do a shutdown of the partitions.
    //  5: Host does the partition shutdown and calls Chassis Power off command
    //  6: App handler handles the command by making a call to ChassisManager
    //     Dbus

    // Now the job is to send the SMS_ATTN.

    // Req message contains the specifics about which method etc that we want to
    // access on which bus, object
    sd_bus_message *response = NULL;

    // Error return mechanism
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    // Gets a hook onto either a SYSTEM or SESSION bus
    sd_bus *bus = ipmid_get_sd_bus_connection();

    rc = sd_bus_call_method(bus,             // In the System Bus
                            bus_name,        // Service to contact
                            object_name,     // Object path
                            intf_name,       // Interface name
                            "setAttention",  // Method to be called
                            &bus_error,      // object to return error
                            &response,       // Response buffer if any
                            NULL);           // No input arguments
    if(rc < 0)
    {
        fprintf(stderr,"ERROR initiating Power Off:[%s]\n",bus_error.message);
        goto finish;
    }

    // See if we were able to successfully raise SMS_ATN
    rc = sd_bus_message_read(response, "x", &bt_resp);
    if (rc < 0)
    {
        fprintf(stderr, "Failed to get a rc from BT for SMS_ATN: %s\n", strerror(-rc));
        goto finish;
    }

finish:
    sd_bus_error_free(&bus_error);
    response = sd_bus_message_unref(response);

    if(rc < 0)
    {
        return sd_bus_reply_method_return(m, "x", rc);
    }
    else
    {
        return sd_bus_reply_method_return(m, "x", bt_resp);
    }
}

//-------------------------------------------
// Function pointer of APIs exposed via Dbus
//-------------------------------------------
static const sd_bus_vtable host_services_vtable[] =
{
    SD_BUS_VTABLE_START(0),
    // Takes No("") arguments -but- returns a value of type 64 bit integer("x")
    SD_BUS_METHOD("SoftPowerOff", "", "x", &soft_power_off, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END,
};

//------------------------------------------------------
// Called by IPMID as part of the start up
// -----------------------------------------------------
int start_host_service(sd_bus *bus, sd_bus_slot *slot)
{
    int rc = 0;

    /* Install the object */
    rc = sd_bus_add_object_vtable(bus,
                                 &slot,
                                "/org/openbmc/HostServices",  /* object path */
                                "org.openbmc.HostServices",   /* interface name */
                                host_services_vtable,
                                NULL);
    if (rc < 0)
    {
        fprintf(stderr, "Failed to issue method call: %s\n", strerror(-rc));
    }
    else
    {
        /* Take one in OpenBmc */
        rc = sd_bus_request_name(bus, "org.openbmc.HostServices", 0);
        if (rc < 0)
        {
            fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-rc));
        }
    }

    return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

//------------------------------------------------------
// Callback register function
// -----------------------------------------------------
void register_host_services()
{
    // Gets a hook onto SYSTEM bus used by host-ipmid
    sd_bus *bus = ipmid_get_sd_bus_connection();

    // Gets a hook onto SYSTEM bus slot used by host-ipmid
    sd_bus_slot *ipmid_slot = ipmid_get_sd_bus_slot();

    //start_host_service(bus, ipmid_slot);
    start_host_service(bus, ipmid_slot);
}
