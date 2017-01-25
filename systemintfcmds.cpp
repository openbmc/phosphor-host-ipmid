#include "systemintfcmds.h"
#include "host-ipmid/ipmid-api.h"

#include <stdio.h>
#include <mapper.h>

void register_netfn_app_functions() __attribute__((constructor));

//-------------------------------------------------------------------
// Called by Host post response from Get_Message_Flags
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_read_event(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    printf("IPMI APP READ EVENT command received\n");

    // TODO : For now, this is catering only to the Soft Power Off via OEM SEL
    //        mechanism. If we need to make this generically used for some
    //        other conditions, then we can take advantage of context pointer.

    constexpr auto objname        = "/xyz/openbmc_project/ipmi/softpoweroff";
    constexpr auto iface          = "org.freedesktop.DBus.Properties";
    constexpr auto soft_off_iface = "xyz.openbmc_project.Ipmi.Internal.\
                                      SoftPowerOff";

    constexpr auto property       = "ResponseReceived";
    constexpr auto value          = "xyz.openbmc_project.Ipmi.Internal.\
                                     SoftPowerOff.HostResponse.SoftOffReceived";
    char *busname = nullptr;

    struct oem_sel_timestamped soft_off = {0};
    *data_len = sizeof(struct oem_sel_timestamped);

    // Get the system bus where most system services are provided.
    auto bus = ipmid_get_sd_bus_connection();

    // Nudge the SoftPowerOff application that it needs to stop the
    // initial watchdog timer.
    auto r = mapper_get_service(bus, objname, &busname);
    if (r < 0) {
        fprintf(stderr, "Failed to get %s bus name: %s\n",
                objname, strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    // No error object or reply expected.
    // TODO : Do this only if the SoftPowerOff object is alive
    r = sd_bus_call_method(bus, busname, objname, iface,
                           "Set", nullptr, nullptr, "sss",
                            soft_off_iface, property, value);
    if (r < 0)
    {
        fprintf(stderr, "Failed to set property in SoftPowerOff object: %s\n",
                strerror(-r));
        rc = IPMI_CC_UNSPECIFIED_ERROR;
        goto finish;
    }

    // either id[0] -or- id[1] can be filled in. We will use id[0]
    soft_off.id[0]   = SEL_OEM_ID_0;
    soft_off.id[1]   = SEL_OEM_ID_0;
    soft_off.type    = SEL_RECORD_TYPE_OEM;

    // Following 3 bytes are from IANA Manufactre_Id field. See below
    soft_off.manuf_id[0]= 0x41;
    soft_off.manuf_id[1]= 0xA7;
    soft_off.manuf_id[2]= 0x00;

    // per IPMI spec NetFuntion for OEM
    soft_off.netfun  = 0x3A;

    // Mechanism to kick start soft shutdown.
    soft_off.cmd     = CMD_POWER;
    soft_off.data[0] = SOFT_OFF;

    // All '0xFF' since unused.
    memset(&soft_off.data[1], 0xFF, 3);

    // Pack the actual response
    memcpy(response, &soft_off, *data_len);
finish:
    free (busname);
    return rc;
}

//---------------------------------------------------------------------
// Called by Host on seeing a SMS_ATN bit set. Return a hardcoded
// value of 0x2 indicating we need Host read some data.
//-------------------------------------------------------------------
ipmi_ret_t ipmi_app_get_msg_flags(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    // Generic return from IPMI commands.
    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI APP GET MSG FLAGS returning with [bit:2] set\n");

    // From IPMI spec V2.0 for Get Message Flags Command :
    // bit:[1] from LSB : 1b = Event Message Buffer Full.
    // Return as 0 if Event Message Buffer is not supported,
    // or when the Event Message buffer is disabled.
    // TODO. For now. assume its not disabled and send "0x2" anyway:

    uint8_t set_event_msg_buffer_full = 0x2;
    *data_len = sizeof(set_event_msg_buffer_full);

    // Pack the actual response
    memcpy(response, &set_event_msg_buffer_full, *data_len);

    return rc;
}

ipmi_ret_t ipmi_app_set_bmc_global_enables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;

    // Event and message logging enabled by default so return for now
    printf("IPMI APP SET BMC GLOBAL ENABLES Ignoring for now\n");

    return rc;
}

void register_netfn_app_functions()
{

    // <Read Event Message Buffer>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_READ_EVENT);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_READ_EVENT, NULL, ipmi_app_read_event,
                           SYSTEM_INTERFACE);

    // <Set BMC Global Enables>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP,
                                            IPMI_CMD_SET_BMC_GLOBAL_ENABLES);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_SET_BMC_GLOBAL_ENABLES, NULL,
                           ipmi_app_set_bmc_global_enables, SYSTEM_INTERFACE);

    // <Get Message Flags>
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GET_MSG_FLAGS, NULL, ipmi_app_get_msg_flags,
                           SYSTEM_INTERFACE);

    return;
}
