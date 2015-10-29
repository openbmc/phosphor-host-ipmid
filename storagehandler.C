#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "storagehandler.h"
#include "storageaddsel.h"
#include "ipmid-api.h"
#include <systemd/sd-bus.h>
#include <vector>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <frup.h>

void register_netfn_storage_functions() __attribute__((constructor));

unsigned int   g_sel_time    = 0xFFFFFFFF;
unsigned short g_sel_reserve = 0x1;

// Needed to be passed into fru parser alorithm
typedef std::vector<fru_area_t> fru_area_vec_t;

// OpenBMC System Manager dbus framework
const char  *bus_name      =  "org.openbmc.managers.System";
const char  *object_name   =  "/org/openbmc/managers/System";
const char  *intf_name     =  "org.openbmc.managers.System";

ipmi_ret_t ipmi_storage_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    printf("Handling STORAGE WILDCARD Netfn:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

ipmi_ret_t ipmi_storage_get_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    time_t currtime;
    ipmi_ret_t rc = IPMI_CC_OK;

    // Get current time in seconds since jan 1 1970
    time(&currtime);
    uint32_t resp = (uint32_t)currtime;
    resp = htole32(resp);

    printf("IPMI Handling GET-SEL-TIME\n");

    // From the IPMI Spec 2.0, response should be a 32-bit value
    *data_len = sizeof(resp);

    // Pack the actual response
    memcpy(response, &resp, *data_len);

    return rc;
}

ipmi_ret_t ipmi_storage_set_sel_time(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    unsigned int *bufftype = (unsigned int *) request;

    printf("Handling Set-SEL-Time:[0x%X], Cmd:[0x%X]\n",netfn, cmd);
    printf("Data: 0x%X]\n",*bufftype);

    g_sel_time = *bufftype;

    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = 0;
    return rc;
}

//------------------------------------------------
// Takes the pointer to stream of bytes and length 
// returns the 8 bit checksum per IPMI spec.
//-------------------------------------------------
unsigned char calculate_crc(unsigned char *data, int len)
{
    char crc = 0;
    int byte = 0;

    for(byte = 0; byte < len; byte++)
    {
        crc += *data++;
    }
    
    return(-crc);
}

//---------------------------------------------------------------------
// Accepts a fru area offset in commom hdr and tells which area it is.
//---------------------------------------------------------------------
uint8_t get_fru_area_type(uint8_t area_offset)
{
    ipmi_fru_area_type type = IPMI_FRU_AREA_TYPE_MAX;

    switch(area_offset)
    {
        case IPMI_FRU_INTERNAL_OFFSET:
            type = IPMI_FRU_AREA_INTERNAL_USE;
            break;

        case IPMI_FRU_CHASSIS_OFFSET:
            type = IPMI_FRU_AREA_CHASSIS_INFO;
            break;

        case IPMI_FRU_BOARD_OFFSET:
            type = IPMI_FRU_AREA_BOARD_INFO;
            break;

        case IPMI_FRU_PRODUCT_OFFSET:
            type = IPMI_FRU_AREA_PRODUCT_INFO;
            break;

        case IPMI_FRU_MULTI_OFFSET:
            type = IPMI_FRU_AREA_MULTI_RECORD;
            break;

        default:
            type = IPMI_FRU_AREA_TYPE_MAX;
    }

    return type;
}

//------------------------------------------------------------------------
// Takes FRU data, invokes Parser for each fru record area and updates
// Inventory
//------------------------------------------------------------------------
int ipmi_update_inventory(const uint8_t fruid, const uint8_t *fru_data, 
                          fru_area_vec_t & area_vec)
{
    // Now, use this fru dictionary object and connect with FRU Inventory Dbus
    // and update the data for this FRU ID.
    int rc = 0;
    
    // Dictionary object to hold Name:Value pair
    sd_bus_message *fru_dict = NULL;

    // SD Bus error report mechanism.
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    // Gets a hook onto either a SYSTEM or SESSION bus
    sd_bus *bus_type = NULL;

    // Req message contains the specifics about which method etc that we want to
    // access on which bus, object
    sd_bus_message *response = NULL;

    rc = sd_bus_open_system(&bus_type);
    if(rc < 0)
    {
        fprintf(stderr,"ERROR: Getting a SYSTEM bus hook\n");
        return -1;
    }

    // For each FRU area, extract the needed data , get it parsed and update
    // the Inventory.
    for(auto& iter : area_vec)
    {
        uint8_t area_type = (iter).type;

        uint8_t area_data[(iter).len];
        memset(area_data, 0x0, sizeof(area_data));

        // Grab area specific data
        memmove(area_data, (iter).offset, (iter).len);

        // Need this to get respective DBUS objects
        const char *area_name  = NULL;

        if(area_type == IPMI_FRU_AREA_CHASSIS_INFO)
        {
            area_name = "CHASSIS_";
        }
        else if(area_type == IPMI_FRU_AREA_BOARD_INFO)
        {
            area_name = "BOARD_";
        }
        else if(area_type == IPMI_FRU_AREA_PRODUCT_INFO)
        {
            area_name = "PRODUCT_";
        }
        else
        {
            fprintf(stderr, "ERROR: Invalid Area type :[%d]",area_type);
            break;
        }
 
        // What we need is BOARD_1, PRODUCT_1, CHASSIS_1 etc..
        char fru_area_name[16] = {0};
        sprintf(fru_area_name,"%s%d",area_name, fruid);

#ifdef __IPMI_DEBUG__
        printf("Updating Inventory with :[%s]\n",fru_area_name);
#endif
        // Each area needs a clean set.       
        sd_bus_error_free(&bus_error);
        sd_bus_message_unref(response);
        sd_bus_message_unref(fru_dict);
    
        // We want to call a method "getObjectFromId" on System Bus that is
        // made available over  OpenBmc system services.
        rc = sd_bus_call_method(bus_type,                   // On the System Bus
                                bus_name,                   // Service to contact
                                object_name,                // Object path 
                                intf_name,                  // Interface name
                                "getObjectFromId",          // Method to be called
                                &bus_error,                 // object to return error
                                &response,                  // Response message on success
                                "ss",                       // input message (string,byte)
                                "FRU_STR",                  // First argument to getObjectFromId
                                fru_area_name);             // Second Argument

        if(rc < 0)
        {
            fprintf(stderr, "Failed to issue method call: %s\n", bus_error.message);
            break;
        }

        // Method getObjectFromId returns 3 parameters and all are strings, namely
        // bus_name , object_path and interface name for accessing that particular 
        // FRU over Inventory SDBUS manager. 'sss' here mentions that format.
        char *inv_bus_name, *inv_obj_path, *inv_intf_name;
        rc = sd_bus_message_read(response, "(sss)", &inv_bus_name, &inv_obj_path, &inv_intf_name);
        if(rc < 0)
        {
            fprintf(stderr, "Failed to parse response message:[%s]\n", strerror(-rc));
            break;
        }

#ifdef __IPMI_DEBUG__
        printf("fru_area=[%s], inv_bus_name=[%s], inv_obj_path=[%s],inv_intf_name=[%s]\n",
                fru_area_name, inv_bus_name, inv_obj_path, inv_intf_name);
#endif

        // Constructor to allow further initializations and customization.
        rc = sd_bus_message_new_method_call(bus_type,
                                            &fru_dict,
                                            inv_bus_name,
                                            inv_obj_path,
                                            inv_intf_name,
                                            "update");
        if(rc < 0)
        {
            fprintf(stderr,"ERROR: creating a update method call\n");
            break;
        }

        // A Dictionary ({}) having (string, variant)
        rc = sd_bus_message_open_container(fru_dict, 'a', "{sv}");
        if(rc < 0)
        {
            fprintf(stderr,"ERROR:[%d] creating a dict container:\n",errno);
            break;
        }

        // Fill the container with information
        rc = parse_fru_area((iter).type, (void *)area_data, (iter).len, fru_dict);
        if(rc < 0)
        {
            fprintf(stderr,"ERROR parsing FRU records\n");
            break;
        }

        sd_bus_message_close_container(fru_dict);

        // Now, Make the actual call to update the FRU inventory database with the
        // dictionary given by FRU Parser. There is no response message expected for
        // this.
        rc = sd_bus_call(bus_type,            // On the System Bus
                         fru_dict,            // With the Name:value dictionary array
                         0,                   // 
                         &bus_error,          // Object to return error.
                         &response);          // Response message if any.

        if(rc < 0)
        {
            fprintf(stderr, "ERROR:[%s] updating FRU inventory for ID:[0x%X]\n",
                    bus_error.message, fruid);
        }
        else
        {
            printf("SUCCESS: Updated:[%s] successfully\n",fru_area_name);
        }
    } // END walking the vector of areas and updating

    sd_bus_error_free(&bus_error);
    sd_bus_message_unref(response);
    sd_bus_message_unref(fru_dict);
    sd_bus_unref(bus_type);

    return rc;
}

//-------------------------------------------------------------------------
// Validates the CRC and if found good, calls fru areas parser and calls
// Inventory Dbus with the dictionary of Name:Value for updating. 
//-------------------------------------------------------------------------
int ipmi_validate_and_update_inventory(const uint8_t fruid, const uint8_t *fru_data)
{
    // Used for generic checksum calculation
    uint8_t checksum = 0;

    // This can point to any FRU entry.
    uint8_t fru_entry;

    // A generic offset locator for any FRU record.
    uint8_t area_offset = 0;

    // First 2 bytes in the record.
    uint8_t fru_area_hdr[2] = {0};

    // To hold info about individual FRU record areas.
    fru_area_t fru_area;

    // For parsing and updating Inventory.
    fru_area_vec_t fru_area_vec;

    int rc = 0;

    uint8_t common_hdr[sizeof(struct common_header)] = {0};
    memset(common_hdr, 0x0, sizeof(common_hdr));

    // Copy first 8 bytes to verify common header
    memcpy(common_hdr, fru_data, sizeof(common_hdr));

    // Validate for first byte to always have a value of [1]
    if(common_hdr[0] != IPMI_FRU_HDR_BYTE_ZERO)
    {
        fprintf(stderr, "ERROR: Common Header entry_1:[0x%X] Invalid.\n",common_hdr[0]);
        return -1;
    }
    else
    {
        printf("SUCCESS: Validated [0x%X] in common header\n",common_hdr[0]);
    }

    // Validate the header checskum that is at last byte ( Offset: 7 )
    checksum = calculate_crc(common_hdr, sizeof(common_hdr)-1);
    if(checksum != common_hdr[IPMI_FRU_HDR_CRC_OFFSET])
    {
#ifdef __IPMI__DEBUG__
        fprintf(stderr, "ERROR: Common Header checksum mismatch."
                " Calculated:[0x%X], Embedded:[0x%X]\n", 
                checksum, common_hdr[IPMI_FRU_HDR_CRC_OFFSET]);
#endif    
        return -1;
    }
    else
    {
        printf("SUCCESS: Common Header checksum MATCH:[0x%X]\n",checksum);
    }

    //-------------------------------------------
    // TODO:  Add support for Multi Record later
    //-------------------------------------------

    //  Now start walking the common_hdr array that has offsets into other FRU
    //  record areas and validate those. Starting with second entry since the
    //  first one is always a [0x01]
    for(fru_entry = IPMI_FRU_INTERNAL_OFFSET; fru_entry < (sizeof(struct common_header) -2); fru_entry++)
    {
        // Offset is 'value given in' internal_offset * 8 from the START of
        // common header. So an an example, 01 00 00 00 01 00 00 fe has
        // product area set at the offset 01 * 8 --> 8 bytes from the START of
        // common header. That means, soon after the header checksum.
        area_offset = common_hdr[fru_entry] * IPMI_EIGHT_BYTES;
        
        if(area_offset)
        {
            memset((void *)&fru_area, 0x0, sizeof(fru_area_t));

            // Enumerated FRU area.
            fru_area.type = get_fru_area_type(fru_entry);

            // From start of fru header + record offset, copy 2 bytes.
            fru_area.offset = &((uint8_t *)fru_data)[area_offset];
            memcpy(fru_area_hdr, fru_area.offset, sizeof(fru_area_hdr));

            // A NON zero value means that the vpd packet has the data for that
            // area. err if first element in the record header is _not_ a [0x01].
            if(fru_area_hdr[0] != IPMI_FRU_HDR_BYTE_ZERO)
            {
                fprintf(stderr, "ERROR: Unexpected :[0x%X] found at Record header\n",
                        fru_area_hdr[0]);

                // This vector by now may have had some entries. Since this is a
                // failure now, clear the state data.
                fru_area_vec.clear();
                return -1;
            }
            else
            {
                printf("SUCCESS: Validated [0x%X] in fru record:[%d] header\n",
                        fru_area_hdr[0],fru_entry);
            }

            // Read Length bytes ( makes a complete record read now )
            fru_area.len = fru_area_hdr[1] * IPMI_EIGHT_BYTES;
#ifdef __IPMI_DEBUG__
            printf("AREA NO[%d], SIZE = [%d]\n",fru_entry, fru_area.len);
#endif
            uint8_t fru_area_data[fru_area.len];
            memset(fru_area_data, 0x0, sizeof(fru_area_data));

            memmove(fru_area_data, fru_area.offset, sizeof(fru_area_data));

            // Calculate checksum (from offset -> (Length-1)).
            // All the bytes except the last byte( which is CRC :) ) will
            // participate in calculating the checksum.
            checksum = calculate_crc(fru_area_data, sizeof(fru_area_data)-1);

            // Verify the embedded checksum in last byte with calculated checksum
            // record_len -1 since length is some N but numbering is 0..N-1
            if(checksum != fru_area_data[fru_area.len-1])
            {
#ifdef __IPMI_DEBUG__
                fprintf(stderr, "ERROR: FRU Header checksum mismatch. "
                        " Calculated:[0x%X], Embedded:[0x%X]\n", 
                        checksum, fru_area_data[fru_area.len - 1]);
#endif
                // This vector by now may have had some entries. Since this is a
                // failure now, clear the state data.
                fru_area_vec.clear();
                return -1;
            }
            else
            {
                printf("SUCCESS: FRU Header checksum MATCH:[0x%X]\n",checksum);
            }

            // Everything is rihgt about this particular FRU record,
            fru_area_vec.push_back(fru_area);

            // Update the internal structure with info about this entry that is
            // needed while handling each areas.
        } // If the packet has data for a particular data record.
    } // End walking all the fru records.
        
    // If we reach here, then we have validated the crc for all the records and
    // time to call FRU area parser to get a Name:Value pair dictionary.
    // This will start iterating all over again on the buffer -BUT- now with the
    // job of taking each areas, getting it parsed and then updating the
    // DBUS.
        
    if(!(fru_area_vec.empty()))
    {
        rc =  ipmi_update_inventory(fruid, fru_data, fru_area_vec);
    }
 
    // We are done with this FRU write packet. 
    fru_area_vec.clear();

    return rc;
}

///-----------------------------------------------------
// Accepts the filename and validates per IPMI FRU spec
//----------------------------------------------------
int ipmi_validate_fru_area(const uint8_t fruid, const char *fru_file_name)
{
    int file_size = 0;
    uint8_t *fru_data = NULL;
    int bytes_read = 0;
    int rc = 0;

    FILE *fru_file = fopen(fru_file_name,"rb");
    if(fru_file == NULL)
    {
        fprintf(stderr, "ERROR: opening:[%s]\n",fru_file_name);
        perror("Error:");
        return -1;
    }

    // Get the size of the file to allocate buffer to hold the entire contents.
    if(fseek(fru_file, 0, SEEK_END))
    {
        perror("Error:");
        fclose(fru_file);
        return -1;
    }

    file_size = ftell(fru_file);
    fru_data = (uint8_t *)malloc(file_size);

    // Read entire file contents to the internal buffer
    if(fseek(fru_file, 0, SEEK_SET))
    {
        perror("Error:");
        fclose(fru_file);
        return -1;
    }

    bytes_read = fread(fru_data, file_size, 1, fru_file);
    if(bytes_read != 1)
    {
        fprintf(stderr, "ERROR reading common header. Bytes read=:[%d]\n",bytes_read);
        perror("Error:");
        fclose(fru_file);
        return -1;
    }
    fclose(fru_file);

    rc = ipmi_validate_and_update_inventory(fruid, fru_data);
    if(rc == -1)
    {
        printf("ERROR: Validation failed for:[%d]\n",fruid);
    }
    else
    {
        printf("SUCCESS: Validated:[%s]\n",fru_file_name);
    }

    if(fru_data)
    {
        free(fru_data);
        fru_data = NULL;
    }

    return rc;
}

///-------------------------------------------------------
// Called by IPMI netfn router for write fru data command
//--------------------------------------------------------
ipmi_ret_t ipmi_storage_write_fru_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd, 
                              ipmi_request_t request, ipmi_response_t response, 
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    FILE *fp = NULL;
    char fru_file_name[16] = {0};
    uint8_t offset = 0;
    uint16_t len = 0;
    ipmi_ret_t rc = IPMI_CC_INVALID;
    int validate_rc = 0;
    const char *mode = NULL;

    // From the payload, extract the header that has fruid and the offsets
    write_fru_data_t *reqptr = (write_fru_data_t*)request;

    // There is no response data for this command.
    *data_len = 0;

    // Maintaining a temporary file to pump the data
    sprintf(fru_file_name, "%s%02x", "/tmp/ipmifru", reqptr->frunum);

    offset = ((uint16_t)reqptr->offsetms) << 8 | reqptr->offsetls;

    // Length is the number of request bytes minus the header itself.
    // The header contains an extra byte to indicate the start of
    // the data (so didn't need to worry about word/byte boundaries)
    // hence the -1...
    len = ((uint16_t)*data_len) - (sizeof(write_fru_data_t)-1);
    
#ifdef __IPMI__DEBUG__
    printf("IPMI WRITE-FRU-DATA for [%s]  Offset = [%d] Length = [%d]\n",
            fru_file_name, offset, len);
#endif

    // offset would be zero if the cmd payload is targeting a new fru
    if (offset == 0)
    {
        mode = "wb";
    } 
    else 
    {
        // offset would be non-zero if the cmd payload is continued for prev
        // fru
        mode = "rb+";
    }

    if ((fp = fopen(fru_file_name, mode)) != NULL) 
    {
        if(fseek(fp, offset, SEEK_SET))
        {
            perror("Error:");
            fclose(fp);
            return rc;
        }
    
        if(fwrite(&reqptr->data, len, 1, fp) != 1)
        {
            perror("Error:");
            fclose(fp);
            return rc;
        }
    
        fclose(fp);
    } 
    else 
    {
        fprintf(stderr, "Error trying to write to fru file %s\n",fru_file_name);
        return rc;
    }
    
    // We received some bytes. It may be full or partial. Run a validator.
    validate_rc = ipmi_validate_fru_area(reqptr->frunum, fru_file_name);
    if(validate_rc != -1)
    {
        // Success validating _and_ updating the Inventory. We no longer need
        // this file.
        remove(fru_file_name);
    }

    // convert the rc per ipmi spec   
    rc = (validate_rc != -1) ? IPMI_CC_OK : IPMI_CC_INVALID;

    return rc;
}

ipmi_ret_t ipmi_storage_get_sel_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;
    unsigned char buf[] = {0x51,0,0,0xff, 0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0x06};

    printf("IPMI Handling GET-SEL-INFO\n");

    *data_len = sizeof(buf);

    // TODO There is plently of work here.  The SEL DB needs to hold a bunch
    // of things in a header.  Items like Time Stamp, number of entries, etc
    // This is one place where the dbus object with the SEL information could
    // mimic what IPMI needs.

    // Pack the actual response
    memcpy(response, &buf, *data_len);

    return rc;
}



ipmi_ret_t ipmi_storage_reserve_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;

    printf("IPMI Handling RESERVE-SEL 0x%04x\n", g_sel_reserve);


    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &g_sel_reserve, *data_len);

    return rc;
}

ipmi_ret_t ipmi_storage_add_sel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{

    ipmi_ret_t rc = IPMI_CC_OK;
    ipmi_add_sel_request_t *p = (ipmi_add_sel_request_t*) request;
    uint16_t recordid;

    recordid = ((uint16_t)p->eventdata[1] << 8) | p->eventdata[2];

    printf("IPMI Handling ADD-SEL for record 0x%04x\n", recordid);

    *data_len = sizeof(g_sel_reserve);

    // Pack the actual response
    memcpy(response, &recordid, 2);

    // TODO This code should grab the completed partial esel located in
    // the /tmp/esel0100 file and commit it to the error log handler.
    send_esel(recordid);

    return rc;
}

void register_netfn_storage_functions()
{
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WILDCARD, NULL, ipmi_storage_wildcard);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_TIME, NULL, ipmi_storage_get_sel_time);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_SET_SEL_TIME, NULL, ipmi_storage_set_sel_time);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_WRITE_FRU_DATA);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_WRITE_FRU_DATA, NULL, ipmi_storage_write_fru_data);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_GET_SEL_INFO, NULL, ipmi_storage_get_sel_info);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_RESERVE_SEL, NULL, ipmi_storage_reserve_sel);

    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",NETFUN_STORAGE, IPMI_CMD_ADD_SEL);
    ipmi_register_callback(NETFUN_STORAGE, IPMI_CMD_ADD_SEL, NULL, ipmi_storage_add_sel);
    return;
}

