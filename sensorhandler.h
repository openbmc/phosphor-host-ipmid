#ifndef __HOST_IPMI_SEN_HANDLER_H__
#define __HOST_IPMI_SEN_HANDLER_H__

#include <stdint.h>

// IPMI commands for net functions.
enum ipmi_netfn_sen_cmds
{
    IPMI_CMD_GET_SDR_INFO       = 0x20,
    IPMI_CMD_RESERVE_SDR_REPO   = 0x22,
    IPMI_CMD_GET_SENSOR_READING = 0x2D,
    IPMI_CMD_GET_SENSOR_TYPE    = 0x2F,
    IPMI_CMD_SET_SENSOR         = 0x30,
};

#define MAX_DBUS_PATH 128
struct dbus_interface_t {
    uint8_t  sensornumber;
    uint8_t  sensortype;

    char  bus[MAX_DBUS_PATH];
    char  path[MAX_DBUS_PATH];
    char  interface[MAX_DBUS_PATH];
};

int set_sensor_dbus_state_s(uint8_t , const char *, const char *);
int set_sensor_dbus_state_y(uint8_t , const char *, const uint8_t);
int find_openbmc_path(const uint8_t , dbus_interface_t *);

/**
 * @struct SetSensorReadingReq
 *
 * IPMI Request data for Set Sensor Reading and Event Status Command
 */
struct SetSensorReadingReq
{
    uint8_t number;
    uint8_t operation;
    uint8_t reading;
    uint8_t assertOffset0_7;
    uint8_t assertOffset8_14;
    uint8_t deassertOffset0_7;
    uint8_t deassertOffset8_14;
    uint8_t eventData1;
    uint8_t eventData2;
    uint8_t eventData3;
} __attribute__((packed));

struct GetSdrInfoReq
{
    bool sdr_count : 1;
} __attribute__((packed));

struct GetSdrInfoResp
{
    uint8_t count;
    struct {
        // The first 4 bits indicate whether any sensors are present on the LUN
        // indicated.
        bool lun0_present       : 1;
        bool lun1_present       : 1;
        bool lun2_present       : 1;
        bool lun3_present       : 1;
        // Reserved
        bool                    : 3;
        // Indicates whether the sensors on the LUN addressed are populated
        // dynamically (1) or statically (0)
        bool dynamic_population : 1;
    } __attribute__((packed)) info;
} __attribute__((packed));
#endif
