#ifndef __HOST_IPMI_SEN_HANDLER_H__
#define __HOST_IPMI_SEN_HANDLER_H__

#include <stdint.h>

// IPMI commands for net functions.
enum ipmi_netfn_sen_cmds
{
    IPMI_CMD_GET_SDR_INFO       = 0x20,
    IPMI_CMD_GET_SENSOR_READING = 0x2D,
    IPMI_CMD_GET_SENSOR_TYPE    = 0x2F,
    IPMI_CMD_SET_SENSOR         = 0x30,
};

// Discrete sensor types.
enum ipmi_sensor_types
{
    IPMI_SENSOR_TEMP    = 0x01,
    IPMI_SENSOR_VOLTAGE = 0x02,
    IPMI_SENSOR_CURRENT = 0x03,
    IPMI_SENSOR_FAN     = 0x04,
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
int find_openbmc_path(uint8_t , dbus_interface_t *);

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

/**
 * Get SDR Info
 */

namespace get_sdr_info {
namespace request {
// Note: for some reason the ipmi_request_t appears to be the
// raw value for this call.
inline bool get_count(void* req) {
    return (bool)((uint64_t)(req) & 1);
}

} // namespace request

namespace response {
#define SDR_INFO_RESP_SIZE 2
inline void set_lun_present(int lun, uint8_t* resp) {
    *resp |= 1 << lun;
}
inline void set_lun_not_present(int lun, uint8_t* resp) {
    *resp &= ~(1 << lun);
}
inline void set_dynamic_population(uint8_t* resp) {
    *resp |= 1 << 7;
}
inline void set_static_population(uint8_t* resp) {
    *resp &= ~(1 << 7);
}
} // namespace response

struct GetSdrInfoResp
{
    uint8_t count;
    uint8_t luns_and_dynamic_population;
};

} // namespace get_sdr_info
#endif
