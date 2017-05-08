#ifndef __HOST_IPMI_SEN_HANDLER_H__
#define __HOST_IPMI_SEN_HANDLER_H__

#include <stdint.h>

// IPMI commands for net functions.
enum ipmi_netfn_sen_cmds
{
    IPMI_CMD_GET_SDR_INFO       = 0x20,
    IPMI_CMD_GET_SDR            = 0x21,
    IPMI_CMD_RESERVE_SDR_REPO   = 0x22,
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

// Request
// Note: for some reason the ipmi_request_t appears to be the
// raw value for this call.
#define GET_SDR_INFO_REQ_GET_COUNT(r) (bool)((uint64_t)(r) & 1)

// Response
#define SDR_INFO_RESP_SIZE 2
#define GET_SDR_INFO_RESP_SET_LUN_PRESENT(l,r) (r |= 1 << l)
#define GET_SDR_INFO_RESP_SET_LUN_NOT_PRESENT(l,r) (r &= ~(1 << l))
#define GET_SDR_INFO_RESP_SET_DYNAMIC_POPL(r) (r |= 1 << 7)
#define GET_SDR_INFO_RESP_SET_STATIC_POPL(r) (r &= ~(1 << 7))

struct GetSdrInfoResp
{
    uint8_t count;
    uint8_t luns_and_dynamic_popl;
};

/**
 * Get SDR
 */

// Request
#define GET_SDR_REQ_GET_RESERVATION_ID(r) (r->reservation_id_lsb + (r->reservation_id_msb << 8))
#define GET_SDR_REQ_GET_RECORD_ID(r) (r->record_id_lsb + (r->record_id_msb << 8))
struct GetSdrReq
{
    uint8_t reservation_id_lsb;
    uint8_t reservation_id_msb;
    uint8_t record_id_lsb;
    uint8_t record_id_msb;
    uint8_t offset;
    uint8_t bytes_to_read;
} __attribute__((packed));

// Response
#define GET_SDR_RESP_SET_NEXT_RECORD_ID(n,r) (r->next_record_id_lsb = n & 0xFF,\
                                              r->next_record_id_msb = (n >> 8) & 0xFF)
struct GetSdrResp
{
    uint8_t next_record_id_lsb;
    uint8_t next_record_id_msb;
    uint8_t record_data[64];
} __attribute__((packed));

#define SDR_HEADER_SET_RECORD_ID(n,h) ((h)->record_id_lsb = (n & 0xFF),\
                                       (h)->record_id_msb = (n >> 8) & 0xFF)
struct SensorDataRecordHeader
{
    uint8_t record_id_lsb;
    uint8_t record_id_msb;
    uint8_t sdr_version;
    uint8_t record_type;
    uint8_t record_length; // Length not counting the header
} __attribute__((packed));

enum SensorDataRecordType
{
    SENSOR_DATA_FULL_RECORD = 1,
};

#define SDR_KEY_SET_OWNER_ID_IPMB(k) ((k)->owner_id &= ~0x01)
#define SDR_KEY_SET_OWNER_ID_SYSTEM_SW(k) ((k)->owner_id |= 0x01)
#define SDR_KEY_SET_OWNER_ID_ADDRESS(a,k) ((k)->owner_id &= 0x01,\
                                           (k)->owner_id |= a<<1)
#define SDR_KEY_SET_OWNER_LUN(l,k) ((k)->owner_lun &= ~0x03,\
                                    (k)->owner_lun |= (l&0x03))
#define SDR_KEY_SET_OWNER_LUN_CHANNEL(c,k) ((k)->owner_lun &= 0x0F,\
                                            (k)->owner_lun |= ((c & 0xF)<<4))
struct SensorDataRecordKey
{
    uint8_t owner_id;
    uint8_t owner_lun;
    uint8_t sensor_number;
} __attribute__((packed));

#define SDR_FULL_BODY_SET_ENTITY_INSTANCE_NUMBER(n,b) ((b)->entity_instance &= 1<<7,\
                                                       (b)->entity_instance |= (n & ~(1<<7))
#define SDR_FULL_BODY_SET_ENTITY_PHYSICAL_ENTITY(b) ((b)->entity_instance &= ~(1<<7))
#define SDR_FULL_BODY_SET_ENTITY_LOGICAL_CONTAINER(b) ((b)->entity_instance |= 1<<7)

#define SDR_FULL_BODY_SENSOR_SCANNING_ENABLED(b) ((b)->sensor_initialization |= 1<<0)
#define SDR_FULL_BODY_SENSOR_SCANNING_DISABLED(b) ((b)->sensor_initialization &= ~(1<<0))
#define SDR_FULL_BODY_EVENT_GENERATION_ENABLED(b) ((b)->sensor_initialization |= 1<<1)
#define SDR_FULL_BODY_EVENT_GENERATION_DISABLED(b) ((b)->sensor_initialization &= ~(1<<1))
#define SDR_FULL_BODY_INIT_TYPES_ENABLED(b) ((b)->sensor_initialization |= 1<<2)
#define SDR_FULL_BODY_INIT_TYPES_DISABLED(b) ((b)->sensor_initialization &= ~(1<<2))
#define SDR_FULL_BODY_INIT_HYST_ENABLED(b) ((b)->sensor_initialization |= 1<<3)
#define SDR_FULL_BODY_INIT_HYST_DISABLED(b) ((b)->sensor_initialization &= ~(1<<3))
#define SDR_FULL_BODY_INIT_THRESH_ENABLED(b) ((b)->sensor_initialization |= 1<<4)
#define SDR_FULL_BODY_INIT_THRESH_DISABLED(b) ((b)->sensor_initialization &= ~(1<<4))
#define SDR_FULL_BODY_INIT_EVENTS_ENABLED(b) ((b)->sensor_initialization |= 1<<5)
#define SDR_FULL_BODY_INIT_EVENTS_DISABLED(b) ((b)->sensor_initialization &= ~(1<<5))
#define SDR_FULL_BODY_INIT_SCANNING_ENABLED(b) ((b)->sensor_initialization |= 1<<6)
#define SDR_FULL_BODY_INIT_SCANNING_DISABLED(b) ((b)->sensor_initialization &= ~(1<<6))
#define SDR_FULL_BODY_INIT_SETTABLE_ENABLED(b) ((b)->sensor_initialization |= 1<<7)
#define SDR_FULL_BODY_INIT_SETTABLE_DISABLED(b) ((b)->sensor_initialization &= ~(1<<7))

#define SDR_FULL_BODY_SET_PERCENTAGE(b) ((b)->sensor_units_1 |= 1<<0)
#define SDR_FULL_BODY_UNSET_PERCENTAGE(b) ((b)->sensor_units_1 &= ~(1<<0))
#define SDR_FULL_BODY_SET_MODIFIER_OPERATION(o,b) ((b)->sensor_units_1 &= ~(3<<1),\
                                                   (b)->sensor_units_1 |= (o & 0x3)<<1)
#define SDR_FULL_BODY_SET_RATE_UNIT(u,b) ((b)->sensor_units_1 &= ~(7<<3),\
                                          (b)->sensor_units_1 |= (u & 0x7)<<3)
#define SDR_FULL_BODY_SET_ANALOG_DATA_FORMAT(f,b) ((b)->sensor_units_1 &= ~(3<<6),\
                                                   (b)->sensor_units_1 |= (f & 0x3)<<6)

#define SDR_FULL_BODY_SET_M(m,b) ((b)->m_lsb = m & 0xFF,\
                                  (b)->m_msb_and_tolerance &= ~(3<<6),\
                                  (b)->m_msb_and_tolerance |= (m & (3<<8) >> 2))
#define SDR_FULL_BODY_SET_TOLERANCE(t,b) ((b)->m_msb_and_tolerance &= ~0x3F,\
                                          (b)->m_msb_and_tolerance |= t & 0x3F)

#define SDR_FULL_BODY_SET_B(b,p) (p->b_lsb = b & 0xFF,\
                                  p->b_msb_and_accuracy_lsb &= ~(3<<6),\
                                  p->b_msb_and_accuracy_lsb |= (b & (3<<8) >> 2))
#define SDR_FULL_BODY_SET_ACCURACY(t,b) ((b)->b_msb_and_accuracy_lsb &= ~0x3F,\
                                         (b)->b_msb_and_accuracy_lsb |= t & 0x3F,\
                                         (b)->accuracy_and_sensor_direction &= 0x0F,\
                                         (b)->accuracy_and_sensor_direction |= (t & 0xF) << 4)
#define SDR_FULL_BODY_SET_ACCURACY_EXP(e,b) ((b)->accuracy_and_sensor_direction &= ~(3<<2),\
                                             (b)->accuracy_and_sensor_direction |= (e & 3)<<2)
#define SDR_FULL_BODY_SET_SENSOR_DIR(d,b) ((b)->accuracy_and_sensor_direction &= ~(3<<0),\
                                           (b)->accuracy_and_sensor_direction |= (d & 3))

#define SDR_FULL_BODY_SET_B_EXP(e,b) ((b)->r_b_exponents &= 0xF0,\
                                      (b)->r_b_exponents |= e & 0x0F)
#define SDR_FULL_BODY_SET_R_EXP(e,b) ((b)->r_b_exponents &= 0x0F,\
                                      (b)->r_b_exponents |= (e & 0x0F)<<4)

#define SDR_FULL_BODY_SET_ID_STRLEN(l,b) ((b)->id_string_info &= ~(0x1F),\
                                          (b)->id_string_info |= l & 0x1F)
#define SDR_FULL_BODY_GET_ID_STRLEN(b) ((b)->id_string_info & 0x1F)
#define SDR_FULL_BODY_SET_ID_TYPE(t,b) ((b)->id_string_info &= ~(3<<6),\
                                        (b)->id_string_info |= (t & 0x3)<<6)
#define FULL_RECORD_ID_STR_MAX_LENGTH 16

struct SensorDataFullRecordBody
{
    uint8_t entity_id;
    uint8_t entity_instance;
    uint8_t sensor_initialization;
    uint8_t sensor_capabilities; // no macro support
    uint8_t sensor_type;
    uint8_t event_reading_type;
    uint8_t supported_assertions[2]; // no macro support
    uint8_t supported_deassertions[2]; // no macro support
    uint8_t discrete_reading_setting_mask[2]; // no macro support
    uint8_t sensor_units_1;
    uint8_t sensor_units_2_base;
    uint8_t sensor_units_3_modifier;
    uint8_t linearization;
    uint8_t m_lsb;
    uint8_t m_msb_and_tolerance;
    uint8_t b_lsb;
    uint8_t b_msb_and_accuracy_lsb;
    uint8_t accuracy_and_sensor_direction;
    uint8_t r_b_exponents;
    uint8_t analog_characteristic_flags; //no macro support
    uint8_t nominal_reading;
    uint8_t normal_max;
    uint8_t normal_min;
    uint8_t sensor_max;
    uint8_t sensor_min;
    uint8_t upper_nonrecoverable_threshold;
    uint8_t upper_critical_threshold;
    uint8_t upper_noncritical_threshold;
    uint8_t lower_nonrecoverable_threshold;
    uint8_t lower_critical_threshold;
    uint8_t lower_noncritical_threshold;
    uint8_t positive_threshold_hysteresis;
    uint8_t negative_threshold_hysteresis;
    uint16_t reserved;
    uint8_t oem_reserved;
    uint8_t id_string_info;
    char id_string[16];
} __attribute__((packed));

// More types contained in section 43.17 Sensor Unit Type Codes,
// IPMI spec v2 rev 1.1
enum SensorUnitTypeCodes
{
    SENSOR_UNIT_UNSPECIFIED = 0,
    SENSOR_UNIT_DEGREES_C = 1,
    SENSOR_UNIT_VOLTS = 4,
    SENSOR_UNIT_AMPERES = 5,
    SENSOR_UNIT_JOULES = 7,
    SENSOR_UNIT_METERS = 34,
    SENSOR_UNIT_REVOLUTIONS = 41,
};

struct SensorDataFullRecord
{
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataFullRecordBody body;
} __attribute__((packed));
#endif
