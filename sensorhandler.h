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

struct GetSdrReq
{
    uint16_t reservation_id;
    uint16_t record_id;
    uint8_t  offset;
    uint8_t  bytes_to_read;
} __attribute__((packed));

struct GetSdrResp
{
    uint16_t next_record_id;
    char record_data[64]; // Record Data max size? Check spec
} __attribute__((packed));

enum SensorDataRecordType
{
    SENSOR_DATA_FULL_RECORD = 1,
} __attribute__((packed));

struct SensorDataRecordHeader
{
    uint16_t record_id;
    uint8_t sdr_version;
    uint8_t record_type;
    uint8_t record_length; // Length not counting the header size
} __attribute__((packed));

struct SensorDataRecordKey
{
     struct
     {
         uint8_t is_i2c_or_system_sw_id : 1;
         uint8_t address : 7;
     } __attribute__((packed)) owner_id;
     struct
     {
         uint8_t owner_lun : 2;
         uint8_t : 2;
         uint8_t channel_number : 4;
     } __attribute__((packed)) owner_lun;
     uint8_t sensor_number;
} __attribute__((packed));


/* Full Record and Dependencies - See pg 521 of IPMI spec v2r1.1*/

struct SupportedEventMask
{
    bool assert_lower_noncritical_low : 1;
    bool assert_lower_noncritical_high : 1;
    bool assert_lower_critical_low : 1;
    bool assert_lower_critical_high : 1;
    bool assert_lower_nonrecoverable_low : 1;
    bool assert_lower_nonrecoverable_high : 1;
    bool assert_upper_noncritical_low : 1;
    bool assert_upper_noncritical_high : 1;
    bool assert_upper_critical_low : 1;
    bool assert_upper_critical_high : 1;
    bool assert_upper_nonrecoverable_low : 1;
    bool assert_upper_nonrecoverable_high : 1;
    bool lower_noncritical_threshold_comparison_returned : 1;
    bool lower_critical_threshold_comparison_returned : 1;
    bool lower_nonrecoverable_threshold_comparison_returned : 1;
    bool : 1;
} __attribute__((packed));

struct SensorDataFullRecordBody
{
    uint8_t entity_id;
    struct
    {
        uint8_t instance_number : 7;
        uint8_t is_logical_container : 1;
    } __attribute__((packed)) entity_instance;
    struct
    {
        bool sensor_scanning_enabled :1;
        bool event_generation_enabled :1;
        bool init_types : 1;
        bool init_hysteresis : 1;
        bool init_thresholds : 1;
        bool init_events : 1;
        bool init_scanning : 1;
        bool is_settable : 1;
    } __attribute__((packed)) sensor_initialization;
    struct
    {
        uint8_t sensor_event_message_control_support : 2;
        uint8_t sensor_threshold_access_support : 2;
        uint8_t sensor_hysteresis_support : 2;
        uint8_t sensor_auto_rearm_support : 1;
        uint8_t ignore_if_missing : 1;
    } __attribute__((packed)) sensor_capabilities;
    uint8_t sensor_type;
    uint8_t event_reading_type;
    SupportedEventMask supported_assertions;
    SupportedEventMask supported_deassertions;
    struct {
        bool lower_noncritical_readable : 1;
        bool lower_critical_readable : 1;
        bool lower_nonrecoverable_readable : 1;
        bool upper_noncritical_readable : 1;
        bool upper_critical_readable : 1;
        bool upper_nonrecoverable_readable : 1;
        bool : 2;
        bool lower_noncritical_settable : 1;
        bool lower_critical_settable : 1;
        bool lower_nonrecoverable_settable : 1;
        bool upper_noncritical_settable : 1;
        bool upper_critical_settable : 1;
        bool upper_nonrecoverable_settable : 1;
        bool : 2;
    } __attribute__((packed)) discrete_reading_setting_mask;
    struct {  // For codes, see IPMI spec page 526
        bool is_percentage : 1;
        uint8_t modifier_operation : 2;
        uint8_t rate_unit : 3;
        uint8_t analog_data_format : 2;
    } __attribute__((packed)) sensor_units_1;
    uint8_t sensor_units_2_base;
    uint8_t sensor_units_3_modifier;
    uint8_t linearization; // See IPMI spec page 526
    uint8_t m_lsb;
    struct {
        uint8_t tolerance : 6;
        uint8_t m_msb : 2;
    } __attribute__((packed)) m_msb_and_tolerance;
    uint8_t b_lsb;
    struct {
        uint8_t accuracy_lsb : 6;
        uint8_t b_msb : 2;
    } __attribute__((packed)) b_msb_and_accuracy_lsb;
    struct {  // For codes, see IPMI spec page 526
        uint8_t sensor_direction : 2;
        uint8_t accuracy_exp : 2;
        uint8_t accuracy_msb : 4;
    } __attribute__((packed)) accuracy_and_sensor_direction;
    struct {
        uint8_t b_exponent : 4;
        uint8_t r_exponent : 4;
    } __attribute__((packed)) r_b_exponents;
    struct {
        bool nominal_reading_specified : 1;
        bool normal_max_specified : 1;
        bool normal_min_specified : 1;
        bool : 5;
    } __attribute__((packed)) analog_characteristic_flags;
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
    uint8_t id_string_type_length_code;
    struct {
        uint8_t length : 5;
        uint8_t : 1;
        uint8_t type : 2;
    } __attribute__((packed)) id_string_info;
    char id_string[16];
} __attribute__((packed));

struct SensorDataFullRecord {
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataFullRecordBody body;
} __attribute__((packed));

#endif
