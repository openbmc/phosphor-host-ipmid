#ifndef __HOST_IPMI_SEN_HANDLER_H__
#define __HOST_IPMI_SEN_HANDLER_H__

#include <stdint.h>
#include "types.hpp"

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
    IPMI_SENSOR_TPM     = 0xCC,
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
 * Get SDR Info
 */

namespace get_sdr_info
{
namespace request
{
// Note: for some reason the ipmi_request_t appears to be the
// raw value for this call.
inline bool get_count(void* req)
{
    return (bool)((uint64_t)(req) & 1);
}
} // namespace request

namespace response
{
#define SDR_INFO_RESP_SIZE 2
inline void set_lun_present(int lun, uint8_t* resp)
{
    *resp |= 1 << lun;
}
inline void set_lun_not_present(int lun, uint8_t* resp)
{
    *resp &= ~(1 << lun);
}
inline void set_dynamic_population(uint8_t* resp)
{
    *resp |= 1 << 7;
}
inline void set_static_population(uint8_t* resp)
{
    *resp &= ~(1 << 7);
}
} // namespace response

struct GetSdrInfoResp
{
    uint8_t count;
    uint8_t luns_and_dynamic_population;
};

} // namespace get_sdr_info

/**
 * Get SDR
 */
namespace get_sdr
{

struct GetSdrReq
{
    uint8_t reservation_id_lsb;
    uint8_t reservation_id_msb;
    uint8_t record_id_lsb;
    uint8_t record_id_msb;
    uint8_t offset;
    uint8_t bytes_to_read;
} __attribute__((packed));

namespace request
{

inline uint8_t get_reservation_id(GetSdrReq* req)
{
    return (req->reservation_id_lsb + (req->reservation_id_msb << 8));
};

inline uint8_t get_record_id(GetSdrReq* req)
{
    return (req->record_id_lsb + (req->record_id_msb << 8));
};

} // namespace request

// Response
struct GetSdrResp
{
    uint8_t next_record_id_lsb;
    uint8_t next_record_id_msb;
    uint8_t record_data[64];
} __attribute__((packed));

namespace response
{

inline void set_next_record_id(int next, GetSdrResp* resp)
{
    resp->next_record_id_lsb = next & 0xff;
    resp->next_record_id_msb = (next >> 8) & 0xff;
};

} // namespace response

// Record header
struct SensorDataRecordHeader
{
    uint8_t record_id_lsb;
    uint8_t record_id_msb;
    uint8_t sdr_version;
    uint8_t record_type;
    uint8_t record_length; // Length not counting the header
} __attribute__((packed));

namespace header
{

inline void set_record_id(int id, SensorDataRecordHeader* hdr)
{
    hdr->record_id_lsb = (id & 0xFF);
    hdr->record_id_msb = (id >> 8) & 0xFF;
};

} // namespace header

enum SensorDataRecordType
{
    SENSOR_DATA_FULL_RECORD = 1,
};

// Record key
struct SensorDataRecordKey
{
    uint8_t owner_id;
    uint8_t owner_lun;
    uint8_t sensor_number;
} __attribute__((packed));

namespace key
{

inline void set_owner_id_ipmb(SensorDataRecordKey* key)
{
    key->owner_id &= ~0x01;
};

inline void set_owner_id_system_sw(SensorDataRecordKey* key)
{
    key->owner_id |= 0x01;
};

inline void set_owner_id_address(uint8_t addr, SensorDataRecordKey* key)
{
    key->owner_id &= 0x01;
    key->owner_id |= addr<<1;
};

inline void set_owner_lun(uint8_t lun, SensorDataRecordKey* key)
{
    key->owner_lun &= ~0x03;
    key->owner_lun |= (lun&0x03);
};

inline void set_owner_lun_channel(uint8_t channel, SensorDataRecordKey* key)
{
    key->owner_lun &= 0x0f;
    key->owner_lun |= ((channel & 0xf)<<4);
};

} // namespace key

// Body - full record
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
    char id_string[FULL_RECORD_ID_STR_MAX_LENGTH];
} __attribute__((packed));

namespace body
{

inline void set_entity_instance_number(uint8_t n,
                                       SensorDataFullRecordBody* body)
{
    body->entity_instance &= 1<<7;
    body->entity_instance |= (n & ~(1<<7));
};
inline void set_entity_physical_entity(SensorDataFullRecordBody* body)
{
    body->entity_instance &= ~(1<<7);
};
inline void set_entity_logical_container(SensorDataFullRecordBody* body)
{
    body->entity_instance |= 1<<7;
};

inline void sensor_scanning_state(bool enabled,
                                  SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<0;
    }
    else
    {
        body->sensor_initialization &= ~(1<<0);
    };
};
inline void event_generation_state(bool enabled,
                                   SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<1;
    }
    else
    {
        body->sensor_initialization &= ~(1<<1);
    }
};
inline void init_types_state(bool enabled,
                             SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<2;
    }
    else
    {
        body->sensor_initialization &= ~(1<<2);
    }
};
inline void init_hyst_state(bool enabled,
                            SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<3;
    }
    else
    {
        body->sensor_initialization &= ~(1<<3);
    }
};
inline void init_thresh_state(bool enabled,
                              SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<4;
    }
    else
    {
        body->sensor_initialization &= ~(1<<4);
    }
};
inline void init_events_state(bool enabled,
                              SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<5;
    }
    else
    {
        body->sensor_initialization &= ~(1<<5);
    }
};
inline void init_scanning_state(bool enabled,
                                SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<6;
    }
    else
    {
        body->sensor_initialization &= ~(1<<6);
    }
};
inline void init_settable_state(bool enabled,
                                SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensor_initialization |= 1<<7;
    }
    else
    {
        body->sensor_initialization &= ~(1<<7);
    }
};

inline void set_percentage(SensorDataFullRecordBody* body)
{
    body->sensor_units_1 |= 1<<0;
};
inline void unset_percentage(SensorDataFullRecordBody* body)
{
    body->sensor_units_1 &= ~(1<<0);
};
inline void set_modifier_operation(uint8_t op, SensorDataFullRecordBody* body)
{
    body->sensor_units_1 &= ~(3<<1);
    body->sensor_units_1 |= (op & 0x3)<<1;
};
inline void set_rate_unit(uint8_t unit, SensorDataFullRecordBody* body)
{
    body->sensor_units_1 &= ~(7<<3);
    body->sensor_units_1 |= (unit & 0x7)<<3;
};
inline void set_analog_data_format(uint8_t format,
                                   SensorDataFullRecordBody* body)
{
    body->sensor_units_1 &= ~(3<<6);
    body->sensor_units_1 |= (format & 0x3)<<6;
};

inline void set_m(uint16_t m, SensorDataFullRecordBody* body)
{
    body->m_lsb = m & 0xff;
    body->m_msb_and_tolerance &= ~(3<<6);
    body->m_msb_and_tolerance |= ((m & (3<<8)) >> 2);
};
inline void set_tolerance(uint8_t tol, SensorDataFullRecordBody* body)
{
    body->m_msb_and_tolerance &= ~0x3f;
    body->m_msb_and_tolerance |= tol & 0x3f;
};

inline void set_b(uint16_t b, SensorDataFullRecordBody* body)
{
    body->b_lsb = b & 0xff;
    body->b_msb_and_accuracy_lsb &= ~(3<<6);
    body->b_msb_and_accuracy_lsb |= ((b & (3<<8)) >> 2);
};
inline void set_accuracy(uint16_t acc, SensorDataFullRecordBody* body)
{
    // bottom 6 bits
    body->b_msb_and_accuracy_lsb &= ~0x3f;
    body->b_msb_and_accuracy_lsb |= acc & 0x3f;
    // top 4 bits
    body->accuracy_and_sensor_direction &= 0x0f;
    body->accuracy_and_sensor_direction |= ((acc >> 6) & 0xf) << 4;
};
inline void set_accuracy_exp(uint8_t exp, SensorDataFullRecordBody* body)
{
    body->accuracy_and_sensor_direction &= ~(3<<2);
    body->accuracy_and_sensor_direction |= (exp & 3)<<2;
};
inline void set_sensor_dir(uint8_t dir, SensorDataFullRecordBody* body)
{
    body->accuracy_and_sensor_direction &= ~(3<<0);
    body->accuracy_and_sensor_direction |= (dir & 3);
};

inline void set_b_exp(uint8_t exp, SensorDataFullRecordBody* body)
{
    body->r_b_exponents &= 0xf0;
    body->r_b_exponents |= exp & 0x0f;
};
inline void set_r_exp(uint8_t exp, SensorDataFullRecordBody* body)
{
    body->r_b_exponents &= 0x0f;
    body->r_b_exponents |= (exp & 0x0f)<<4;
};

inline void set_id_strlen(uint8_t len, SensorDataFullRecordBody* body)
{
    body->id_string_info &= ~(0x1f);
    body->id_string_info |= len & 0x1f;
};
inline uint8_t get_id_strlen( SensorDataFullRecordBody* body)
{
    return body->id_string_info & 0x1f;
};
inline void set_id_type(uint8_t type, SensorDataFullRecordBody* body)
{
    body->id_string_info &= ~(3<<6);
    body->id_string_info |= (type & 0x3)<<6;
};

} // namespace body

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

} // get_sdr

namespace ipmi
{

namespace sensor
{

/**
 * @brief Map offset to the corresponding bit in the assertion byte.
 *
 * The discrete sensors support upto 14 states. 0-7 offsets are stored in one
 * byte and offsets 8-14 in the second byte.
 *
 * @param[in] offset - offset number.
 * @param[in/out] resp - get sensor reading response.
 */
inline void setOffset(uint8_t offset, ipmi::sensor::GetReadingResponse* resp)
{
    if (offset > 7)
    {
        resp->assertOffset8_14 |= 1 << (offset - 8);
    }
    else
    {
        resp->assertOffset0_7 |= 1 << offset;
    }
}

/**
 * @brief Set the reading field in the response.
 *
 * @param[in] offset - offset number.
 * @param[in/out] resp - get sensor reading response.
 */
inline void setReading(uint8_t value, ipmi::sensor::GetReadingResponse* resp)
{
    resp->reading = value;
}

} // namespace sensor

} // namespace ipmi
#endif
