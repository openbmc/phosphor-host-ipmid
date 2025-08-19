#pragma once

#include <stdint.h>

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>

#include <exception>

/**
 * @enum device_type
 * IPMI FRU device types
 */
enum device_type
{
    IPMI_PHYSICAL_FRU = 0x00,
    IPMI_LOGICAL_FRU = 0x80,
};

// Discrete sensor types.
enum ipmi_sensor_types
{
    IPMI_SENSOR_TEMP = 0x01,
    IPMI_SENSOR_VOLTAGE = 0x02,
    IPMI_SENSOR_CURRENT = 0x03,
    IPMI_SENSOR_FAN = 0x04,
    IPMI_SENSOR_TPM = 0xCC,
};

/** @brief Custom exception for reading sensors that are not funcitonal.
 */
struct SensorFunctionalError : public std::exception
{
    const char* what() const noexcept
    {
        return "Sensor not functional";
    }
};

#define MAX_DBUS_PATH 128
struct dbus_interface_t
{
    uint8_t sensornumber;
    uint8_t sensortype;

    char bus[MAX_DBUS_PATH];
    char path[MAX_DBUS_PATH];
    char interface[MAX_DBUS_PATH];
};

struct PlatformEventRequest
{
    uint8_t eventMessageRevision;
    uint8_t sensorType;
    uint8_t sensorNumber;
    uint8_t eventDirectionType;
    uint8_t data[3];
};

static constexpr const char* ipmiSELObject = "xyz.openbmc_project.Logging.IPMI";
static constexpr const char* ipmiSELPath = "/xyz/openbmc_project/Logging/IPMI";
static constexpr const char* ipmiSELAddInterface =
    "xyz.openbmc_project.Logging.IPMI";
static const std::string ipmiSELAddMessage = "IPMI generated SEL Entry";

static constexpr int selSystemEventSizeWith3Bytes = 8;
static constexpr int selSystemEventSizeWith2Bytes = 7;
static constexpr int selSystemEventSizeWith1Bytes = 6;
static constexpr int selIPMBEventSize = 7;
static constexpr uint8_t directionMask = 0x80;
static constexpr uint8_t byte3EnableMask = 0x30;
static constexpr uint8_t byte2EnableMask = 0xC0;

int set_sensor_dbus_state_s(uint8_t, const char*, const char*);
int set_sensor_dbus_state_y(uint8_t, const char*, const uint8_t);
int find_openbmc_path(uint8_t, dbus_interface_t*);

ipmi::Cc ipmi_sen_get_sdr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                          ipmi_request_t request, ipmi_response_t response,
                          ipmi_data_len_t data_len, ipmi_context_t context);

ipmi::RspType<uint16_t> ipmiSensorReserveSdr();

static const uint16_t FRU_RECORD_ID_START = 256;
static const uint16_t ENTITY_RECORD_ID_START = 512;
static const uint8_t SDR_VERSION = 0x51;
static const uint16_t END_OF_RECORD = 0xFFFF;
static const uint8_t LENGTH_MASK = 0x1F;

/**
 * Get SDR
 */
namespace get_sdr
{

struct GetSdrReq
{
    uint8_t reservationIdLsb;
    uint8_t reservationIdMsb;
    uint8_t recordIdLsb;
    uint8_t recordIdMsb;
    uint8_t offset;
    uint8_t bytesToRead;
} __attribute__((packed));

namespace request
{

inline uint16_t getReservationId(GetSdrReq* req)
{
    return (req->reservationIdLsb + (req->reservationIdMsb << 8));
};

inline uint16_t getRecordId(GetSdrReq* req)
{
    return (req->recordIdLsb + (req->recordIdMsb << 8));
};

} // namespace request

// Response
struct GetSdrResp
{
    uint8_t nextRecordIdLsb;
    uint8_t nextRecordIdMsb;
    uint8_t recordData[64];
} __attribute__((packed));

namespace response
{

inline void setNextRecordId(uint16_t next, GetSdrResp* resp)
{
    resp->nextRecordIdLsb = next & 0xff;
    resp->nextRecordIdMsb = (next >> 8) & 0xff;
};

} // namespace response

// Record header
struct SensorDataRecordHeader
{
    uint8_t recordIdLsb;
    uint8_t recordIdMsb;
    uint8_t sdrVersion;
    uint8_t recordType;
    uint8_t recordLength; // Length not counting the header
} __attribute__((packed));

namespace header
{

inline void setRecordId(int id, SensorDataRecordHeader* hdr)
{
    hdr->recordIdLsb = (id & 0xFF);
    hdr->recordIdMsb = (id >> 8) & 0xFF;
};

} // namespace header

enum SensorDataRecordType
{
    SENSOR_DATA_FULL_RECORD = 0x1,
    SENSOR_DATA_COMPACT_RECORD = 0x2,
    SENSOR_DATA_EVENT_RECORD = 0x3,
    SENSOR_DATA_ENTITY_RECORD = 0x8,
    SENSOR_DATA_FRU_RECORD = 0x11,
    SENSOR_DATA_MGMT_CTRL_LOCATOR = 0x12,
};

// Record key
struct SensorDataRecordKey
{
    uint8_t ownerId;
    uint8_t ownerLun;
    uint8_t sensorNumber;
} __attribute__((packed));

/** @struct SensorDataFruRecordKey
 *
 *  FRU Device Locator Record(key) - SDR Type 11
 */
struct SensorDataFruRecordKey
{
    uint8_t deviceAddress;
    uint8_t fruID;
    uint8_t accessLun;
    uint8_t channelNumber;
} __attribute__((packed));

/** @struct SensorDataEntityRecordKey
 *
 *  Entity Association Record(key) - SDR Type 8
 */
struct SensorDataEntityRecordKey
{
    uint8_t containerEntityId;
    uint8_t containerEntityInstance;
    uint8_t flags;
    uint8_t entityId1;
    uint8_t entityInstance1;
} __attribute__((packed));

namespace key
{

static constexpr uint8_t listOrRangeBit = 7;
static constexpr uint8_t linkedBit = 6;

inline void setOwnerIdIpmb(SensorDataRecordKey* key)
{
    key->ownerId &= ~0x01;
};

inline void setOwnerIdSystemSw(SensorDataRecordKey* key)
{
    key->ownerId |= 0x01;
};

inline void setOwnerIdBmc(SensorDataRecordKey* key)
{
    key->ownerId |= 0x20;
};

inline void setOwnerIdAddress(uint8_t addr, SensorDataRecordKey* key)
{
    key->ownerId &= 0x01;
    key->ownerId |= addr << 1;
};

inline void setOwnerLun(uint8_t lun, SensorDataRecordKey* key)
{
    key->ownerLun &= ~0x03;
    key->ownerLun |= (lun & 0x03);
};

inline void setOwnerLunChannel(uint8_t channel, SensorDataRecordKey* key)
{
    key->ownerLun &= 0x0f;
    key->ownerLun |= ((channel & 0xf) << 4);
};

inline void setFlags(bool isList, bool isLinked, SensorDataEntityRecordKey* key)
{
    key->flags = 0x00;
    if (!isList)
        key->flags |= 1 << listOrRangeBit;

    if (isLinked)
        key->flags |= 1 << linkedBit;
};

} // namespace key

/** @struct GetSensorThresholdsResponse
 *
 *  Response structure for Get Sensor Thresholds command
 */
struct GetSensorThresholdsResponse
{
    uint8_t validMask;           //!< valid mask
    uint8_t lowerNonCritical;    //!< lower non-critical threshold
    uint8_t lowerCritical;       //!< lower critical threshold
    uint8_t lowerNonRecoverable; //!< lower non-recoverable threshold
    uint8_t upperNonCritical;    //!< upper non-critical threshold
    uint8_t upperCritical;       //!< upper critical threshold
    uint8_t upperNonRecoverable; //!< upper non-recoverable threshold
} __attribute__((packed));

// Body - full record
#define FULL_RECORD_ID_STR_MAX_LENGTH 16

static const int FRU_RECORD_DEVICE_ID_MAX_LENGTH = 16;

struct SensorDataFullRecordBody
{
    uint8_t entityId;
    uint8_t entityInstance;
    uint8_t sensorInitialization;
    uint8_t sensorCapabilities; // no macro support
    uint8_t sensorType;
    uint8_t eventReadingType;
    uint8_t supportedAssertions[2];        // no macro support
    uint8_t supportedDeassertions[2];      // no macro support
    uint8_t discreteReadingSettingMask[2]; // no macro support
    uint8_t sensorUnits1;
    uint8_t sensorUnits2Base;
    uint8_t sensorUnits3Modifier;
    uint8_t linearization;
    uint8_t mLsb;
    uint8_t mMsbAndToLerance;
    uint8_t bLsb;
    uint8_t bMsbAndAccuracyLsb;
    uint8_t accuracyAndSensorDirection;
    uint8_t rbExponents;
    uint8_t analogCharacteristicFlags; // no macro support
    uint8_t nominalReading;
    uint8_t normalMax;
    uint8_t normalMin;
    uint8_t sensorMax;
    uint8_t sensorMin;
    uint8_t upperNonrecoverableThreshold;
    uint8_t upperCriticalThreshold;
    uint8_t upperNoncriticalThreshold;
    uint8_t lowerNonrecoverableThreshold;
    uint8_t lowerCriticalThreshold;
    uint8_t lowerNoncriticalThreshold;
    uint8_t positiveThresholdHysteresis;
    uint8_t negativeThresholdHysteresis;
    uint16_t reserved;
    uint8_t oemReserved;
    uint8_t idStringInfo;
    char idString[FULL_RECORD_ID_STR_MAX_LENGTH];
} __attribute__((packed));

/** @struct SensorDataCompactRecord
 *
 *  Compact Sensor Record(body) - SDR Type 2
 */
struct SensorDataCompactRecordBody
{
    uint8_t entityId;
    uint8_t entityInstance;
    uint8_t sensorInitialization;
    uint8_t sensorCapabilities; // no macro support
    uint8_t sensorType;
    uint8_t eventReadingType;
    uint8_t supportedAssertions[2];        // no macro support
    uint8_t supportedDeassertions[2];      // no macro support
    uint8_t discreteReadingSettingMask[2]; // no macro support
    uint8_t sensorUnits1;
    uint8_t sensorUnits2Base;
    uint8_t sensorUnits3Modifier;
    uint8_t record_sharing[2];
    uint8_t positiveThresholdHysteresis;
    uint8_t negativeThresholdHysteresis;
    uint8_t reserved[3];
    uint8_t oemReserved;
    uint8_t idStringInfo;
    char idString[FULL_RECORD_ID_STR_MAX_LENGTH];
} __attribute__((packed));

/** @struct SensorDataEventRecord
 *
 *  Event Only Sensor Record(body) - SDR Type 3
 */
struct SensorDataEventRecordBody
{
    uint8_t entityId;
    uint8_t entityInstance;
    uint8_t sensorType;
    uint8_t eventReadingType;
    uint8_t sensor_record_sharing_1;
    uint8_t sensor_record_sharing_2;
    uint8_t reserved;
    uint8_t oemReserved;
    uint8_t idStringInfo;
    char idString[FULL_RECORD_ID_STR_MAX_LENGTH];
} __attribute__((packed));

/** @struct SensorDataFruRecordBody
 *
 *  FRU Device Locator Record(body) - SDR Type 11
 */
struct SensorDataFruRecordBody
{
    uint8_t reserved;
    uint8_t deviceType;
    uint8_t deviceTypeModifier;
    uint8_t entityID;
    uint8_t entityInstance;
    uint8_t oem;
    uint8_t deviceIDLen;
    char deviceID[FRU_RECORD_DEVICE_ID_MAX_LENGTH];
} __attribute__((packed));

/** @struct SensorDataEntityRecordBody
 *
 *  Entity Association Record(body) - SDR Type 8
 */
struct SensorDataEntityRecordBody
{
    uint8_t entityId2;
    uint8_t entityInstance2;
    uint8_t entityId3;
    uint8_t entityInstance3;
    uint8_t entityId4;
    uint8_t entityInstance4;
} __attribute__((packed));

namespace body
{

inline void setEntityInstanceNumber(uint8_t n, SensorDataFullRecordBody* body)
{
    body->entityInstance &= 1 << 7;
    body->entityInstance |= (n & ~(1 << 7));
};

inline void setEntityPhysicalEntity(SensorDataFullRecordBody* body)
{
    body->entityInstance &= ~(1 << 7);
};

inline void setEntityLogicalContainer(SensorDataFullRecordBody* body)
{
    body->entityInstance |= 1 << 7;
};

inline void sensorScanningState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 0;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 0);
    };
};

inline void eventGenerationState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 1;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 1);
    }
};

inline void initTypesState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 2;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 2);
    }
};

inline void initHystState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 3;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 3);
    }
};

inline void initThreshState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 4;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 4);
    }
};

inline void initEventsState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 5;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 5);
    }
};

inline void initScanningState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 6;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 6);
    }
};

inline void initSettableState(bool enabled, SensorDataFullRecordBody* body)
{
    if (enabled)
    {
        body->sensorInitialization |= 1 << 7;
    }
    else
    {
        body->sensorInitialization &= ~(1 << 7);
    }
};

inline void setPercentage(SensorDataFullRecordBody* body)
{
    body->sensorUnits1 |= 1 << 0;
};

inline void unsetPercentage(SensorDataFullRecordBody* body)
{
    body->sensorUnits1 &= ~(1 << 0);
};

inline void setModifierOperation(uint8_t op, SensorDataFullRecordBody* body)
{
    body->sensorUnits1 &= ~(3 << 1);
    body->sensorUnits1 |= (op & 0x3) << 1;
};

inline void setRateUnit(uint8_t unit, SensorDataFullRecordBody* body)
{
    body->sensorUnits1 &= ~(7 << 3);
    body->sensorUnits1 |= (unit & 0x7) << 3;
};

inline void setAnalogDataFormat(uint8_t format, SensorDataFullRecordBody* body)
{
    body->sensorUnits1 &= ~(3 << 6);
    body->sensorUnits1 |= (format & 0x3) << 6;
};

inline void setM(uint16_t m, SensorDataFullRecordBody* body)
{
    body->mLsb = m & 0xff;
    body->mMsbAndToLerance &= ~(3 << 6);
    body->mMsbAndToLerance |= ((m & (3 << 8)) >> 2);
};

inline void setTolerance(uint8_t tol, SensorDataFullRecordBody* body)
{
    body->mMsbAndToLerance &= ~0x3f;
    body->mMsbAndToLerance |= tol & 0x3f;
};

inline void setB(uint16_t b, SensorDataFullRecordBody* body)
{
    body->bLsb = b & 0xff;
    body->bMsbAndAccuracyLsb &= ~(3 << 6);
    body->bMsbAndAccuracyLsb |= ((b & (3 << 8)) >> 2);
};

inline void setAccuracy(uint16_t acc, SensorDataFullRecordBody* body)
{
    // bottom 6 bits
    body->bMsbAndAccuracyLsb &= ~0x3f;
    body->bMsbAndAccuracyLsb |= acc & 0x3f;
    // top 4 bits
    body->accuracyAndSensorDirection &= 0x0f;
    body->accuracyAndSensorDirection |= ((acc >> 6) & 0xf) << 4;
};

inline void setAccuracyExp(uint8_t exp, SensorDataFullRecordBody* body)
{
    body->accuracyAndSensorDirection &= ~(3 << 2);
    body->accuracyAndSensorDirection |= (exp & 3) << 2;
};

inline void setSensorDir(uint8_t dir, SensorDataFullRecordBody* body)
{
    body->accuracyAndSensorDirection &= ~(3 << 0);
    body->accuracyAndSensorDirection |= (dir & 3);
};

inline void setBexp(uint8_t exp, SensorDataFullRecordBody* body)
{
    body->rbExponents &= 0xf0;
    body->rbExponents |= exp & 0x0f;
};
inline void setRexp(uint8_t exp, SensorDataFullRecordBody* body)
{
    body->rbExponents &= 0x0f;
    body->rbExponents |= (exp & 0x0f) << 4;
};

inline void setIdStrLen(uint8_t len, SensorDataFullRecordBody* body)
{
    body->idStringInfo &= ~(0x1f);
    body->idStringInfo |= len & 0x1f;
};

inline void setIdStrLen(uint8_t len, SensorDataEventRecordBody* body)
{
    body->idStringInfo &= ~(0x1f);
    body->idStringInfo |= len & 0x1f;
};

inline uint8_t getIdStrLen(SensorDataFullRecordBody* body)
{
    return body->idStringInfo & 0x1f;
};

inline void setIdType(uint8_t type, SensorDataFullRecordBody* body)
{
    body->idStringInfo &= ~(3 << 6);
    body->idStringInfo |= (type & 0x3) << 6;
};

inline void setIdType(uint8_t type, SensorDataEventRecordBody* body)
{
    body->idStringInfo &= ~(3 << 6);
    body->idStringInfo |= (type & 0x3) << 6;
};

inline void setDeviceIdStrLen(uint8_t len, SensorDataFruRecordBody* body)
{
    body->deviceIDLen &= ~(LENGTH_MASK);
    body->deviceIDLen |= len & LENGTH_MASK;
};

inline uint8_t getDeviceIdStrLen(SensorDataFruRecordBody* body)
{
    return body->deviceIDLen & LENGTH_MASK;
};

inline void setReadableMask(uint8_t mask, SensorDataFullRecordBody* body)
{
    body->discreteReadingSettingMask[1] = mask & 0x3F;
}

} // namespace body

// More types contained in section 43.17 Sensor Unit Type Codes,
// IPMI spec v2 rev 1.1
enum SensorUnitTypeCodes
{
    SENSOR_UNIT_UNSPECIFIED = 0,
    SENSOR_UNIT_DEGREES_C = 1,
    SENSOR_UNIT_VOLTS = 4,
    SENSOR_UNIT_AMPERES = 5,
    SENSOR_UNIT_WATTS = 6,
    SENSOR_UNIT_JOULES = 7,
    SENSOR_UNIT_RPM = 18,
    SENSOR_UNIT_METERS = 34,
    SENSOR_UNIT_REVOLUTIONS = 41,
};

struct SensorDataFullRecord
{
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataFullRecordBody body;
} __attribute__((packed));

/** @struct SensorDataComapactRecord
 *
 *  Compact Sensor Record - SDR Type 2
 */
struct SensorDataCompactRecord
{
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataCompactRecordBody body;
} __attribute__((packed));

/** @struct SensorDataEventRecord
 *
 *  Event Only Sensor Record - SDR Type 3
 */
struct SensorDataEventRecord
{
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataEventRecordBody body;
} __attribute__((packed));

/** @struct SensorDataFruRecord
 *
 *  FRU Device Locator Record - SDR Type 11
 */
struct SensorDataFruRecord
{
    SensorDataRecordHeader header;
    SensorDataFruRecordKey key;
    SensorDataFruRecordBody body;
} __attribute__((packed));

/** @struct SensorDataEntityRecord
 *
 *  Entity Association Record - SDR Type 8
 */
struct SensorDataEntityRecord
{
    SensorDataRecordHeader header;
    SensorDataEntityRecordKey key;
    SensorDataEntityRecordBody body;
} __attribute__((packed));

} // namespace get_sdr

namespace ipmi
{

namespace sensor
{

/**
 * @brief Map offset to the corresponding bit in the assertion byte.
 *
 * The discrete sensors support up to 14 states. 0-7 offsets are stored in one
 * byte and offsets 8-14 in the second byte.
 *
 * @param[in] offset - offset number.
 * @param[in/out] resp - get sensor reading response.
 */
inline void setOffset(uint8_t offset, ipmi::sensor::GetSensorResponse* resp)
{
    if (offset > 7)
    {
        resp->discreteReadingSensorStates |= 1 << (offset - 8);
    }
    else
    {
        resp->thresholdLevelsStates |= 1 << offset;
    }
}

/**
 * @brief Set the reading field in the response.
 *
 * @param[in] offset - offset number.
 * @param[in/out] resp - get sensor reading response.
 */
inline void setReading(uint8_t value, ipmi::sensor::GetSensorResponse* resp)
{
    resp->reading = value;
}

/**
 * @brief Map the value to the assertion bytes. The assertion states are stored
 *        in 2 bytes.
 *
 * @param[in] value - value to mapped to the assertion byte.
 * @param[in/out] resp - get sensor reading response.
 */
inline void setAssertionBytes(uint16_t value,
                              ipmi::sensor::GetSensorResponse* resp)
{
    resp->thresholdLevelsStates = static_cast<uint8_t>(value & 0x00FF);
    resp->discreteReadingSensorStates = static_cast<uint8_t>(value >> 8);
}

/**
 * @brief Set the scanning enabled bit in the response.
 *
 * @param[in/out] resp - get sensor reading response.
 */
inline void enableScanning(ipmi::sensor::GetSensorResponse* resp)
{
    resp->readingOrStateUnavailable = false;
    resp->scanningEnabled = true;
    resp->allEventMessagesEnabled = false;
}

} // namespace sensor

} // namespace ipmi
