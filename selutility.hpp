#pragma once

#include <ipmid/types.hpp>
#include <sdbusplus/server.hpp>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ipmi
{

namespace sel
{

static constexpr auto mapperBusName = "xyz.openbmc_project.ObjectMapper";
static constexpr auto mapperObjPath = "/xyz/openbmc_project/object_mapper";
static constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";

static constexpr auto logWatchPath = "/xyz/openbmc_project/logging";
static constexpr auto logBasePath = "/xyz/openbmc_project/logging/entry";
static constexpr auto logEntryIntf = "xyz.openbmc_project.Logging.Entry";
static constexpr auto logDeleteIntf = "xyz.openbmc_project.Object.Delete";

static constexpr auto logObj = "/xyz/openbmc_project/logging";
static constexpr auto logIntf = "xyz.openbmc_project.Collection.DeleteAll";
static constexpr auto logDeleteAllMethod = "DeleteAll";

static constexpr auto propIntf = "org.freedesktop.DBus.Properties";

using ObjectPaths = std::vector<std::string>;
using PropertyName = std::string;
using Resolved = bool;
using Id = uint32_t;
using Timestamp = uint64_t;
using Message = std::string;
using AdditionalData = std::map<std::string, std::string>;
using PropertyType =
    std::variant<Resolved, Id, Timestamp, Message, AdditionalData>;

static constexpr auto selVersion = 0x51;
static constexpr auto invalidTimeStamp = 0xFFFFFFFF;

static constexpr auto firstEntry = 0x0000;
static constexpr auto lastEntry = 0xFFFF;
static constexpr auto entireRecord = 0xFF;
static constexpr auto selRecordSize = 16;

namespace operationSupport
{
static constexpr bool overflow = false;
static constexpr bool deleteSel = true;
static constexpr bool partialAddSelEntry = false;
static constexpr bool reserveSel = true;
static constexpr bool getSelAllocationInfo = false;
} // namespace operationSupport

/** @struct GetSELEntryRequest
 *
 *  IPMI payload for Get SEL Entry command request.
 */
struct GetSELEntryRequest
{
    uint16_t reservationID; //!< Reservation ID.
    uint16_t selRecordID;   //!< SEL Record ID.
    uint8_t offset;         //!< Offset into record.
    uint8_t readLength;     //!< Bytes to read.
} __attribute__((packed));

constexpr size_t SELRecordLength = 16;

/** @struct SELEventRecord
 *
 * IPMI SEL Event Record
 */
struct SELEventRecord
{
    uint16_t recordID;        //!< Record ID.
    uint8_t recordType;       //!< Record Type.
    uint32_t timeStamp;       //!< Timestamp.
    uint16_t generatorID;     //!< Generator ID.
    uint8_t eventMsgRevision; //!< Event Message Revision.
    uint8_t sensorType;       //!< Sensor Type.
    uint8_t sensorNum;        //!< Sensor Number.
    uint8_t eventType;        //!< Event Dir | Event Type.
    uint8_t eventData1;       //!< Event Data 1.
    uint8_t eventData2;       //!< Event Data 2.
    uint8_t eventData3;       //!< Event Data 3.
} __attribute__((packed));

static_assert(sizeof(SELEventRecord) == SELRecordLength);

/** @struct SELOEMRecordTypeCD
 *
 * IPMI SEL OEM Record - Type C0h-DFh
 */
struct SELOEMRecordTypeCD
{
    uint16_t recordID;         //!< Record ID.
    uint8_t recordType;        //!< Record Type.
    uint32_t timeStamp;        //!< Timestamp.
    uint8_t manufacturerID[3]; //!< Manufacturer ID.
    uint8_t oemDefined[6];     //!< OEM Defined data.
} __attribute__((packed));

static_assert(sizeof(SELOEMRecordTypeCD) == SELRecordLength);

/** @struct SELOEMRecordTypeEF
 *
 * IPMI SEL OEM Record - Type E0h-FFh
 */
struct SELOEMRecordTypeEF
{
    uint16_t recordID;      //!< Record ID.
    uint8_t recordType;     //!< Record Type.
    uint8_t oemDefined[13]; //!< OEM Defined data.
} __attribute__((packed));

static_assert(sizeof(SELOEMRecordTypeEF) == SELRecordLength);

union SELEventRecordFormat
{
    SELEventRecord eventRecord;
    SELOEMRecordTypeCD oemCD;
    SELOEMRecordTypeEF oemEF;
};

/** @struct GetSELEntryResponse
 *
 *  IPMI payload for Get SEL Entry command response.
 */
struct GetSELEntryResponse
{
    uint16_t nextRecordID;      //!< Next RecordID.
    SELEventRecordFormat event; // !< The Event Record.
} __attribute__((packed));

static_assert(sizeof(GetSELEntryResponse) ==
              SELRecordLength + sizeof(uint16_t));

static constexpr auto initiateErase = 0xAA;
static constexpr auto getEraseStatus = 0x00;
static constexpr auto eraseComplete = 0x01;

/** @brief Convert logging entry to SEL
 *
 *  @param[in] objPath - DBUS object path of the logging entry.
 *
 *  @return On success return the response of Get SEL entry command.
 */
GetSELEntryResponse convertLogEntrytoSEL(const std::string& objPath);

/** @brief Get the timestamp of the log entry
 *
 *  @param[in] objPath - DBUS object path of the logging entry.
 *
 *  @return On success return the timestamp of the log entry as number of
 *          seconds from epoch.
 */
std::chrono::seconds getEntryTimeStamp(const std::string& objPath);

/** @brief Read the logging entry object paths
 *
 *  This API would read the logging dbus logging entry object paths and sorting
 *  the filename in the numeric order. The paths is cleared before populating
 *  the object paths.
 *
 *  @param[in,out] paths - sorted list of logging entry object paths.
 *
 *  @note This function is invoked when the Get SEL Info command or the Delete
 *        SEL entry command is invoked. The Get SEL Entry command is preceded
 *        typically by Get SEL Info command, so readLoggingObjectPaths is not
 *        invoked before each Get SEL entry command.
 */
void readLoggingObjectPaths(ObjectPaths& paths);

template <typename T>
std::string toHexStr(const T& data)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (const auto& v : data)
    {
        stream << std::setw(2) << static_cast<int>(v);
    }
    return stream.str();
}
namespace internal
{

/** @brief Convert logging entry to SEL event record
 *
 *  @param[in] objPath - DBUS object path of the logging entry.
 *  @param[in] iter - Iterator to the sensor data corresponding to the logging
 *                    entry
 *
 *  @return On success return the SEL event record, throw an exception in case
 *          of failure.
 */
GetSELEntryResponse prepareSELEntry(
    const std::string& objPath,
    ipmi::sensor::InvObjectIDMap::const_iterator iter);

} // namespace internal

} // namespace sel

} // namespace ipmi
