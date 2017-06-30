#pragma once

#include <cstdint>
#include <sdbusplus/server.hpp>
#include "types.hpp"

namespace ipmi
{

namespace sel
{

static constexpr auto mapperBusName = "xyz.openbmc_project.ObjectMapper";
static constexpr auto mapperObjPath = "/xyz/openbmc_project/object_mapper";
static constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";

static constexpr auto logBasePath = "/xyz/openbmc_project/logging/entry";
static constexpr auto logEntryIntf = "xyz.openbmc_project.Logging.Entry";
static constexpr auto logDeleteIntf = "xyz.openbmc_project.Object.Delete";

static constexpr auto propIntf = "org.freedesktop.DBus.Properties";

using ObjectPaths = std::vector<std::string>;
using PropertyType = sdbusplus::message::variant<bool, uint32_t, uint64_t,
                     std::string, std::vector<std::string>>;

static constexpr auto selVersion = 0x51;
static constexpr auto invalidTimeStamp = 0xFFFFFFFF;
static constexpr auto operationSupport = 0x0A;

/** @struct GetSELInfoResponse
 *
 *  IPMI payload for Get SEL Info command response.
 */
struct GetSELInfoResponse
{
    uint8_t selVersion;             //!< SEL revision.
    uint16_t entries;               //!< Number of log entries in SEL.
    uint16_t freeSpace;             //!< Free Space in bytes.
    uint32_t addTimeStamp;          //!< Most recent addition timestamp.
    uint32_t eraseTimeStamp;        //!< Most recent erase timestamp.
    uint8_t operationSupport;       //!< Operation support.
} __attribute__((packed));

/** @struct GetSELEntryResponse
 *
 *  IPMI payload for Get SEL Entry command response.
 */
struct GetSELEntryResponse
{
    uint16_t nextRecordID;          //!< Next RecordID.
    uint16_t recordID;              //!< Record ID.
    uint8_t recordType;             //!< Record Type.
    uint32_t timeStamp;             //!< Timestamp.
    uint16_t generatorID;           //!< Generator ID.
    uint8_t eventMsgRevision;       //!< Event Message Revision.
    uint8_t sensorType;             //!< Sensor Type.
    uint8_t sensorNum;              //!< Sensor Number.
    uint8_t eventType;              //!< Event Dir | Event Type.
    uint8_t eventData1;             //!< Event Data 1.
    uint8_t eventData2;             //!< Event Data 2.
    uint8_t eventData3;             //!< Event Data 3.
} __attribute__((packed));

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
 *  @return On success return the timestamp of the log entry.
 */
uint32_t getEntryTimeStamp(const std::string& objPath);

/** @brief Read the logging entry object paths
 *
 *  @param[in,out] paths - sorted list of logging entry object paths.
 *
 *  @note This function is invoked when the Get SEL Info command or the Delete
 *        SEL entry command is invoked. The Get SEL Entry command is preceded
 *        typically by Get SEL Info command, so the cache can be utilized for
 *        performance.
 */
void readLoggingObjectPaths(ObjectPaths& paths);

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

}

} // namespace sel

} // namespace ipmi
