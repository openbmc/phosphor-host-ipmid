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

using PropertyType = sdbusplus::message::variant<bool, uint32_t, uint64_t,
                     std::string, std::vector<std::string>>;

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
 *  @return On success return the timestamp of the log entry as number of
 *          seconds from epoch.
 */
std::chrono::seconds getEntryTimeStamp(const std::string& objPath);

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
