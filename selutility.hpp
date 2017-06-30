#pragma once

#include <cstdint>
#include <map>
#include <vector>

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
static constexpr auto propId = "Id";
static constexpr auto propResolved = "Resolved";
static constexpr auto propTimeStamp = "Timestamp";

static constexpr auto assocIntf = "org.openbmc.Associations";
static constexpr auto assocProp = "associations";

using namespace std::string_literals;
static const auto  systemSensor = "/xyz/openbmc_project/inventory/system"s;
static const auto boardSensor =
        "/xyz/openbmc_project/inventory/system/chassis/motherboard"s;

using AssociationList = std::vector<std::tuple<
                        std::string, std::string, std::string>>;
using ObjectPaths = std::vector<std::string>;

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

static constexpr auto systemEventRecord = 0x02;
static constexpr auto generatorID = 0x2000;
static constexpr auto evmRev = 0x04;
static constexpr auto deassertEvent = 0x80;

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
    uint8_t evmRev;                 //!< EvM Rev.
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
uint32_t getEntryTimeStamp(const std::string& objPath);;

} // namespace sel

} // namespace ipmi
