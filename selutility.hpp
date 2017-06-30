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
static constexpr auto mapperIface = "xyz.openbmc_project.ObjectMapper";

static constexpr auto logBasePath = "/xyz/openbmc_project/logging/entry";
static constexpr auto logEntryIface = "xyz.openbmc_project.Logging.Entry";
static constexpr auto logDeleteIface = "xyz.openbmc_project.Object.Delete";

static constexpr auto systemRecord = 0x02;
static constexpr auto generator = 0x2000;
static constexpr auto evmRev = 0x04;

using ObjectTree = std::map<std::string, std::map<std::string,
                            std::vector<std::string>>>;
using ObjectPaths = std::vector<std::string>;

using AssociationList = std::vector<std::tuple<
                        std::string, std::string, std::string>>;

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

/** @struct GetSELEntryRequest
 *
 *  IPMI payload for Get SEL Entry command request.
 */
struct GetSELEntryRequest
{
    uint16_t reservationID;         //!< Reservation ID.
    uint16_t selRecordID;           //!< SEL Record ID.
    uint8_t offset;                 //!< Offset into record.
    uint8_t readLength;             //!< Bytes to read.
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
    uint8_t evmRev;                 //!< EvM Rev.
    uint8_t sensorType;             //!< Sensor Type.
    uint8_t sensorNum;              //!< Sensor Number.
    uint8_t eventType;              //!< Event Dir | Event Type.
    uint8_t eventData1;             //!< Event Data 1.
    uint8_t eventData2;             //!< Event Data 2.
    uint8_t eventData3;             //!< Event Data 3.
} __attribute__((packed));

/** @struct DeleteSELEntryRequest
 *
 *  IPMI payload for Delete SEL Entry command request.
 */
struct DeleteSELEntryRequest
{
    uint16_t reservationID;         //!< Reservation ID.
    uint16_t selRecordID;           //!< SEL Record ID.
} __attribute__((packed));


uint32_t getEntryTimeStamp(const std::string& service,
                           const std::string& objPath);

GetSELEntryResponse convertErrorLogtoSEL(const std::string& objPath);

} // namespace sel

} // namespace ipmi
