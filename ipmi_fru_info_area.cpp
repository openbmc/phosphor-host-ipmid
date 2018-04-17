#include <algorithm>
#include <map>
#include <numeric>

#include <ctime>

#include "ipmi_fru_info_area.hpp"
#include <phosphor-logging/elog.hpp>
namespace ipmi
{
namespace fru
{
using namespace phosphor::logging;

//Property variables
static constexpr auto partNumber       = "PartNumber";
static constexpr auto serialNumber     = "SerialNumber";
static constexpr auto manufacturer     = "Manufacturer";
static constexpr auto buildDate        = "BuildDate";
static constexpr auto model            = "Model";
static constexpr auto prettyName       = "PrettyName";
static constexpr auto version          = "Version";

//Board info areas
static constexpr auto board            = "Board";
static constexpr auto chassis          = "Chassis";
static constexpr auto product          = "Product";

static constexpr auto specVersion              = 0x1;
static constexpr auto recordUnitOfMeasurement   = 0x8; //size in bytes
static constexpr auto checksumSize             = 0x1; //size in bytes
static constexpr auto recordNotPresent         = 0x0;
static constexpr auto englishLanguageCode      = 0x0;
static constexpr auto typeLengthByteNull       = 0x0;
static constexpr auto endOfCustomFields        = 0xC1;
static constexpr auto commonHeaderFormatSize   = 0x8; //size in bytes
static constexpr auto manufacturingDateSize     = 0x3;
static constexpr auto areaSizeOffset           = 0x1;
static constexpr uint8_t typeASCII             = 0xC0;
static constexpr auto maxRecordAttributeValue  = 0x1F;

static constexpr auto secs_from_1970_1996 = 820454400;
static constexpr auto secs_per_min = 60;

/**
 * @brief Format Beginning of Individual IPMI FRU Data Section
 *
 * @param[in] langCode Language code
 * @param[in/out] data FRU area data
 */
void preFormatProcessing(bool langCode, FruAreaData& data)
{
    //Add id for version of FRU Info Storage Spec used
    data.emplace_back(specVersion);

    //Add Data Size - 0 as a placeholder, can edit after the data is finalized
    data.emplace_back(typeLengthByteNull);

    if (langCode)
    {
        data.emplace_back(englishLanguageCode);
    }
}

/**
 * @brief Append checksum of the FRU area data
 *
 * @param[in/out] data FRU area data
 */
void appendDataChecksum(FruAreaData& data)
{
    uint8_t checksumVal = std::accumulate(data.begin(), data.end(), 0);
    // Push the Zero checksum as the last byte of this data
    // This appears to be a simple summation of all the bytes
    data.emplace_back(-checksumVal);
}

/**
 * @brief Append padding bytes for the FRU area data
 *
 * @param[in/out] data FRU area data
 */
void padData(FruAreaData& data)
{
    uint8_t pad = (data.size() + checksumSize) % recordUnitOfMeasurement;
    if (pad)
    {
        data.resize((data.size() + recordUnitOfMeasurement - pad));
    }
}

/**
 * @brief Format End of Individual IPMI FRU Data Section
 *
 * @param[in/out] fruAreaData FRU area info data
 */
void postFormatProcessing(FruAreaData& data)
{
    //This area needs to be padded to a multiple of 8 bytes (after checksum)
    padData(data);

    //Set size of data info area
    data.at(areaSizeOffset) = (data.size() + checksumSize) /
        (recordUnitOfMeasurement);

    //Finally add area checksum
    appendDataChecksum(data);
}

/**
 * @brief Read property value from inventory and append to the FRU area data
 *
 * @param[in] key key to search for in the property inventory data
 * @param[in] propMap map of property values
 * @param[in,out] data FRU area data to be appended
 */
void appendData(const Property& key, const PropertyMap& propMap,
                FruAreaData& data)
{
    auto iter = propMap.find(key);
    if (iter != propMap.end())
    {
        auto value = iter->second;
        //If starts with 0x or 0X remove them
        //ex: 0x123a just take 123a
        if ((value.compare(0, 2, "0x")) == 0 ||
           (value.compare(0, 2, "0X") == 0))
        {
            value.erase(0, 2);
        }

        // 5 bits for length
        // if length is greater then 31(2^5) bytes then trim the data to 31 bytess.
        auto valueLength =  (value.length() > maxRecordAttributeValue) ?
            maxRecordAttributeValue : value.length();
        // 2 bits for type
        // Set the type to ascii
        uint8_t typeLength = valueLength | ipmi::fru::typeASCII;

        data.emplace_back(typeLength);
        std::copy(value.begin(),
                  value.begin() + valueLength,
                  std::back_inserter(data));
    }
    else
    {
        //set 0 size
        data.emplace_back(typeLengthByteNull);
    }
}


/**
 * @brief Appends Build Date
 *
 * @param[in] propMap map of property values
 * @param[in/out] data FRU area to add the manfufacture date
 */
void appendMfgDate(const PropertyMap& propMap, FruAreaData& data)
{
    //MFG Date/Time
    auto iter = propMap.find(buildDate);
    if (iter != propMap.end())
    {
        tm time = {};
        strptime(iter->second.c_str(), "%F - %H:%M:%S", &time);
        time_t raw = mktime(&time);

        // From FRU Spec:
        // "Mfg. Date / Time
        // Number of minutes from 0:00 hrs 1/1/96.
        // LSbyte first (little endian)
        // 00_00_00h = unspecified."
        if (raw > secs_from_1970_1996)
        {
            raw -= secs_from_1970_1996;
            raw /= secs_per_min;
            uint8_t fru_raw[3];
            fru_raw[0] = raw & 0xFF;
            fru_raw[1] = (raw >> 8) & 0xFF;
            fru_raw[2] = (raw >> 16) & 0xFF;
            std::copy(fru_raw, fru_raw + 3, std::back_inserter(data));
            return;
        }
        fprintf(stderr, "MgfDate invalid date: %u secs since UNIX epoch\n",
                static_cast<unsigned int>(raw));
    }
    //Blank date
    data.emplace_back(0);
    data.emplace_back(0);
    data.emplace_back(0);
}

/**
 * @brief Builds a section of the common header
 *
 * @param[in] infoAreaSize size of the FRU area to write
 * @param[in] offset Current offset for data in overall record
 * @param[in/out] data Common Header section data container
 */
void buildCommonHeaderSection(
    const uint32_t& infoAreaSize, uint16_t& offset, FruAreaData& data)
{
    //Check if data for internal use section populated
    if (infoAreaSize == 0)
    {
        //Indicate record not present
        data.emplace_back(recordNotPresent);
    }
    else
    {
        // offset should be multiple of 8.
        auto remainder = offset % recordUnitOfMeasurement;
        // add the padding bytes in the offset so that offset
        // will be multiple of 8 byte.
        offset += (remainder > 0) ? recordUnitOfMeasurement - remainder : 0;
        //Place data to define offset to area data section
        data.emplace_back(offset / recordUnitOfMeasurement);

        offset += infoAreaSize;
    }
}

/**
 * @brief Builds the Chassis info area data section
 *
 * @param[in] propMap map of properties for chassis info area
 * @return FruAreaData container with chassis info area
 */
FruAreaData buildChassisInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        //Set formatting data that goes at the beginning of the record
        preFormatProcessing(false, fruAreaData);

        //chassis type
        fruAreaData.emplace_back(0);

        //Chasiss part number, in config.yaml it is configured as model
        appendData(model, propMap, fruAreaData);

        //Board serial number
        appendData(serialNumber, propMap, fruAreaData);

        //Indicate End of Custom Fields
        fruAreaData.emplace_back(endOfCustomFields);

        //Complete record data formatting
        postFormatProcessing(fruAreaData);
    }
    return fruAreaData;
}

/**
 * @brief Builds the Board info area data section
 *
 * @param[in] propMap map of properties for board info area
 * @return FruAreaData container with board info area
 */
FruAreaData buildBoardInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        preFormatProcessing(true, fruAreaData);

        //Manufacturing date
        appendMfgDate(propMap, fruAreaData);

        //manufacturer
        appendData(manufacturer, propMap, fruAreaData);

        //Product name/Pretty name
        appendData(prettyName, propMap, fruAreaData);

        //Board serial number
        appendData(serialNumber, propMap, fruAreaData);

        //Board part number
        appendData(partNumber, propMap, fruAreaData);

        //FRU File ID
        appendData(version, propMap, fruAreaData);

        //End of custom fields
        fruAreaData.emplace_back(endOfCustomFields);

        postFormatProcessing(fruAreaData);
    }
    return fruAreaData;
}

/**
 * @brief Builds the Product info area data section
 *
 * @param[in] propMap map of FRU properties for Board info area
 * @return FruAreaData container with product info area data
 */
FruAreaData buildProductInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        //Set formatting data that goes at the beginning of the record
        preFormatProcessing(true, fruAreaData);

        //manufacturer
        appendData(manufacturer, propMap, fruAreaData);

        //Product name/Pretty name
        appendData(prettyName, propMap, fruAreaData);

        //Product part/model number
        appendData(model, propMap, fruAreaData);

        //Product version
        appendData(version, propMap, fruAreaData);

        //Serial Number
        appendData(serialNumber, propMap, fruAreaData);

        //Add Asset Tag
        fruAreaData.emplace_back(recordNotPresent);

        //FRU File ID
        appendData(version, propMap, fruAreaData);

        //End of custom fields
        fruAreaData.emplace_back(endOfCustomFields);

        postFormatProcessing(fruAreaData);
    }
    return fruAreaData;
}

FruAreaData buildFruAreaData(const FruInventoryData& inventory)
{
    FruAreaData combFruArea{};
    //Now build common header with data for this FRU Inv Record
    //Use this variable to increment size of header as we go along to determine
    //offset for the subsequent area offsets
    uint16_t curDataOffset = commonHeaderFormatSize;
    //First byte is id for version of FRU Info Storage Spec used
    combFruArea.emplace_back(specVersion);

    //2nd byte is offset to internal use data
    combFruArea.emplace_back(recordNotPresent);

    //3rd byte is offset to chassis data
    FruAreaData chassisArea;
    auto chassisIt = inventory.find(chassis);
    if (chassisIt != inventory.end())
    {
        chassisArea = std::move(buildChassisInfoArea(chassisIt->second));
    }
    // update the offset to chassis data.
    buildCommonHeaderSection(chassisArea.size(), curDataOffset, combFruArea);

    //4th byte is offset to board data
    FruAreaData boardArea;
    auto boardIt = inventory.find(board);
    if (boardIt != inventory.end())
    {
        boardArea = std::move(buildBoardInfoArea(boardIt->second));
    }
    // update the offset to the board data.
    buildCommonHeaderSection(boardArea.size(), curDataOffset, combFruArea);

    //5th byte is offset to product data
    FruAreaData prodArea;
    auto prodIt = inventory.find(product);
    if (prodIt != inventory.end())
    {
        prodArea = std::move(buildProductInfoArea(prodIt->second));
    }
    // update the offset to the product data.
    buildCommonHeaderSection(prodArea.size(), curDataOffset, combFruArea);

    //6th byte is offset to multirecord data
    combFruArea.emplace_back(recordNotPresent);

    //7th byte is PAD
    combFruArea.emplace_back(recordNotPresent);

    //8th (Final byte of Header Format) is the checksum
    appendDataChecksum(combFruArea);

    //Combine everything into one full IPMI FRU specification Record
    //add chassis use area data
    combFruArea.insert(
            combFruArea.end(), chassisArea.begin(), chassisArea.end());

    //add board area data
    combFruArea.insert(combFruArea.end(), boardArea.begin(), boardArea.end());

    //add product use area data
    combFruArea.insert(combFruArea.end(), prodArea.begin(), prodArea.end());

    return combFruArea;
}

} //fru
} //ipmi
