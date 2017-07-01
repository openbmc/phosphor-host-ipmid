#include <algorithm>
#include <map>
#include "ipmi_fru_info_area.hpp"
#include <phosphor-logging/elog.hpp>

using namespace phosphor::logging;
namespace phosphor
{
namespace hostipmi
{

//Property variables
constexpr auto partNumber       = "PartNumber";
constexpr auto serialNumber     = "SerialNumber";
constexpr auto manufacturer     = "manufacturer";
constexpr auto buildDate        = "BuildDate";
constexpr auto model            = "Model";
constexpr auto prettyName       = "PrettyName";
constexpr auto version          = "Version";

//Board info areas
constexpr auto board            = "Board";
constexpr auto chassis          = "Chassis";
constexpr auto product          = "Product";

constexpr auto hexNo1          = "0x";
constexpr auto hexNo2          = "0X";

constexpr auto specVersion              = 0x1;
constexpr auto recordUnitOfMeasurment   = 0x8; //size in bytes
constexpr auto checksumSize             = 0x1; //size in bytes
constexpr auto recordNotPresent         = 0x0;
constexpr auto englishLanguageCode      = 0x0;
constexpr auto typeLengthByteNull       = 0x0;
constexpr auto endOfCustomFields        = 0xC1;
constexpr auto commonHeaderFormatSize   = 0x8; //size in bytes
constexpr auto manfucturingDateSize     = 0x3;
constexpr auto areaSizeOffset           = 0x1;
constexpr auto hexNoSize                = 0x2;

using PropertyMap = std::map<Property, Value>;

/**
 * @brief Format Beginning of Individual IPMI Fru Data Section
 *
 * @param[in] langCode, Language code
 * @param[out] fruAreaData, fru area data
 */
void preFormatProcessing(bool langCode, FruAreaData& fruAreaData)
{
    //Add id for version of FRU Info Storage Spec used
    fruAreaData.emplace_back(specVersion);

    //Add Data Size - 0 as a placeholder, can edit after the data is finalized
    fruAreaData.emplace_back(typeLengthByteNull);

    if (langCode)
    {
        fruAreaData.emplace_back(uint8_t(englishLanguageCode));
    }
}

/**
 * @brief Append checksum of the fru area data
 *
 * @param[out] fruAreaData, fru area data
 */
void appendDataChecksum(FruAreaData& fruAreaData)
{
    uint8_t checksumVal = 0;
    for (const auto& iter : fruAreaData)
    {
        checksumVal += iter;
    }
    // Push the Zero checksum as the last byte of this data
    // This appears to be a simple summation of all the bytes
    fruAreaData.emplace_back(-checksumVal);
}

/**
 * @brief Append padding bytes for the fur area data
 *
 * @param[out] fruAreaData, fru area data
 */
void padData(FruAreaData& fruAreaData)
{
    uint8_t pad = ((fruAreaData.size() + checksumSize) %
                   (recordUnitOfMeasurment));
    if (pad)
    {
        fruAreaData.insert(
            fruAreaData.end(),
            (recordUnitOfMeasurment - pad),
            uint8_t(0));
    }
}

/**
 * @brief Format End of Individual IPMI Fru Data Section
 *
 * @param[out] furAreaData, Fru area info data
 */
void postFormatProcessing(FruAreaData& fruAreaData)
{
    //This area needs to be padded to a multiple of 8 bytes (after checksum)
    padData(fruAreaData);

    //Set size of data info area
    fruAreaData.at(areaSizeOffset) =
        ((fruAreaData.size() + checksumSize) / (recordUnitOfMeasurment));

    //Finally add board info checksum
    appendDataChecksum(fruAreaData);
}

/**
 * @brief Append the data to Fru area if corresponding value found in inventory
 *
 * @param[in] key, key to search for in the property inventory data
 * @param[in] propMap, Key value pairs of inventory data
 * @param[out] fruAreaData, fru area to add the manfufacture date
 */
void appendData(
    const std::string& key, const PropertyMap& propMap,
    FruAreaData& fruAreaData)
{
    auto iter = propMap.find(key);
    if (iter != propMap.end())
    {
        auto value = iter->second;
        //If starts with 0x or 0X remove them
        if((value.compare(0, hexNoSize, hexNo1 )) == 0 ||
           (value.compare( 0, hexNoSize, hexNo2 ) == 0))
        {
            value.erase(0, hexNoSize);
        }
        auto size = static_cast<uint8_t>(value.length());
        fruAreaData.emplace_back(size);
        std::copy(value.begin(), value.end(), std::back_inserter(fruAreaData));
    }
    else
    {
        //set 0 size
        fruAreaData.emplace_back(uint8_t(typeLengthByteNull));
    }
}

/**
 * @brief Builds a section of the common header
 *
 * @param[in] propMap, Property, Value key pairs of inventory data
 * @param[out] fruAreaData, fru area to add the manfufacture date
 */
void appendMfgDate(const PropertyMap& propMap,
                   FruAreaData& fruAreaData)
{
    //MFG Date/Time
    bool blankDate = true;
    auto iter = propMap.find(buildDate);
    if (iter != propMap.end())
    {
        auto& value = iter->second;
        if (value.length() == manfucturingDateSize)
        {
            std::copy(
                value.begin(), value.end(), std::back_inserter(fruAreaData));
            blankDate = false;
        }
    }
    //Blank date
    if (blankDate)
    {
        fruAreaData.emplace_back(uint8_t(0));
        fruAreaData.emplace_back(uint8_t(0));
        fruAreaData.emplace_back(uint8_t(0));
    }
}

/**
 * @brief Builds a section of the common header
 *
 * @param[in] fruAreaSize, size of the fru area to write
 * @param[in] offset, Current offset for data in overall record
 * @param[iout] data, Common Header section data container
 */
void buildCommonHeaderSection(
    const uint32_t& infoAreaSize, uint32_t& offset, FruAreaData& fruArea)
{
    //Check if data for internal use section populated
    if (infoAreaSize == 0)
    {
        //Indicate record not present
        fruArea.emplace_back(recordNotPresent);
    }
    else
    {
        //Place data to define offset to area data section
        fruArea.emplace_back(
            (offset + commonHeaderFormatSize) / (recordUnitOfMeasurment));
        offset += infoAreaSize;
    }
}

/**
 * @brief Builds the Chassis info area data section
 *
 * @param[in] propMap, Property, Value key pairs for chassis info area
 * @return fruAreaData, container with chassis info area
 */
FruAreaData buildChassisInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        //Set formatting data that goes at the beginning of the record
        preFormatProcessing(false, fruAreaData);

        //chassis type
        fruAreaData.emplace_back(uint8_t(0));

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
 * @param[in] propMap, Property, Value key pairs for chassis info area
 * @return fruAreaData, container with board info area
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

        //FRU File ID - Empty
        fruAreaData.emplace_back(typeLengthByteNull);

        // Empty FRU File ID bytes
        fruAreaData.emplace_back(recordNotPresent);

        //End of custom fields
        fruAreaData.emplace_back(endOfCustomFields);

        postFormatProcessing(fruAreaData);
    }
    return fruAreaData;
}

/**
 * @brief Builds the Product info area data section
 *
 * @param[in] propMap, Property, Value key pairs for chassis info area
 * @return fruAreaData, container with product info area data
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

        //FRU File ID - Empty
        fruAreaData.emplace_back(typeLengthByteNull);

        // Empty FRU File ID bytes
        fruAreaData.emplace_back(recordNotPresent);

        //End of custom fields
        fruAreaData.emplace_back(endOfCustomFields);

        postFormatProcessing(fruAreaData);
    }
    return fruAreaData;
}

FruAreaData buildFruAreaData(const FruInventoryData& invData)
{
    PropertyMap chassisPropMap;
    PropertyMap boardPropMap;
    PropertyMap productPropMap;
    for (const auto& inv : invData)
    {
        std::string section = std::get<0>(inv);
        if (section == board)
        {
            boardPropMap.insert(
                std::make_pair(std::get<1>(inv), std::get<2>(inv)));
        }
        else if (section == chassis)
        {
            chassisPropMap.insert(
                std::make_pair(std::get<1>(inv), std::get<2>(inv)));
        }
        else if (section == product)
        {
            productPropMap.insert(
                std::make_pair(std::get<1>(inv), std::get<2>(inv)));
        }
        else
        {
            log<level::ERR>("Unsupported section type");
        }
    }


    FruAreaData combFruArea;
    //Now build common header with data for this FRU Inv Record
    //Use this variable to increment size of header as we go along to determine
    //offset for the subsequent area offsets
    uint32_t curDataOffset = 0;

    //First byte is id for version of FRU Info Storage Spec used
    combFruArea.emplace_back(specVersion);

    //2nd byte is offset to internal use data
    combFruArea.emplace_back(recordNotPresent);

    //3rd byte is offset to chassis data
    auto chassisArea = buildChassisInfoArea(chassisPropMap);
    buildCommonHeaderSection(chassisArea.size(), curDataOffset,
                                      combFruArea);

    //4th byte is offset to board data
    auto boardArea = buildBoardInfoArea(boardPropMap);
    buildCommonHeaderSection(
            boardArea.size(), curDataOffset, combFruArea);

    //5th byte is offset to product data
    auto productArea = buildProductInfoArea(productPropMap);
    buildCommonHeaderSection(productArea.size(), curDataOffset,
                                      combFruArea);

    //6th byte is offset to multirecord data
    combFruArea.emplace_back(recordNotPresent);

    //7th byte is PAD
    padData(combFruArea);

    //8th (Final byte of Header Format) is the checksum
    appendDataChecksum(combFruArea);

    //
    //Combine everything into one full IPMI Fru Inventory Record

    //add chassis use area data
    combFruArea.insert(
            combFruArea.end(), chassisArea.begin(), chassisArea.end());

    //add board area data
    combFruArea.insert(
            combFruArea.end(), boardArea.begin(), boardArea.end());

    //add product use area data
    combFruArea.insert(
            combFruArea.end(), productArea.begin(), productArea.end());

    return combFruArea;
}

} //hostipmi
} //phosphor
