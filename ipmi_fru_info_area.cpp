#include <algorithm>
#include "ipmi_fru_info_area.hpp"

namespace phosphor
{
namespace hostipmi
{
namespace details
{
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

//Creates a 2's complement checksum at the end of the given data vector
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

void postFormatProcessing(FruAreaData& fruAreaData)
{
    //This area needs to be padded to a multiple of 8 bytes (after checksum)
    padData(fruAreaData);

    //Set size of data info area
    fruAreaData.at(areaSizeOffset) =
        ((fruAreaData.size() + checksumSize) /
         (recordUnitOfMeasurment));

    //Finally add board info checksum
    appendDataChecksum(fruAreaData);
}

void appendData(
    const std::string& key, const PropertyMap& propMap,
    FruAreaData& fruAreaData)
{
    auto iter = propMap.find(key);
    if (iter != propMap.end())
    {
        auto& value = iter->second;
        uint8_t size = value.length();
        fruAreaData.emplace_back(size);
        std::copy(value.begin(), value.end(), std::back_inserter(fruAreaData));
    }
    else
    {
        //set 0 size
        fruAreaData.emplace_back(uint8_t(typeLengthByteNull));
    }
}

void appendMfgDate(const PropertyMap& propMap,
                   FruAreaData& fruAreaData)
{
    //MFG Date/Time
    bool blankDate = true;
    auto iter = propMap.find(BUILD_DATE);
    if (iter != propMap.end())
    {
        auto& value = iter->second;
        if (value.length() == manfucturingDateSize)
        {
            std::copy(
                value.begin(), value.end(), std::back_inserter(fruAreaData));
            blankDate = false;
        }
        else
        {
            throw std::runtime_error("Invalid date format set");
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

// update chassis info area
FruAreaData buildChassisInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        //Set formatting data that goes at the beginning of the record
        preFormatProcessing(false, fruAreaData);

        //chassis type
        fruAreaData.emplace_back(uint8_t(0));

        //Chasiss part number, in config.yaml it is configured as MODEL
        appendData(MODEL, propMap, fruAreaData);

        //Board serial number
        appendData(SERIAL_NUMBER, propMap, fruAreaData);

        //Indicate End of Custom Fields
        fruAreaData.emplace_back(endOfCustomFields);

        //Complete record data formatting
        postFormatProcessing(fruAreaData);
    }
    return fruAreaData;
}

// update board info area
FruAreaData buildBoardInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        preFormatProcessing(true, fruAreaData);

        //Manufacturing date
        appendMfgDate(propMap, fruAreaData);

        //Manufacturer
        appendData(MANUFACTURER, propMap, fruAreaData);

        //Product name/Pretty name
        appendData(PRETTY_NAME, propMap, fruAreaData);

        //Board serial number
        appendData(SERIAL_NUMBER, propMap, fruAreaData);

        //Board part number
        appendData(PART_NUMBER, propMap, fruAreaData);

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

// build product info area
FruAreaData buildProductInfoArea(const PropertyMap& propMap)
{
    FruAreaData fruAreaData;
    if (!propMap.empty())
    {
        //Set formatting data that goes at the beginning of the record
        preFormatProcessing(true, fruAreaData);

        //Manufacturer
        appendData(MANUFACTURER, propMap, fruAreaData);

        //Product name/Pretty name
        appendData(PRETTY_NAME, propMap, fruAreaData);

        //Product part/Model number
        appendData(MODEL, propMap, fruAreaData);

        //Product version
        appendData(VERSION, propMap, fruAreaData);

        //Serial Number
        appendData(SERIAL_NUMBER, propMap, fruAreaData);

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
} //details

details::FruAreaData buildFruAreaData(const details::FruInventoryData& invData)
{
    details::PropertyMap chassisPropMap;
    details::PropertyMap boardPropMap;
    details::PropertyMap productPropMap;
    for (const auto& inv : invData)
    {
        std::string section = std::get<0>(inv);
        if (section == details::BOARD)
        {
            boardPropMap.insert(
                std::make_pair(std::get<1>(inv), std::get<2>(inv)));
        }
        else if (section == details::CHASSIS)
        {
            chassisPropMap.insert(
                std::make_pair(std::get<1>(inv), std::get<2>(inv)));
        }
        else if (section == details::PRODUCT)
        {
            productPropMap.insert(
                std::make_pair(std::get<1>(inv), std::get<2>(inv)));
        }
        else
        {
            throw std::runtime_error("Unsupported section type " + section);
        }
    }


    details::FruAreaData combFruArea;
    //Now build common header with data for this FRU Inv Record
    //Use this variable to increment size of header as we go along to determine
    //offset for the subsequent area offsets
    uint32_t curDataOffset = 0;

    //First byte is id for version of FRU Info Storage Spec used
    combFruArea.emplace_back(details::specVersion);

    //2nd byte is offset to internal use data
    combFruArea.emplace_back(details::recordNotPresent);

    //3rd byte is offset to chassis data
    auto chassisArea = details::buildChassisInfoArea(chassisPropMap);
    details::buildCommonHeaderSection(chassisArea.size(), curDataOffset,
                                      combFruArea);

    //4th byte is offset to board data
    auto boardArea = details::buildBoardInfoArea(boardPropMap);
    details::buildCommonHeaderSection(boardArea.size(), curDataOffset, combFruArea);

    //5th byte is offset to product data
    auto productArea = details::buildProductInfoArea(productPropMap);
    details::buildCommonHeaderSection(productArea.size(), curDataOffset,
                                      combFruArea);

    //6th byte is offset to multirecord data
    combFruArea.emplace_back(details::recordNotPresent);

    //7th byte is PAD
    details::padData(combFruArea);

    //8th (Final byte of Header Format) is the checksum
    details::appendDataChecksum(combFruArea);

    //
    //Combine everything into one full IPMI Fru Inventory Record

    //add chassis use area data
    combFruArea.insert(combFruArea.end(), chassisArea.begin(), chassisArea.end());

    //add board area data
    combFruArea.insert(combFruArea.end(), boardArea.begin(), boardArea.end());

    //add product use area data
    combFruArea.insert(combFruArea.end(), productArea.begin(), productArea.end());

    return combFruArea;
}

} //hostipmi
} //phosphor
