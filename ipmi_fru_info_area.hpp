#pragma once

#include <string>
#include <map>
#include <vector>

namespace phosphor
{
namespace hostipmi
{

using FruAreaData = std::vector<uint8_t>;
using Section = std::string;
using Value = std::string;
using Property = std::string;
using FruInventoryData = std::vector<std::tuple<Section, Property, Value>>;

namespace details
{
constexpr auto specVersion               = 0x1;
constexpr auto recordUnitOfMeasurment    = 0x8; //size in bytes
constexpr auto checksumSize              = 0x1; //size in bytes
constexpr auto recordNotPresent          = 0x0;
constexpr auto englishLanguageCode       = 0x0;
constexpr auto typeLengthByteNull        = 0x0;
constexpr auto endOfCustomFields         = 0xC1;
constexpr auto commonHeaderFormatSize    = 0x8; //size in bytes
constexpr auto manfucturingDateSize      = 0x3;
constexpr auto areaSizeOffset            = 0x1;

//Property variables
constexpr auto PART_NUMBER      = "PartNumber";
constexpr auto SERIAL_NUMBER    = "SerialNumber";
constexpr auto MANUFACTURER     = "Manufacturer";
constexpr auto BUILD_DATE = "BuildDate";
constexpr auto MODEL = "Model";
constexpr auto PRETTY_NAME = "PrettyName";
constexpr auto VERSION = "Version";

//Board info areas
constexpr auto BOARD = "Board";
constexpr auto CHASSIS = "Chassis";
constexpr auto PRODUCT = "Product";

using PropertyMap = std::map<Property, Value>;

/**
 * @brief Format Beginning of Individual IPMI Fru Data Section
 *
 * @param[in] langCode, Language code
 * @param[out] fruAreaData, fru area data
 */
void preFormatProcessing(bool langCode, FruAreaData& fruAreaData);

/**
 * @brief Append checksum of the fru area data
 *
 * @param[out] fruAreaData, fru area data
 */
void appendDataChecksum(FruAreaData& fruAreaData);

/**
 * @brief Append padding bytes for the fur area data
 *
 * @param[out] fruAreaData, fru area data
 */
void padData(FruAreaData& fruAreaData);

/**
 * @brief Format End of Individual IPMI Fru Data Section
 *
 * @param[out] furAreaData, Fru area info data
 */
void postFormatProcessing(FruAreaData& fruAreaData);

/**
 * @brief Append the data to Fru area if corresponding value found in inventory
 *
 * @param[in] key, key to search for in the property inventory data
 * @param[in] propMap, Key value pairs of inventory data
 * @param[out] fruAreaData, fru area to add the manfufacture date
 */
void appendData(
    const std::string& key, const PropertyMap& propMap,
    FruAreaData& fruAreaData);

/**
 * @brief Builds a section of the common header
 *
 * @param[in] propMap, Property, Value key pairs of inventory data
 * @param[out] fruAreaData, fru area to add the manfufacture date
 */
void appendMfgDate(const PropertyMap& propMap,
                   FruAreaData& fruAreaData);

/**
 * @brief Builds a section of the common header
 *
 * @param[in] fruAreaSize, size of the fru area to write
 * @param[in] offset, Current offset for data in overall record
 * @param[iout] data, Common Header section data container
 */
void buildCommonHeaderSection(
    const uint32_t& infoAreaSize, uint32_t& offset, FruAreaData& fruArea);

/**
 * @brief Builds the Chassis info area data section
 *
 * @param[in] propMap, Property, Value key pairs for chassis info area
 * @return fruAreaData, container with chassis info area
 */
FruAreaData buildChassisInfoArea(const PropertyMap& propMap);

/**
 * @brief Builds the Board info area data section
 *
 * @param[in] propMap, Property, Value key pairs for chassis info area
 * @return fruAreaData, container with board info area
 */
FruAreaData buildBoardInfoArea(const PropertyMap& propMap);

/**
 * @brief Builds the Product info area data section
 *
 * @param[in] propMap, Property, Value key pairs for chassis info area
 * @return fruAreaData, container with product info area data
 */
FruAreaData buildProductInfoArea(const PropertyMap& propMap);
} //details

/**
 * @brief Builds Fru area data section
 *
 * @param[in] invData, Property, Value key pairs for chassis info area
 * @return fruArea fru area data
 */
FruAreaData buildFruAreaData(const FruInventoryData& invData);
} //hostipmi
} //phosphor

