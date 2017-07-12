#ifndef __HOST_IPMI_DCMI_HANDLER_H__
#define __HOST_IPMI_DCMI_HANDLER_H__

#include <map>
#include <string>
#include <vector>

// IPMI commands for net functions.
enum ipmi_netfn_sen_cmds
{
    // Get capability bits
    IPMI_CMD_DCMI_GET_POWER = 0x03,
    IPMI_CMD_DCMI_GET_ASSET_TAG = 0x06,
    IPMI_CMD_DCMI_SET_ASSET_TAG = 0x08,
};

namespace dcmi
{

static constexpr auto mapperBusName = "xyz.openbmc_project.ObjectMapper";
static constexpr auto mapperObjPath = "/xyz/openbmc_project/object_mapper";
static constexpr auto mapperIface = "xyz.openbmc_project.ObjectMapper";

static constexpr auto inventoryRoot = "/xyz/openbmc_project/inventory/";
static constexpr auto propIntf = "org.freedesktop.DBus.Properties";
static constexpr auto assetTagIntf =
        "xyz.openbmc_project.Inventory.Decorator.AssetTag";
static constexpr auto assetTagProp = "AssetTag";

using ObjectTree = std::map<std::string, std::map<std::string,
                            std::vector<std::string>>>;

static constexpr auto groupExtId = 0xDC;

static constexpr auto assetTagMaxOffset = 62;
static constexpr auto assetTagMaxSize = 63;
static constexpr auto maxBytes = 16;

/** @struct GetAssetTagRequest
 *
 *  DCMI payload for Get Asset Tag command request.
 */
struct GetAssetTagRequest
{
    uint8_t groupID;            //!< Group extension identification.
    uint8_t offset;             //!< Offset to read.
    uint8_t bytes;              //!< Number of bytes to read.
} __attribute__((packed));

/** @struct GetAssetTagResponse
 *
 *  DCMI payload for Get Asset Tag command response.
 */
struct GetAssetTagResponse
{
    uint8_t groupID;            //!< Group extension identification.
    uint8_t tagLength;          //!< Total asset tag length.
} __attribute__((packed));

/** @struct SetAssetTagRequest
 *
 *  DCMI payload for Set Asset Tag command request.
 */
struct SetAssetTagRequest
{
    uint8_t groupID;            //!< Group extension identification.
    uint8_t offset;             //!< Offset to write.
    uint8_t bytes;              //!< Number of bytes to write.
} __attribute__((packed));

/** @struct SetAssetTagResponse
 *
 *  DCMI payload for Set Asset Tag command response.
 */
struct SetAssetTagResponse
{
    uint8_t groupID;            //!< Group extension identification.
    uint8_t tagLength;          //!< Total asset tag length.
} __attribute__((packed));

/** @brief Read the asset tag of the server
 *
 *  @return On success return the asset tag.
 */
std::string readAssetTag();

/** @brief Write the asset tag to the asset tag DBUS property
 *
 *  @param[in] assetTag - Asset Tag to be written to the property.
 */
void writeAssetTag(const std::string& assetTag);

} // namespace dcmi

#endif
