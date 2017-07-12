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

using ObjectPath = std::string;
using Service = std::string;
using Interfaces = std::vector<std::string>;
using ObjectTree = std::map<ObjectPath, std::map<Service, Interfaces>>;

/** @brief Read the asset tag of the server
 *
 *  @return On success return the asset tag.
 */
std::string readAssetTag();

} // namespace dcmi

#endif
