#ifndef __HOST_IPMI_DCMI_HANDLER_H__
#define __HOST_IPMI_DCMI_HANDLER_H__

// IPMI commands for net functions.
enum ipmi_netfn_sen_cmds
{
    // Get capability bits
    IPMI_CMD_DCMI_GET_POWER = 0x03,
    
};

namespace dcmi
{

static constexpr auto assetTagPath = "/xyz/openbmc_project/inventory/system";
static constexpr auto propIntf = "org.freedesktop.DBus.Properties";
static constexpr auto assetTagIntf =
        "xyz.openbmc_project.Inventory.Decorator.AssetTag";
static constexpr auto assetTagProp = "AssetTag";

} // namespace dcmi

#endif
