#pragma once
#include "ipmi_fru_info_area.hpp"

#include <sdbusplus/bus.hpp>
#include <string>

namespace ipmi
{
namespace fru
{
using FRUId = uint8_t;
using FRUAreaMap = std::map<FRUId, FruAreaData>;

static constexpr auto XYZ_PREFIX = "/xyz/openbmc_project/";
static constexpr auto INV_INTF = "xyz.openbmc_project.Inventory.Manager";
static constexpr auto OBJ_PATH = "/xyz/openbmc_project/inventory";
static constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";
static constexpr auto invItemIntf = "xyz.openbmc_project.Inventory.Item";
static constexpr auto itemPresentProp = "Present";

/**
 * @brief Get fru area data as per IPMI specification
 *
 * @param[in] fruNum FRU ID
 *
 * @return FRU area data as per IPMI specification
 */
const FruAreaData& getFruAreaData(const FRUId& fruNum);

/**
 * @brief Register callback handler into DBUS for PropertyChange events
 *
 * @return negative value on failure
 */
int registerCallbackHandler();
} // namespace fru
} // namespace ipmi
