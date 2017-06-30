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

uint32_t getEntryTimeStamp(const std::string& service,
                           const std::string& objPath);

} // namespace sel

} // namespace ipmi
