#pragma once

#include <sdbusplus/server.hpp>

std::string getService(sdbusplus::bus::bus& bus,
                       const std::string& intf,
                       const std::string& path);
