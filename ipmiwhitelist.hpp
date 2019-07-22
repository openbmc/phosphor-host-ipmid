#pragma once

#include <tuple>
#include <utility>
#include <vector>

using netfncmd_tuple = std::tuple<unsigned char, unsigned char, unsigned short>;

extern const std::vector<netfncmd_tuple> whitelist;
