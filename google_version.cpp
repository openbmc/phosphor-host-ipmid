#include "google_version.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <string>

#ifndef GBMC_VERSION_PREFIX
#define GBMC_VERSION_PREFIX "gbmc-release-"
#endif

GoogleVersionReader::GoogleVersionReader(ReleaseReader* release_reader) :
    os_release_items_(release_reader->ReadReleaseFile())
{
}

// Parameters renamed here in definition for clarity, whereas it's unambiguous
// in the declaration.
bool GoogleVersionReader::ReadVersion(int* major_out, int* minor_out,
                                      int* point_out, int* subpoint_out)
{
    int major = 0;
    int minor = 0;
    int point = 0;
    int subpoint = 0;

    const std::string version = ReadVersion();
    int num_fields = sscanf(version.c_str(), GBMC_VERSION_PREFIX "%d.%d.%d.%d",
                            &major, &minor, &point, &subpoint);
    // Don't write the output unless parse was successful.
    switch (num_fields)
    {
        case 4:
            *subpoint_out = subpoint;
            [[fallthrough]];
        case 3:
            *point_out = point;
            [[fallthrough]];
        case 2:
            *minor_out = minor;
            *major_out = major;
            break;
        default:
            return false;
    }
    return true;
}

std::string GoogleVersionReader::ReadVersion()
{
    return GetOsReleaseValue("VERSION_ID");
}

std::string GoogleVersionReader::ReadDistro()
{
    return GetOsReleaseValue("ID");
}

// Returns a default-constructed string for map keys that are not found, without
// inserting a value like operator[] does.
std::string GoogleVersionReader::GetOsReleaseValue(const std::string& key) const
{
    auto iter = os_release_items_.find(key);
    if (iter == os_release_items_.end())
    {
        return std::string();
    }
    return iter->second;
}

const char* const OsReleaseReader::kOsReleaseDefaultPath = "/etc/os-release";

OsReleaseReader::OsReleaseReader(const std::string& os_release_path) :
    os_release_path_(os_release_path)
{
}

std::map<std::string, std::string> OsReleaseReader::ReadReleaseFile()
{
    std::map<std::string, std::string> items;
    std::ifstream os_release_file(os_release_path_);
    if (!os_release_file)
    {
        std::cerr << "Failed to open \"" << os_release_path_
                  << "\" for release version\n";
        return items;
    }
    // Matches KEY="VALUE" where the quotes are optional.
    std::regex key_value_re(
        "(\\w+)" // Alphanumeric/underscore chars (group 0)
        "="
        "\"?"   // Optional quote
        "(.*?)" // Any characters, excluding the optional quotes (group 1)
        "\"?"); // Optional quote
    while (os_release_file)
    {
        std::string line;
        std::getline(os_release_file,
                     line); // If this fails, line will be empty.
        std::smatch key_value_match;
        if (std::regex_match(line, key_value_match, key_value_re))
        {
            // First submatch is KEY. Second submatch is VALUE.
            items[key_value_match[1]] = key_value_match[2];
        }
    }
    return items;
}
