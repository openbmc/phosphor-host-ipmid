#include "sys_info_param.hpp"

#include "nlohmann/json.hpp"

#include <fstream>
#include <phosphor-logging/log.hpp>

static constexpr const char* encodingString = "encoding";
static constexpr const char* lenString = "stringLen";
static constexpr const char* dataString = "stringDataN";

void to_json(nlohmann::json& j, const IpmiSysInfo& p)
{
    j = nlohmann::json{{encodingString, p.encoding},
                       {lenString, p.stringLen},
                       {dataString, p.stringDataN}};
}

void from_json(const nlohmann::json& j, IpmiSysInfo& p)
{
    uint16_t cnt = 0;
    j.at(encodingString).get_to(p.encoding);
    j.at(lenString).get_to(p.stringLen);
    // from json array to std::array
    for (auto& elem : j.at(dataString))
    {
        p.stringDataN[cnt] = elem;
        cnt++;
    }
}

std::optional<IpmiSysInfo>
    SysInfoParamStore::lookup(uint8_t paramSelector) const
{
    const auto iterator = params.find(paramSelector);
    if (iterator == params.end())
    {
        return std::nullopt;
    }

    auto& callback = iterator->second;
    auto s = callback();
    return s;
}

void SysInfoParamStore::update(uint8_t paramSelector, const IpmiSysInfo& s,
                               bool isNonVolatile)
{
    nlohmann::json jsonData;

    // Add a callback that captures a copy of the string passed and returns it
    // when invoked.
    if (true == isNonVolatile)
    {
        try
        {
            std::string filename = "/var/lib/ipmi/sysinfo" +
                                   std::to_string(paramSelector) + ".json";
            std::ofstream outFile(filename);
            if (!outFile.good())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "can not create JSON file");
                return;
            }

            // format json data
            jsonData = s;
            outFile << jsonData;
            outFile.close();
        }
        catch (std::ios_base::failure& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Exception",
                phosphor::logging::entry("EXCEPTION=%s", e.what()));
        }
    }

    // clang-format off
    update(paramSelector, [s]() {
        return s;
    });
    // clang-format on
}

void SysInfoParamStore::update(uint8_t paramSelector,
                               const std::function<IpmiSysInfo()>& callback)
{
    params[paramSelector] = callback;
}

int SysInfoParamStore::restore(uint8_t paramSelector)
{
    std::string filename =
        "/var/lib/ipmi/sysinfo" + std::to_string(paramSelector) + ".json";
    IpmiSysInfo info;

    try
    {
        std::ifstream infile(filename);
        if (!infile.good())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "file does not exist",
                phosphor::logging::entry("FILE=%s", filename.c_str()));
            return -1;
        }

        nlohmann::json data = nlohmann::json::parse(infile, nullptr, false);
        info = data; // from json to structure
        infile.close();
    }
    catch (std::ios_base::failure& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exception", phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return -1;
    }
    catch (nlohmann::json::parse_error& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Parsing channel cipher suites JSON failed");
        return -1;
    }
    catch (const nlohmann::json::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Json Exception caught.",
            phosphor::logging::entry("MSG:%s", e.what()));
        return -1;
    }

    // clang-format off
    update(paramSelector, [info]() {
        return info;
    });
    // clang-format on
    return 0;
}
