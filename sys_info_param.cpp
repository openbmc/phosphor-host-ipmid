#include "sys_info_param.hpp"

#include <fstream>
#include <phosphor-logging/log.hpp>

std::tuple<bool, std::string>
    SysInfoParamStore::lookup(uint8_t paramSelector) const
{
    const auto iterator = params.find(paramSelector);
    if (iterator == params.end())
    {
        return std::make_tuple(false, "");
    }

    auto& callback = iterator->second;
    auto s = callback();
    return std::make_tuple(true, s);
}

void SysInfoParamStore::update(uint8_t paramSelector, const std::string& s,
                               bool isNonVolatile)
{
    // Add a callback that captures a copy of the string passed and returns it
    // when invoked.
    if (true == isNonVolatile)
    {
        try
        {
            std::string filename = "/var/lib/ipmi/sysinfo" +
                                   std::to_string(paramSelector) + ".txt";
            std::ofstream outFile(filename, std::ios::out | std::ios::trunc);
            outFile.write(s.c_str(), s.size());
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
                               const std::function<std::string()>& callback)
{
    params[paramSelector] = callback;
}

int SysInfoParamStore::restore(uint8_t paramSelector)
{
    constexpr size_t buffLen = 64;
    char buf[buffLen];
    std::string filename =
        "/var/lib/ipmi/sysinfo" + std::to_string(paramSelector) + ".txt";
    std::string s = "";

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
        if (infile.peek() != std::ifstream::traits_type::eof())
        { // not empty file
            infile.read(buf, buffLen);
            uint8_t size = infile.gcount();
            if (size > buffLen)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "data from file excced maximum size");
                return -1;
            }
            buf[size] = '\0';
            s = buf;
        }
        infile.close();
    }
    catch (std::ios_base::failure& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exception", phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return -1;
    }
    // clang-format off
    update(paramSelector, [s]() {
        return s;
    });
    // clang-format on
    return 0;
}
