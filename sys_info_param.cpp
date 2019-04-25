#include "sys_info_param.hpp"

#include <fstream>
#include <phosphor-logging/log.hpp>

std::tuple<bool, IpmiSysInfo>
    SysInfoParamStore::lookup(uint8_t paramSelector) const
{
    const auto iterator = params.find(paramSelector);
    IpmiSysInfo dummy = {0};
    if (iterator == params.end())
    {
        return std::make_tuple(false, dummy);
    }

    auto& callback = iterator->second;
    auto s = callback();
    return std::make_tuple(true, s);
}

void SysInfoParamStore::update(uint8_t paramSelector, const IpmiSysInfo& s,
                               bool isNonVolatile)
{
    // Add a callback that captures a copy of the string passed and returns it
    // when invoked.
    if (true == isNonVolatile)
    {
        try
        {
            std::string filename = "/var/lib/ipmi/sysinfo" +
                                   std::to_string(paramSelector) + ".dat";
            std::ofstream outFile(filename, std::ios::out | std::ios::binary |
                                                std::ios::trunc);
            char* buf = const_cast<char*>(reinterpret_cast<const char*>(&s));
            outFile.write(buf, sizeof(IpmiSysInfo));
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
        "/var/lib/ipmi/sysinfo" + std::to_string(paramSelector) + ".dat";
    IpmiSysInfo s;

    try
    {
        std::ifstream infile(filename, std::ios::in | std::ios::binary);
        if (!infile.good())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "file does not exist",
                phosphor::logging::entry("FILE=%s", filename.c_str()));
            return -1;
        }
        if (infile.peek() != std::ifstream::traits_type::eof())
        { // not empty file
            infile.read(reinterpret_cast<char*>(&s), sizeof(IpmiSysInfo));
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
