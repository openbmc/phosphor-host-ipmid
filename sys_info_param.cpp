#include "sys_info_param.hpp"

bool SysInfoParamStore::lookup(uint8_t paramSelector,
                               std::string* s) const
{
    const auto iterator = params.find(paramSelector);
    if (iterator == params.end())
    {
        return false;
    }
    if (s != nullptr) {
      auto& callback = iterator->second;
      *s = callback();
    }
    return true;
}

void SysInfoParamStore::update(uint8_t paramSelector,
                               const std::string& s)
{
    // Add a callback that captures a copy of the string passed and returns it
    // when invoked.
    update(paramSelector, [s]()
    {
        return s;
    });
}

void SysInfoParamStore::update(uint8_t paramSelector,
                               const std::function<std::string()>& callback)
{
    params[paramSelector] = callback;
}
