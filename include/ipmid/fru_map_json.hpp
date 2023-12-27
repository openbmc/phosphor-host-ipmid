#pragma once

#include <ipmid/fruread.hpp>
#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

namespace ipmi
{
namespace fru
{

/**
 * @brief Owner of the FruMap.
 */
class FruMapContainer
{
  public:
    /** Get ahold of the owner. */
    static FruMapContainer* getContainer();

    /** Get Fru Maps. */
    const FruMap& getFruMap();

    /** Get Fru Extras Maps. */
    const ExtrasMap& getFruExtras();

  private:
    FruMapContainer()
    {
        loadConfigurations();
    }

    void loadConfigurations();
    void loadFruMap(const nlohmann::json& fruJson);
    void loadFruExtras(const nlohmann::json& extrasJson);
    Value jsonEntryToDbusVal(const std::string& type,
                             const nlohmann::json& value);

    FruMap frus;
    ExtrasMap extras;
};

} // namespace fru
} // namespace ipmi
