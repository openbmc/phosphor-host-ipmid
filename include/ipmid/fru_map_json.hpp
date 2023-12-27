#pragma once

#include <ipmid/fruread.hpp>
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

  private:
    FruMapContainer()
    {
        loadConfigurations();
    }

    void loadConfigurations();
    void loadFruMap(const nlohmann::json& fruJson);

    FruMap frus;
};

} // namespace fru
} // namespace ipmi
