#pragma once

#include <ipmid/types.hpp>
#include <memory>
#include <nlohmann/json.hpp>

namespace ipmi
{
namespace sensor
{

/**
 * @brief Owner of the SensorMap.
 */
class SensorMapContainer
{
  public:
    /** Get ahold of the owner. */
    static SensorMapContainer* getContainer();

    /** Get Inventory Object Sensor Maps. */
    const InvObjectIDMap& getInvSensors();

  private:
    SensorMapContainer()
    {
        loadConfigurations();
    }

    void loadConfigurations();
    void loadInvSensors(const nlohmann::json& invJson);

    InvObjectIDMap invSensors;
};

} // namespace sensor
} // namespace ipmi
