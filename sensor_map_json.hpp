#pragma once

#include <ipmid/types.hpp>
#include <nlohmann/json.hpp>

#include <memory>

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

    /** Get Id Info SensorMaps. */
    const IdInfoMap& getIdInfoSensors();

  private:
    SensorMapContainer()
    {
        loadConfigurations();
    }

    void loadConfigurations();
    void loadInvSensors(const nlohmann::json& invJson);
    void loadIdInfoSensors(const nlohmann::json& idInfoJson);
    bool isContains(const nlohmann::json& arrayJson, const std::string& name);

    InvObjectIDMap invSensors;
    IdInfoMap idInfoSensors;
};

} // namespace sensor
} // namespace ipmi
