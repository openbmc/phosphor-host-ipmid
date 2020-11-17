#pragma once

#include "common/mapperd_manager.hpp"

#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/test/integration/private_bus.hpp>
#include <string>
#include <vector>

using sdbusplus::SdBusDuration;
using sdbusplus::test::integration::PrivateBus;

namespace openbmc
{

namespace test
{

namespace integration
{

class Expectation
{
  public:
    Expectation() = delete;
    Expectation(const Expectation&) = delete;
    Expectation& operator=(const Expectation&) = delete;
    Expectation(Expectation&&) = delete;
    Expectation& operator=(Expectation&&) = delete;

    Expectation(sdbusplus::bus::bus& bus, const std::string& match);

    ~Expectation();

    void newEvent(sdbusplus::message::message& m);

    void exactly(int times);

    void atLeast(int times);

    void atMost(int times);

  private:
    size_t count;
    sdbusplus::bus::match::match eventMatch;
    int exactlyTimes;
    int atLeastTimes;
    int atMostTimes;
};

class IntegrationTest
{
  public:
    IntegrationTest();

    void runFor(SdBusDuration microseconds);

    std::shared_ptr<Expectation> expectSignal(const std::string& match);

    std::shared_ptr<Expectation>
        expectPropsChangedSignal(const std::string& path,
                                 const std::string& interface);

  protected:
    std::shared_ptr<PrivateBus> mockBus;
    std::shared_ptr<sdbusplus::bus::bus> bus;

    bool isMapperxStarted();

  private:
    MapperxDaemon mapperxDaemon;
    std::vector<std::shared_ptr<Expectation>> expectations;
};

} // namespace integration
} // namespace test
} // namespace openbmc
