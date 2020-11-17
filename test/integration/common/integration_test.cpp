#include "common/integration_test.hpp"

#include "common/mapperd_manager.hpp"

#include <memory>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/test/integration/test_timer.hpp>
#include <string>

#include <gtest/gtest.h>

namespace openbmc
{

namespace test
{

namespace integration
{

Expectation::Expectation(sdbusplus::bus::bus& bus, const std::string& match) :
    count(0),
    eventMatch(bus, match,
               std::move([this](sdbusplus::message::message& message) {
                   this->newEvent(message);
               })),
    exactlyTimes(-1), atLeastTimes(-1), atMostTimes(-1)
{
}

Expectation::~Expectation()
{
    if (exactlyTimes != -1)
    {
        EXPECT_EQ(count, ((size_t)exactlyTimes));
    }
    if (atLeastTimes != -1)
    {
        EXPECT_GE(count, ((size_t)atLeastTimes));
    }
    if (atMostTimes != -1)
    {
        EXPECT_LE(count, ((size_t)atMostTimes));
    }
}

void Expectation::newEvent(sdbusplus::message::message& m)
{
    count++;
}

void Expectation::exactly(int times)
{
    exactlyTimes = times;
}

void Expectation::atLeast(int times)
{
    atLeastTimes = times;
}

void Expectation::atMost(int times)
{
    atMostTimes = times;
}

IntegrationTest::IntegrationTest()
{
    mockBus = std::make_shared<PrivateBus>();
    mapperxDaemon.start();
    mockBus->registerService("xyz.openbmc_project.test.Integration");
    bus = mockBus->getBus("xyz.openbmc_project.test.Integration");
}

std::shared_ptr<Expectation>
    IntegrationTest::expectSignal(const std::string& match)
{
    auto e = std::make_shared<Expectation>(*bus, match);
    expectations.push_back(e);
    return e;
}

static auto getPropsChangedMatchString(const std::string& path,
                                       const std::string& interface)
{
    return sdbusplus::bus::match::rules::interface(
               "org.freedesktop.DBus.Properties") +
           sdbusplus::bus::match::rules::path(path) +
           sdbusplus::bus::match::rules::member("PropertiesChanged") +
           sdbusplus::bus::match::rules::argN(0, interface);
}

std::shared_ptr<Expectation>
    IntegrationTest::expectPropsChangedSignal(const std::string& path,
                                              const std::string& interface)
{
    return expectSignal(getPropsChangedMatchString(path, interface));
}

void IntegrationTest::runFor(SdBusDuration microseconds)
{
    sdbusplus::test::integration::Timer test;
    auto duration = test.duration();
    while (duration < microseconds)
    {
        bus->process_discard(); // discard any unhandled messages
        bus->wait(microseconds - duration);
        duration = test.duration();
    }
}

bool IntegrationTest::isMapperxStarted()
{
    return mapperxDaemon.isStarted();
}

} // namespace integration
} // namespace test
} // namespace openbmc
