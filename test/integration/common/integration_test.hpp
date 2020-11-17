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

    /** Constructs an expectation. sdbusplus matches are created in constructor.
     *
     * @param bus - The reference to bus to place this match on.
     * @param match - The sdbusplus match string for expected events.
     */
    Expectation(sdbusplus::bus::bus& bus, const std::string& match);

    /** The expectations will be evaluated in destructor.
     */
    ~Expectation();

    /** When a new event matches the criteria, this method will be called.
     */
    void newEvent(sdbusplus::message::message& m);

    /** Adds an expectation on the exact number of times that the matched event
     * occurs.
     */
    void exactly(int times);

    /** Adds an expectation on the minimum number of times that the matched
     * event occurs.
     */
    void atLeast(int times);

    /** Adds an expectation on the maximum number of times that the matched
     * event occurs.
     */
    void atMost(int times);

  private:
    size_t count;
    sdbusplus::bus::match::match eventMatch;
    int exactlyTimes;
    int atLeastTimes;
    int atMostTimes;
};

/** This is the base class to place utilities that are shared by all OpenBMC
 * integration tests.
 *
 * This class takes care of the mapperx daemon and starts the private bus for
 * the test.
 */
class IntegrationTest
{
  public:
    IntegrationTest();

    /** If the integration test itself needs interaction with the bus,
     * e.g., expecting signals, etc. it should call this method, which is
     * an event loop on sdbus.
     *
     * @param microseconds - the test duration in micorseconds. The loop will
     * terminate after this duration.
     */
    void runFor(SdBusDuration microseconds);

    /** Adds an expectation based on the match string that is provided.
     *
     * @param match - The sdbusplus match string.
     * @return the expectation object. The exact expected behavior should be
     * added to this object, e.g., number of times that matched event should
     * occur. @see Expectation.
     */
    std::shared_ptr<Expectation> expectSignal(const std::string& match);

    /** A special version of an expected signal to catch
     * PropertiesChanged signal on D-Bus.
     *
     * @param path - The path of the object on D-Bus
     * @param interface - The interface for which we expect this signal happens.
     */
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
