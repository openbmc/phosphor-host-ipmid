#pragma once

#include "common/integration_test.hpp"
#include "common/services/bmc_state.hpp"
#include "common/services/networkd.hpp"
#include "common/services/restriction_mode.hpp"
#include "common/services/sensor_server.hpp"
#include "common/services/user_manager.hpp"

#include <ipmid/api-types.hpp>
#include <memory>
#include <sdbusplus/test/integration/daemon_manager.hpp>
#include <string>
#include <unordered_map>
#include <vector>

using openbmc::test::integration::IntegrationTest;
using sdbusplus::test::integration::Daemon;

class IpmidDaemon : public Daemon
{
  public:
    IpmidDaemon(const IpmidDaemon&) = delete;
    IpmidDaemon& operator=(const IpmidDaemon&) = delete;
    IpmidDaemon(IpmidDaemon&&) = delete;
    IpmidDaemon& operator=(IpmidDaemon&&) = delete;

    IpmidDaemon() : IpmidDaemon(defaultIpmidPath){};

    IpmidDaemon(const char* ipmidPath) : Daemon({ipmidPath}){};

  private:
    static constexpr char defaultIpmidPath[] = "ipmid";
};

/** This class includes shared functionalities that all ipmid integration
 * tests can use.
 * It manages ipmid, which is the daemon under test in these examples.
 * @see IpmidDaemon
 */
class IpmidTest : public IntegrationTest
{

  public:
    using Value =
        std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t,
                     int64_t, uint64_t, double, std::string>;
    using CommandOptions = std::map<std::string, Value>;
    using Response =
        std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;

    /** Inner class to facilitate running the ipmid execute method
     */
    class Executor
    {
      public:
        Executor(
            IpmidTest& test, uint8_t netFn, uint8_t lun, uint8_t cmd,
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        virtual Response execute();

        virtual void verify(const std::vector<uint8_t>& expectedResponseData =
                                std::vector<uint8_t>{},
                            uint8_t expectedCC = ipmi::ccSuccess);

        virtual void verifyResponse(uint8_t expectedCC = ipmi::ccSuccess);

        virtual void verifyResponseData(
            const std::vector<uint8_t>& expectedData = std::vector<uint8_t>{});

        virtual void printResponse();

        virtual ~Executor();

      private:
        IpmidTest& test;

        uint8_t netFn;
        uint8_t lun;
        uint8_t cmd;
        const std::vector<uint8_t>& commandData;
        CommandOptions options;
        Response response;

        static constexpr int responseDataPrintLimit = 20;
        static constexpr uint8_t netFnResponse = 0x01;

        static constexpr char ipmiHostServiceName[] =
            "xyz.openbmc_project.Ipmi.Host";
        static constexpr char ipmiObjPath[] = "/xyz/openbmc_project/Ipmi";
        static constexpr char ipmiServerInterface[] =
            "xyz.openbmc_project.Ipmi.Server";
        static constexpr char ipmiExecute[] = "execute";
    };

    class AppExecutor : public Executor
    {
      public:
        AppExecutor(
            IpmidTest& test, uint8_t lun, uint8_t cmd,
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<AppExecutor> getDeviceId(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<AppExecutor> coldReset(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<AppExecutor> getSelfTestResults(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<AppExecutor> setUsername(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<AppExecutor> setUserPassword(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<AppExecutor> setUserAccess(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});
    };

    class SensorExecutor : public Executor
    {
      public:
        SensorExecutor(
            IpmidTest& test, uint8_t lun, uint8_t cmd,
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<SensorExecutor> getDeviceSdrInfo(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{0},
            CommandOptions options = {});

        static std::shared_ptr<SensorExecutor>
            getDeviceSdr(IpmidTest& test, uint8_t lun = uint8_t(1),
                         const std::vector<uint8_t>& commandData =
                             std::vector<uint8_t>{0, 0, 0, 0, 0, 0xff},
                         CommandOptions options = {});

        static std::shared_ptr<SensorExecutor>
            getSensorReading(IpmidTest& test, uint8_t lun = uint8_t(1),
                             const std::vector<uint8_t>& commandData =
                                 std::vector<uint8_t>{0xD0},
                             CommandOptions options = {});
    };

    class TransportExecutor : public Executor
    {
      public:
        TransportExecutor(
            IpmidTest& test, uint8_t lun, uint8_t cmd,
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});

        static std::shared_ptr<TransportExecutor> setLan(
            IpmidTest& test, uint8_t lun = uint8_t(1),
            const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
            CommandOptions options = {});
    };

    IpmidTest();

    std::shared_ptr<AppExecutor> executeGetDeviceId(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<AppExecutor> executeColdReset(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<AppExecutor> executeGetSelfTestResults(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<AppExecutor> executeSetUsername(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<AppExecutor> executeSetUserPassword(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<AppExecutor> executeSetUserAccess(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<SensorExecutor> executeGetDeviceSdrInfo(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{0},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<SensorExecutor> executeGetDeviceSdr(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{0, 0, 0,
                                                                       0, 0,
                                                                       0xff},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<SensorExecutor> executeGetSensorReading(
        const std::vector<uint8_t>& commandData = std::vector<uint8_t>{0xD0},
        uint8_t lun = uint8_t(1), CommandOptions options = {});

    std::shared_ptr<TransportExecutor>
        executeSetLan(const std::vector<uint8_t>& commandData,
                      uint8_t lun = uint8_t(1), CommandOptions options = {});

    void initiateTempService(std::string serviceName,
                             SdBusDuration microsecondsToRun);
    void startTempService();

    void initiateRestrictionModeService(std::string serviceName,
                                        SdBusDuration microsecondsToRun);
    void startRestrictionModeService();

    void initiateUserManagerService(std::string serviceName,
                                    SdBusDuration microsecondsToRun);
    void startUserManagerService();

    void initiateBMCStateService(std::string serviceName,
                                 SdBusDuration microsecondsToRun);
    void startBMCStateService();

    void initiateNetworkDService(std::string serviceName,
                                 SdBusDuration microsecondsToRun);
    void startNetworkDService();

    void startIpmid(int warmUpMilisec = 4000);

    void addNewTempObject(const std::string& path,
                          const SensorProperties& tempSensorVals,
                          double changeRatePercentage = 0.001);

    void addNewRestrictionModeObject(const std::string& path,
                                     const RestrictionModeProperties& vals);

    void addNewUserManagerObject(const std::string& path,
                                 const UserManagerProperties& vals);

    void addNewUserObject(const std::string& path, const UserProperties& vals);

    void addNewBMCStateObject(const std::string& path,
                              const BMCStateProperties& vals);

    void addNewSystemConfigurationObject(
        const std::string& path, const SystemConfigurationProperties& vals);

    void addNewEthernetInterfaceObject(
        const std::string& path,
        const EthernetInterfaceProperties& ethIfacevals);

    void addNewNetworkManagerObject(const std::string& path);

    std::shared_ptr<SensorService> tempService;
    std::shared_ptr<RestrictionModeService> restrictionModeService;
    std::shared_ptr<UserManagerService> userManagerService;
    std::shared_ptr<BMCStateService> bmcStateService;
    std::shared_ptr<NetworkDService> networkDService;

  private:
    IpmidDaemon ipmidDaemon;
};
