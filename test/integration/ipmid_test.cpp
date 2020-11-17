#include "ipmid_test.hpp"

#include "common/integration_test.hpp"
#include "common/services/bmc_state.hpp"
#include "common/services/networkd.hpp"
#include "common/services/restriction_mode.hpp"
#include "common/services/sensor_server.hpp"

#include <memory>
#include <sdbusplus/test/integration/daemon_manager.hpp>
#include <string>

IpmidTest::Executor::Executor(IpmidTest& test, uint8_t netFn, uint8_t lun,
                              uint8_t cmd,
                              const std::vector<uint8_t>& commandData,
                              IpmidTest::CommandOptions options) :
    test(test),
    netFn(netFn), lun(lun), cmd(cmd), commandData(commandData), options(options)
{
    execute();
}

IpmidTest::Response IpmidTest::Executor::execute()
{
    auto method = test.bus->new_method_call(ipmiHostServiceName, ipmiObjPath,
                                            ipmiServerInterface, ipmiExecute);
    method.append(netFn, lun, cmd, commandData, options);
    auto reply = test.bus->call(method);
    reply.read(response);
    return response;
}

void IpmidTest::Executor::verify(
    const std::vector<uint8_t>& expectedResponseData, uint8_t expectedCC)
{
    verifyResponse(expectedCC);
    verifyResponseData(expectedResponseData);
}

void IpmidTest::Executor::verifyResponse(uint8_t expectedCC)
{
    auto actualNefFn = std::get<0>(response);
    auto actualLun = std::get<1>(response);
    auto actualCmd = std::get<2>(response);
    auto actualCC = std::get<3>(response);
    auto expectedNetFn = netFn | netFnResponse;
    EXPECT_EQ(actualNefFn, expectedNetFn);
    EXPECT_EQ(actualLun, lun);
    EXPECT_EQ(actualCmd, cmd);
    EXPECT_EQ(actualCC, expectedCC);
}

void IpmidTest::Executor::verifyResponseData(
    const std::vector<uint8_t>& expectedData)
{
    auto actualData = std::vector<uint8_t>(std::get<4>(response));
    EXPECT_EQ(actualData.size(), expectedData.size());
    for (size_t i = 0; i < actualData.size(); i++)
    {
        EXPECT_EQ(actualData[i], expectedData[i]);
    }
}

IpmidTest::Executor::~Executor()
{
    printResponse();
}

void IpmidTest::Executor::printResponse()
{
    auto data = std::vector<uint8_t>(std::get<4>(response));
    std::fprintf(stdout,
                 "0: [%#04X]\n"
                 "1: [%#04X]\n"
                 "2: [%#04X]\n"
                 "3: [%#04X]\n"
                 "data size(): %lu\n",
                 std::get<0>(response), std::get<1>(response),
                 std::get<2>(response), std::get<3>(response), data.size());
    int i = 0;
    for (auto& d : data)
    {
        if (i >= responseDataPrintLimit)
        {
            break;
        }
        std::fprintf(stdout, "%d: [%#04X]\t", i, d);
        i++;
    }
    std::fprintf(stdout, "\n\r");
}

IpmidTest::AppExecutor::AppExecutor(IpmidTest& test, uint8_t lun, uint8_t cmd,
                                    const std::vector<uint8_t>& commandData,
                                    IpmidTest::CommandOptions options) :
    IpmidTest::Executor(test, ipmi::netFnApp, lun, cmd, commandData, options)
{
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::AppExecutor::getDeviceId(IpmidTest& test, uint8_t lun,
                                        const std::vector<uint8_t>& commandData,
                                        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::AppExecutor>(
        test, lun, ipmi::app::cmdGetDeviceId, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::AppExecutor::coldReset(IpmidTest& test, uint8_t lun,
                                      const std::vector<uint8_t>& commandData,
                                      IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::AppExecutor>(
        test, lun, ipmi::app::cmdColdReset, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::AppExecutor::getSelfTestResults(
        IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::AppExecutor>(
        test, lun, ipmi::app::cmdGetSelfTestResults, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::AppExecutor::setUsername(IpmidTest& test, uint8_t lun,
                                        const std::vector<uint8_t>& commandData,
                                        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::AppExecutor>(
        test, lun, ipmi::app::cmdSetUserName, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor> IpmidTest::AppExecutor::setUserPassword(
    IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
    IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::AppExecutor>(
        test, lun, ipmi::app::cmdSetUserPasswordCommand, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor> IpmidTest::AppExecutor::setUserAccess(
    IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
    IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::AppExecutor>(
        test, lun, ipmi::app::cmdSetUserAccessCommand, commandData, options);
}

IpmidTest::SensorExecutor::SensorExecutor(
    IpmidTest& test, uint8_t lun, uint8_t cmd,
    const std::vector<uint8_t>& commandData,
    IpmidTest::CommandOptions options) :
    IpmidTest::Executor(test, ipmi::netFnSensor, lun, cmd, commandData, options)
{
}

std::shared_ptr<IpmidTest::SensorExecutor>
    IpmidTest::SensorExecutor::getDeviceSdrInfo(
        IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::SensorExecutor>(
        test, lun, ipmi::sensor_event::cmdGetDeviceSdrInfo, commandData,
        options);
}

std::shared_ptr<IpmidTest::SensorExecutor>
    IpmidTest::SensorExecutor::getDeviceSdr(
        IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::SensorExecutor>(
        test, lun, ipmi::sensor_event::cmdGetDeviceSdr, commandData, options);
}

std::shared_ptr<IpmidTest::SensorExecutor>
    IpmidTest::SensorExecutor::getSensorReading(
        IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::SensorExecutor>(
        test, lun, ipmi::sensor_event::cmdGetSensorReading, commandData,
        options);
}

IpmidTest::TransportExecutor::TransportExecutor(
    IpmidTest& test, uint8_t lun, uint8_t cmd,
    const std::vector<uint8_t>& commandData,
    IpmidTest::CommandOptions options) :
    IpmidTest::Executor(test, ipmi::netFnTransport, lun, cmd, commandData,
                        options)
{
}

std::shared_ptr<IpmidTest::TransportExecutor>
    IpmidTest::TransportExecutor::setLan(
        IpmidTest& test, uint8_t lun, const std::vector<uint8_t>& commandData,
        IpmidTest::CommandOptions options)
{
    return std::make_shared<IpmidTest::TransportExecutor>(
        test, lun, ipmi::transport::cmdSetLanConfigParameters, commandData,
        options);
}

IpmidTest::IpmidTest() : IntegrationTest(), ipmidDaemon()
{
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::executeGetDeviceId(const std::vector<uint8_t>& commandData,
                                  uint8_t lun,
                                  IpmidTest::CommandOptions options)
{
    return AppExecutor::getDeviceId(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::executeColdReset(const std::vector<uint8_t>& commandData,
                                uint8_t lun, IpmidTest::CommandOptions options)
{
    return AppExecutor::coldReset(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor> IpmidTest::executeGetSelfTestResults(
    const std::vector<uint8_t>& commandData, uint8_t lun,
    IpmidTest::CommandOptions options)
{
    return AppExecutor::getSelfTestResults(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::executeSetUsername(const std::vector<uint8_t>& commandData,
                                  uint8_t lun,
                                  IpmidTest::CommandOptions options)
{
    return AppExecutor::setUsername(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::executeSetUserPassword(const std::vector<uint8_t>& commandData,
                                      uint8_t lun,
                                      IpmidTest::CommandOptions options)
{
    return AppExecutor::setUserPassword(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::AppExecutor>
    IpmidTest::executeSetUserAccess(const std::vector<uint8_t>& commandData,
                                    uint8_t lun,
                                    IpmidTest::CommandOptions options)
{
    return AppExecutor::setUserAccess(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::SensorExecutor>
    IpmidTest::executeGetDeviceSdrInfo(const std::vector<uint8_t>& commandData,
                                       uint8_t lun,
                                       IpmidTest::CommandOptions options)
{
    return SensorExecutor::getDeviceSdrInfo(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::SensorExecutor>
    IpmidTest::executeGetDeviceSdr(const std::vector<uint8_t>& commandData,
                                   uint8_t lun,
                                   IpmidTest::CommandOptions options)
{
    return SensorExecutor::getDeviceSdr(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::SensorExecutor>
    IpmidTest::executeGetSensorReading(const std::vector<uint8_t>& commandData,
                                       uint8_t lun,
                                       IpmidTest::CommandOptions options)
{
    return SensorExecutor::getSensorReading(*this, lun, commandData, options);
}

std::shared_ptr<IpmidTest::TransportExecutor>
    IpmidTest::executeSetLan(const std::vector<uint8_t>& commandData,
                             uint8_t lun, IpmidTest::CommandOptions options)
{
    return TransportExecutor::setLan(*this, lun, commandData, options);
}

void IpmidTest::initiateTempService(std::string serviceName,
                                    SdBusDuration microsecondsToRun)
{
    tempService = std::make_shared<SensorService>(serviceName, mockBus,
                                                  microsecondsToRun);
}

void IpmidTest::startTempService()
{
    tempService->start();
}

void IpmidTest::initiateRestrictionModeService(std::string serviceName,
                                               SdBusDuration microsecondsToRun)
{
    restrictionModeService = std::make_shared<RestrictionModeService>(
        serviceName, mockBus, microsecondsToRun);
}

void IpmidTest::startRestrictionModeService()
{
    restrictionModeService->start();
}

void IpmidTest::initiateUserManagerService(std::string serviceName,
                                           SdBusDuration microsecondsToRun)
{
    userManagerService = std::make_shared<UserManagerService>(
        serviceName, mockBus, microsecondsToRun);
}

void IpmidTest::startUserManagerService()
{
    userManagerService->start();
}

void IpmidTest::initiateBMCStateService(std::string serviceName,
                                        SdBusDuration microsecondsToRun)
{
    bmcStateService = std::make_shared<BMCStateService>(serviceName, mockBus,
                                                        microsecondsToRun);
}

void IpmidTest::startBMCStateService()
{
    bmcStateService->start();
}

void IpmidTest::initiateNetworkDService(std::string serviceName,
                                        SdBusDuration microsecondsToRun)
{
    networkDService = std::make_shared<NetworkDService>(serviceName, mockBus,
                                                        microsecondsToRun);
}

void IpmidTest::startNetworkDService()
{
    IpmidTest::networkDService->start();
}

void IpmidTest::startIpmid(int warmUpMilisec)
{
    ipmidDaemon.start(warmUpMilisec);
}

void IpmidTest::addNewTempObject(const std::string& path,
                                 const SensorProperties& tempSensorVals,
                                 double changeRatePercentage)
{
    tempService->addSensor(path, tempSensorVals, changeRatePercentage);
}

void IpmidTest::addNewRestrictionModeObject(
    const std::string& path, const RestrictionModeProperties& vals)
{
    restrictionModeService->addRestrictionModeObject(path, vals);
}

void IpmidTest::addNewUserManagerObject(const std::string& path,
                                        const UserManagerProperties& vals)
{
    userManagerService->addUserManagerObject(path, vals);
}

void IpmidTest::addNewUserObject(const std::string& path,
                                 const UserProperties& vals)
{
    userManagerService->addUserObject(path, vals);
}

void IpmidTest::addNewBMCStateObject(const std::string& path,
                                     const BMCStateProperties& vals)
{
    bmcStateService->addBMCStateObject(path, vals);
}

void IpmidTest::addNewSystemConfigurationObject(
    const std::string& path, const SystemConfigurationProperties& vals)
{
    networkDService->addSystemConfigurationObject(path, vals);
}

void IpmidTest::addNewEthernetInterfaceObject(
    const std::string& path, const EthernetInterfaceProperties& ethIfacevals)
{
    networkDService->addEthernetInterfaceObject(path, ethIfacevals);
}

void IpmidTest::addNewNetworkManagerObject(const std::string& path)
{
    networkDService->addNetworkManagerObject(path);
}
