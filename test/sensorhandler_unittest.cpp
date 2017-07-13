#include <systemd/sd-bus.h>
#include "host-ipmid/ipmid-api.h"
#include "sensorhandler.h"
#include "types.hpp"
#include "sdbuswrapper.h"
#include "ipmid.hpp"
#include <mapper.h>
#include <errno.h>

#include <xyz/openbmc_project/Sensor/Value/server.hpp>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define SENSOR_ID_A 0x01
#define SENSOR_STRING_ID_A "A"
#define SENSOR_PATH_A "/sensor/path/" SENSOR_STRING_ID_A
#define SENSOR_COEFFM_A 315
#define SENSOR_COEFFB_A 0
#define SENSOR_EXPB_A 0
#define SENSOR_OFFSET_A 0
#define SENSOR_UNIT_A "xyz.openbmc_project.Sensor.Value.Unit.DegreesC"
#define SENSOR_SCALE_A -3

#define INVALID_SENSOR_ID 0xFF

#define SENSOR_TYPE_ANALOG 1
#define SENSOR_READING_TYPE_ANALOG 1
#define SENSOR_IFACE_ANALOG "xyz.openbmc_project.Sensor.Value"
#define SENSOR_VALUE_PROPERTY_ANALOG "Value"
#define SENSOR_UNIT_PROPERTY_ANALOG "Unit"
#define SENSOR_SCALE_PROPERTY_ANALOG "Scale"
#define SENSOR_OFFSET_ANALOG 0
#define SENSOR_PROPERTY_TYPE_ANALOG "int"

using namespace testing;

/**
 * Testbench fakes and mocks.
 */
sd_bus* bus = nullptr;
FILE* ipmidbus = nullptr;

extern const ipmi::sensor::IdInfoMap sensors = {
    {SENSOR_ID_A,    // Sensor ID
      {       // struct Info
        SENSOR_TYPE_ANALOG,    // sensorType
        SENSOR_PATH_A, // sensorPath
        SENSOR_READING_TYPE_ANALOG,    // sensorReadingType
        SENSOR_COEFFM_A,  // coefficientM
        SENSOR_COEFFB_A,    // coefficientB
        SENSOR_EXPB_A,    // exponentB
        SENSOR_OFFSET_A,    // scaledOffset
        {     // DbusInterfaceMap
          {
            SENSOR_IFACE_ANALOG, // DbusInterface
            {                                   // DbusPropertyMap
              {
                SENSOR_VALUE_PROPERTY_ANALOG,    // DbusProperty
                {           // OffsetValueMap
                  {
                    SENSOR_OFFSET_ANALOG,      // Offset
                    {std::string(SENSOR_PROPERTY_TYPE_ANALOG),}},}},}},}}},  // Values.Type
};

int updateSensorRecordFromSSRAESC(const void *record) {
    return 0;
}

void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_context_t context, ipmid_callback_t cb,
                            ipmi_cmd_privilege_t priv)
{
    EXPECT_EQ(NETFUN_SENSOR, netfn);
}

sd_bus* ipmid_get_sd_bus_connection() {
    return bus;
}

int mapper_get_service(sd_bus *conn, const char *obj, char **service)
{
    *service = new char[16];
    strcpy(*service, "test");
    return 0;
}

namespace ipmi
{
std::string getService(sdbusplus::bus::bus& bus,
                       const std::string& intf,
                       const std::string& path)
{
    return "";
}
} // namespace ipmi

namespace sdbusplus
{
namespace xyz
{
namespace openbmc_project
{
namespace Sensor
{
namespace server
{
    Value::Unit Value::convertUnitFromString(const std::string& s)
    {
        return Value::Unit::DegreesC;
    }
} // namespace server
} // namespace Sensor
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

class MockSdBusWrapper : public SdBusWrapper {
 public:
  MOCK_METHOD6(sd_bus_message_new_method_call,
               int(sd_bus *bus, sd_bus_message **m, const char *interface_bus,
                   const char *interface_path, const char *interface_type,
                   const char *interface_operation));

  MOCK_METHOD5(sd_bus_call, int(sd_bus *bus, sd_bus_message *m, uint64_t usec,
                                sd_bus_error *ret_error, sd_bus_message **reply));

  MOCK_METHOD9(sd_bus_call_method, int(sd_bus *bus, const char *destination,
                                       const char *path, const char *interface,
                                       const char *member, sd_bus_error *error,
                                       sd_bus_message **reply, const char *types,
                                       const char *a1));

  MOCK_METHOD10(sd_bus_call_method, int(sd_bus *bus, const char *destination,
                                       const char *path, const char *interface,
                                       const char *member, sd_bus_error *error,
                                       sd_bus_message **reply, const char *types,
                                       const char *a1, const char a2));

  MOCK_METHOD8(sd_bus_get_property, int(sd_bus *bus, const char *destination,
                                        const char *path, const char *interface,
                                        const char *member, sd_bus_error *ret_error,
                                        sd_bus_message **reply, const char *type));

  MOCK_METHOD3(sd_bus_message_append, int(sd_bus_message *m, const char *types,
                                          const char *a1));

  MOCK_METHOD4(sd_bus_message_append, int(sd_bus_message *m, const char *types,
                                          const char *a1, const char *a2));

  MOCK_METHOD4(sd_bus_message_append, int(sd_bus_message *m, const char *types,
                                          const char *a1, const char a2));

  MOCK_METHOD3(sd_bus_message_read, int(sd_bus_message *m, const char *types,
                                        char **a1));

  MOCK_METHOD3(sd_bus_message_read, int(sd_bus_message *m, const char *types,
                                        int *a1));

  MOCK_METHOD4(sd_bus_message_read, int(sd_bus_message *m, const char *types,
                                        const char *a1, char **a2));

  MOCK_METHOD4(sd_bus_message_read, int(sd_bus_message *m, const char *types,
                                        char **a1, char **a2));

  MOCK_METHOD1(sd_bus_error_free, void(sd_bus_error *e));

  MOCK_METHOD1(sd_bus_message_unref, sd_bus_message*(sd_bus_message *m));

  MOCK_METHOD8(sd_bus_get_property_trivial, int(sd_bus *bus,
                                                const char *destination,
                                                const char *path,
                                                const char *interface,
                                                const char *member,
                                                sd_bus_error *ret_error,
                                                char type, void *ret_ptr));

  MOCK_METHOD7(sd_bus_get_property_string, int(sd_bus *bus,
                                               const char *destination,
                                               const char *path,
                                               const char *interface,
                                               const char *member,
                                               sd_bus_error *ret_error,
                                               char **ret));
};

ACTION_P(SetArg7ToLong, value)
{
    *reinterpret_cast<uint64_t*>(arg7) = value;
}

ACTION_P(SetArg6ToString, value)
{
    *arg6 = (char*)malloc(strlen(value));
    strcpy(*reinterpret_cast<char**>(arg6), value);
}

class SensorHandlerTest : public testing::Test {
    protected:
        virtual void SetUp(){
            // give it something nonzero; none of the mocks will touch the ptr.
            bus = reinterpret_cast<sd_bus*>(this);
        };

        virtual void TearDown() {
        };

        ipmi_request_t _request;
        ipmi_response_t _response;
        ipmi_data_len_t _data_len;
        ipmi_context_t _context;
};

/**
 * Reserve SDR
 *
 * For now, this method only returns 1 all the time.
 * More tests must be added if the method is changed.
 *
 * - Happy Path
 */
TEST_F(SensorHandlerTest, ReserveSdr)
{
    _request = NULL;
    _response = new uint16_t;
    _data_len = new size_t(0);
    _context = NULL;
    NiceMock<MockSdBusWrapper> mock;
    ipmi_ret_t ret = ipmi_sen_reserve_sdr(ipmi_net_fns::NETFUN_SENSOR,
                                          ipmi_netfn_sen_cmds::IPMI_CMD_RESERVE_SDR_REPO,
                                          _request, _response, _data_len, _context, &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    ASSERT_EQ(sizeof(uint16_t), *_data_len);

    // For now, there is exactly one SDR reservation ID
    ASSERT_EQ(1, *(uint16_t*)_response);

    delete (uint16_t*)_response;
    _response = new uint16_t;
    *_data_len = 0;
    ret = ipmi_sen_reserve_sdr(ipmi_net_fns::NETFUN_SENSOR,
                               ipmi_netfn_sen_cmds::IPMI_CMD_RESERVE_SDR_REPO,
                               _request, _response, _data_len, _context, &mock);

    // Should be idempotent
    ASSERT_EQ(IPMI_CC_OK, ret);
    ASSERT_EQ(sizeof(uint16_t), *_data_len);

    // For now, there is exactly one SDR reservation ID
    ASSERT_EQ(1, *(uint16_t*)_response);

    delete (uint16_t*)_response;
    delete _data_len;
}

/**
 * Get Reading
 *
 * Returns the value of the sensor, scaled down to fit inside 8 bits.
 *
 * - Happy Path
 * - DBus not responsive
 * - Request nonexistent sensor
 * - TODO: functional sensor
 */
TEST_F(SensorHandlerTest, GetReadingHappyPath)
{
    _request = new sensor_data_t;
    ((sensor_data_t*)_request)->sennum = SENSOR_ID_A;
    _response = new sensorreadingresp_t;
    _data_len = new size_t;
    char expectedValue = 20;

    NiceMock<MockSdBusWrapper> mock;
    EXPECT_CALL(mock, sd_bus_get_property_trivial(bus, _, StrEq(SENSOR_PATH_A),\
                                                  StrEq(SENSOR_IFACE_ANALOG),\
                                                  StrEq(SENSOR_VALUE_PROPERTY_ANALOG),\
                                                  _, 'x', _))
        .Times(1)
        .WillOnce(DoAll(SetArg7ToLong(expectedValue*SENSOR_COEFFM_A), Return(0)));

    ipmi_ret_t ret = ipmi_sen_get_sensor_reading(ipmi_net_fns::NETFUN_SENSOR,
                                                 ipmi_netfn_sen_cmds::IPMI_CMD_GET_SENSOR_READING,
                                                 _request, _response, _data_len, _context,
                                                 &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    ASSERT_EQ(sizeof(sensorreadingresp_t), *_data_len);
    ASSERT_EQ (expectedValue, ((sensorreadingresp_t*)_response)->value);

    delete (sensor_data_t*)_request;
    delete (sensorreadingresp_t*)_response;
    delete _data_len;
}

TEST_F(SensorHandlerTest, GetReadingFailsWithNoDbus)
{
    _request = new sensor_data_t;
    ((sensor_data_t*)_request)->sennum = SENSOR_ID_A;
    _response = new sensorreadingresp_t;
    _data_len = new size_t;

    NiceMock<MockSdBusWrapper> mock;
    EXPECT_CALL(mock, sd_bus_get_property_trivial(bus, _, StrEq(SENSOR_PATH_A),\
                                                  StrEq(SENSOR_IFACE_ANALOG),\
                                                  StrEq(SENSOR_VALUE_PROPERTY_ANALOG),\
                                                  _, 'x', _))
        .Times(1)
        .WillOnce(Return(-EBADR));

    ipmi_ret_t ret = ipmi_sen_get_sensor_reading(ipmi_net_fns::NETFUN_SENSOR,
                                                 ipmi_netfn_sen_cmds::IPMI_CMD_GET_SENSOR_READING,
                                                 _request, _response, _data_len, _context,
                                                 &mock);

    ASSERT_EQ(IPMI_CC_SENSOR_INVALID, ret);
    ASSERT_EQ(0, *_data_len);

    delete (sensor_data_t*)_request;
    delete (sensorreadingresp_t*)_response;
    delete _data_len;
}

TEST_F(SensorHandlerTest, GetReadingFailsWithInvalidSensor)
{
    _request = new sensor_data_t;
    ((sensor_data_t*)_request)->sennum = INVALID_SENSOR_ID;
    _response = new sensorreadingresp_t;
    _data_len = new size_t;

    NiceMock<MockSdBusWrapper> mock;
    EXPECT_CALL(mock, sd_bus_call_method(bus, _, _, _, "getObjectFromByteId",\
                                         _, _, "sy", _, _))
        .Times(1)
        .WillOnce(Return(-EINVAL));

    ipmi_ret_t ret = ipmi_sen_get_sensor_reading(ipmi_net_fns::NETFUN_SENSOR,
                                                 ipmi_netfn_sen_cmds::IPMI_CMD_GET_SENSOR_READING,
                                                 _request, _response, _data_len, _context,
                                                 &mock);

    ASSERT_EQ(IPMI_CC_SENSOR_INVALID, ret);

    delete (sensor_data_t*)_request;
    delete (sensorreadingresp_t*)_response;
    delete _data_len;
}

/**
 * Get Sensor Type
 *
 * Returns the IPMI sensor type of the requested sensor.
 *
 * - Happy Path (multiple sensor types)
 * - TODO: Functional sensor type
 */
TEST_F(SensorHandlerTest, GetSensorTypeHappyPath)
{
    _request = new sensor_data_t;
    ((sensor_data_t*)_request)->sennum = SENSOR_ID_A;
    _response = new char[2];
    _data_len = new size_t;

    StrictMock<MockSdBusWrapper> mock;  // We expect 0 calls to DBus.

    ipmi_ret_t ret = ipmi_sen_get_sensor_type(ipmi_net_fns::NETFUN_SENSOR,
                                              ipmi_netfn_sen_cmds::IPMI_CMD_GET_SENSOR_TYPE,
                                              _request, _response, _data_len, _context,
                                              &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    ASSERT_EQ(2, *_data_len);
    // TODO: assert that array is equal to {SENSOR_TYPE_A, 0x6F}

    delete (sensor_data_t*)_request;
    delete (char*)_response;
    delete _data_len;

}

// TODO(emilyshaffer) add second sensor with different type

/**
 * Get SDR Info
 *
 * Returns the number of entries in the SDR. DBus isn't used, so we don't really
 * have failure cases.
 *
 * - Happy path (get sensor count)
 * - Happy path (get SDR count)
 */
TEST_F(SensorHandlerTest, GetSdrInfoRepoCountHappyPath)
{
    using namespace get_sdr_info;
    /**
     * NOTE: In practice, the request pointer was treated as an integer
     * in this call, instead of as a pointer.  Duplicating this behavior
     * in the testbench.
     */
    _request = (void*)1; // Get SDR repository count (should only be one SDR)
    _response = new GetSdrInfoResp();
    _data_len = new size_t;
    uint8_t expectedLuns = 0x01; // Only LUN0 has sensors; statically populated.

    StrictMock<MockSdBusWrapper> mock;  // We expect 0 calls to DBus.

    ipmi_ret_t ret = ipmi_sen_get_sdr_info(ipmi_net_fns::NETFUN_SENSOR,
                                           ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR_INFO,
                                           _request, _response, _data_len,
                                           _context, &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    // Exactly 1 SDR repository
    ASSERT_EQ(1, reinterpret_cast<GetSdrInfoResp*>(_response)->count);
    ASSERT_EQ(expectedLuns,
              reinterpret_cast<GetSdrInfoResp*>(_response)->luns_and_dynamic_population);

    delete (GetSdrInfoResp*)_response;
    delete _data_len;
}

TEST_F(SensorHandlerTest, GetSdrInfoSensorCountHappyPath)
{
    using namespace get_sdr_info;
    /**
     * NOTE: In practice, the request pointer was treated as an integer
     * in this call, instead of as a pointer.  Duplicating this behavior
     * in the testbench.
     */
    _request = (void*)0; // Get sensor count
    _response = new GetSdrInfoResp();
    _data_len = new size_t;
    uint8_t expectedLuns = 0x01; // Only LUN0 has sensors; statically populated.

    StrictMock<MockSdBusWrapper> mock;  // We expect 0 calls to DBus.

    ipmi_ret_t ret = ipmi_sen_get_sdr_info(ipmi_net_fns::NETFUN_SENSOR,
                                           ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR_INFO,
                                           _request, _response, _data_len,
                                           _context, &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    // Exactly 1 SDR repository
    ASSERT_EQ(sensors.size(), reinterpret_cast<GetSdrInfoResp*>(_response)->count);
    ASSERT_EQ(expectedLuns,
              reinterpret_cast<GetSdrInfoResp*>(_response)->luns_and_dynamic_population);

    delete (GetSdrInfoResp*)_response;
    delete _data_len;
}

/**
 * Get SDR
 *
 * Returns detailed information about a sensor.
 *
 * - Happy path
 * - Requested sensor not in list
 * - Read with offset
 * - TODO: Partial read (not supported yet)
 */
TEST_F(SensorHandlerTest, GetSdrHappyPath)
{
    using namespace get_sdr;

    _request = new GetSdrReq();
    _response = new GetSdrResp();
    _data_len = new size_t;

    StrictMock<MockSdBusWrapper> mock;
    EXPECT_CALL(mock, sd_bus_get_property_string(bus, _, StrEq(SENSOR_PATH_A),\
                                                 StrEq(SENSOR_IFACE_ANALOG),\
                                                 StrEq(SENSOR_UNIT_PROPERTY_ANALOG),\
                                                 _, _))
        .Times(AtMost(1))
        .WillOnce(DoAll(SetArg6ToString(SENSOR_UNIT_A), Return(0)));

    EXPECT_CALL(mock, sd_bus_get_property_trivial(bus, _, StrEq(SENSOR_PATH_A),\
                                                 StrEq(SENSOR_IFACE_ANALOG),\
                                                 StrEq(SENSOR_SCALE_PROPERTY_ANALOG),\
                                                 _, 'x', _))
        .Times(AtMost(1))
        .WillOnce(DoAll(SetArg7ToLong(SENSOR_SCALE_A), Return(0)));

    ipmi_ret_t ret = ipmi_sen_get_sdr(ipmi_net_fns::NETFUN_SENSOR,
                                      ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR_INFO,
                                      _request, _response, _data_len,
                                      _context, &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    ASSERT_EQ(sizeof(GetSdrResp), *_data_len);

    GetSdrResp* resp = reinterpret_cast<GetSdrResp*>(_response);

    // 0xFFFF indicates end of records.  We should only have one sensor to
    // report here.
    ASSERT_EQ(0xFF, resp->next_record_id_lsb);
    ASSERT_EQ(0xFF, resp->next_record_id_msb);

    SensorDataFullRecord *fullRecord =
        reinterpret_cast<SensorDataFullRecord*>(&(resp->record_data));

    ASSERT_EQ(SENSOR_ID_A, fullRecord->header.record_id_lsb);
    ASSERT_EQ(0, fullRecord->header.record_id_msb);
    ASSERT_EQ(SENSOR_DATA_FULL_RECORD, fullRecord->header.record_type);
    ASSERT_EQ(0x51, fullRecord->header.sdr_version);
    ASSERT_EQ(sizeof(SensorDataFullRecord), fullRecord->header.record_length);

    ASSERT_EQ(SENSOR_ID_A, fullRecord->key.sensor_number);

    ASSERT_EQ(SENSOR_ID_A, fullRecord->body.entity_id);
    ASSERT_EQ(SENSOR_TYPE_ANALOG, fullRecord->body.sensor_type);
    ASSERT_EQ(SENSOR_READING_TYPE_ANALOG, fullRecord->body.event_reading_type);
    ASSERT_EQ(0, fullRecord->body.sensor_units_1); // No rate unit
    ASSERT_EQ(SENSOR_UNIT_DEGREES_C, fullRecord->body.sensor_units_2_base);

    // m, b, b_exp, and r_exp are all in bitfielded bytes.
    // IPMI v2r1-1 pg 526
    uint8_t expectedMLsb = SENSOR_COEFFM_A & 0x0FF;
    uint8_t expectedMTol = (SENSOR_COEFFM_A & 0xF00) >> 2; // top 2 bits at top of byte
    uint8_t expectedBLsb = SENSOR_COEFFB_A & 0x0FF;
    uint8_t expectedBAcc = (SENSOR_COEFFB_A & 0xF00) >> 2; // top 2 bits at top of byte
    uint8_t expectedRBExp = (SENSOR_EXPB_A & 0x0F)
                          | ((SENSOR_SCALE_A & 0X0F) << 4);
    ASSERT_EQ(expectedMLsb, fullRecord->body.m_lsb);
    ASSERT_EQ(expectedMTol, fullRecord->body.m_msb_and_tolerance);
    ASSERT_EQ(expectedBLsb, fullRecord->body.b_lsb);
    ASSERT_EQ(expectedBAcc, fullRecord->body.b_msb_and_accuracy_lsb);
    ASSERT_EQ(expectedRBExp, fullRecord->body.r_b_exponents);

    // Note: more data is contained in id_string_info, but we expect it to be
    // zeroes as we are using Unicode.
    ASSERT_EQ(strlen(SENSOR_STRING_ID_A), fullRecord->body.id_string_info);
    ASSERT_STREQ(SENSOR_STRING_ID_A, fullRecord->body.id_string);

    delete _data_len;
    delete (GetSdrResp*)_response;
    delete (GetSdrReq*)_request;
}

TEST_F(SensorHandlerTest, GetSdrSensorNotInList)
{
    using namespace get_sdr;

    _request = new GetSdrReq();
    reinterpret_cast<GetSdrReq*>(_request)->record_id_lsb = INVALID_SENSOR_ID;
    _response = new GetSdrResp();
    _data_len = new size_t;

    StrictMock<MockSdBusWrapper> mock;

    ipmi_ret_t ret = ipmi_sen_get_sdr(ipmi_net_fns::NETFUN_SENSOR,
                                      ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR_INFO,
                                      _request, _response, _data_len,
                                      _context, &mock);

    ASSERT_EQ(IPMI_CC_SENSOR_INVALID, ret);

    delete _data_len;
    delete (GetSdrResp*)_response;
    delete (GetSdrReq*)_request;
}

TEST_F(SensorHandlerTest, GetSdrSensorWithOffset)
{
    using namespace get_sdr;
    const int& offset = 10;

    _request = new GetSdrReq();
    reinterpret_cast<GetSdrReq*>(_request)->offset = offset;
    _response = new GetSdrResp();
    _data_len = new size_t;

    StrictMock<MockSdBusWrapper> mock;
    EXPECT_CALL(mock, sd_bus_get_property_string(bus, _, StrEq(SENSOR_PATH_A),\
                                                 StrEq(SENSOR_IFACE_ANALOG),\
                                                 StrEq(SENSOR_UNIT_PROPERTY_ANALOG),\
                                                 _, _))
        .Times(AtMost(1))
        .WillOnce(DoAll(SetArg6ToString(SENSOR_UNIT_A), Return(0)));

    EXPECT_CALL(mock, sd_bus_get_property_trivial(bus, _, StrEq(SENSOR_PATH_A),\
                                                 StrEq(SENSOR_IFACE_ANALOG),\
                                                 StrEq(SENSOR_SCALE_PROPERTY_ANALOG),\
                                                 _, 'x', _))
        .Times(AtMost(1))
        .WillOnce(DoAll(SetArg7ToLong(SENSOR_SCALE_A), Return(0)));

    ipmi_ret_t ret = ipmi_sen_get_sdr(ipmi_net_fns::NETFUN_SENSOR,
                                      ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR_INFO,
                                      _request, _response, _data_len,
                                      _context, &mock);

    ASSERT_EQ(IPMI_CC_OK, ret);
    ASSERT_EQ(sizeof(GetSdrResp) - offset, *_data_len);

    delete _data_len;
    delete (GetSdrResp*)_response;
    delete (GetSdrReq*)_request;
}
