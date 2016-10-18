#include "ipmid-router.hpp"

#include <memory>
#include <vector>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "ipmid-test-utils.hpp"

using std::unique_ptr;
using std::vector;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Mock;
using ::testing::MockFunction;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;
using ::testing::_;

namespace ipmid
{

class MockIpmiMessageBus : public IpmiMessageBus
{
    public:
        MOCK_METHOD2(SendMessage, void(const IpmiContext& context,
                                       const IpmiMessage& message));
};

class MockIpmiHandler : public IpmiHandler
{
    public:
        MOCK_METHOD2(HandleRequest, bool(const IpmiContext& context,
                                         const IpmiMessage& message));
};

class IpmidRouterTest : public ::testing::Test
{
    protected:
        IpmidRouterTest() :
            message_bus_(new MockIpmiMessageBus),
            root_router_(unique_ptr<IpmiMessageBus>(message_bus_))
        {
            // This gets cleaned up after the test case finishes, so to gmock it looks
            // like a leak.
            Mock::AllowLeak(message_bus_);
        }

        MockIpmiMessageBus* message_bus_;
        RootRouter root_router_;
};

TEST_F(IpmidRouterTest, SendResponse)
{
    IpmiContext context;
    IpmiMessage message;

    EXPECT_CALL(*message_bus_, SendMessage(context, message));
    root_router_.SendResponse(context, message);
}

TEST_F(IpmidRouterTest, NoHandlers)
{
    IpmiContext context;
    IpmiMessage message;
    message.netfn = 0x2;
    EXPECT_FALSE(root_router_.HandleRequest(context, message));
}

TEST_F(IpmidRouterTest, SimpleHandler)
{
    MockIpmiHandler* mock_handler = new MockIpmiHandler();
    const uint8_t netfn = 0x2;
    root_router_.RegisterHandler(netfn, unique_ptr<IpmiHandler>(mock_handler));

    IpmiContext context;
    IpmiMessage message;
    message.netfn = netfn;
    EXPECT_CALL(*mock_handler, HandleRequest(context, message))
    .WillOnce(Return(true));

    EXPECT_TRUE(root_router_.HandleRequest(context, message));

    EXPECT_CALL(*mock_handler, HandleRequest(context, message))
    .WillOnce(Return(false));

    EXPECT_FALSE(root_router_.HandleRequest(context, message));
}

typedef MockFunction<void(uint8_t, uint8_t, ipmi_request_t, ipmi_response_t, size_t*)>
MockIpmidCallbackT;

ipmi_ret_t mock_handler_wrapper(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request, ipmi_response_t response,
                                ipmi_data_len_t len, ipmi_context_t context)
{
    MockIpmidCallbackT* mock_handler = reinterpret_cast<MockIpmidCallbackT*>
                                       (context);
    mock_handler->Call(netfn, cmd, request, response, len);
    return 0;
}

ACTION_P2(SetArg3VoidPointer, start, size)
{
    memcpy(static_cast<uint8_t*>(arg3), start, size);
}

MATCHER_P(VoidPointerMatchVector, value, "")
{
    for (size_t i = 0; i < value.size(); i++)
    {
        if (reinterpret_cast<uint8_t*>(arg)[i] != value[i])
        {
            return false;
        }
    }
    return true;
}

TEST_F(IpmidRouterTest, IpmidCallbackTAdapterHandler)
{
    const uint8_t netfn = 0x4;
    const uint8_t lun = 3;
    const uint8_t seq = 57;
    const uint8_t cmd = 5;
    const vector<uint8_t> payload = {'a', 'b', 'c'};
    const vector<uint8_t> new_payload = {'y', 'z'};
    MockIpmidCallbackT mock_handler;
    root_router_.RegisterIpmidCallbackT(netfn, cmd, &mock_handler,
                                        mock_handler_wrapper);

    IpmiContext context;
    IpmiMessage request;
    request.netfn = netfn;
    request.lun = lun;
    request.seq = seq;
    request.cmd = cmd;
    request.payload = payload;
    EXPECT_CALL(mock_handler, Call(netfn,
                                   cmd,
                                   VoidPointerMatchVector(payload),
                                   _,
                                   Pointee(payload.size())))
    .WillOnce(DoAll(SetArg3VoidPointer(new_payload.data(), new_payload.size()),
                    SetArgPointee<4>(new_payload.size())));
    IpmiMessage response = request;
    response.netfn |= 1;
    response.payload = new_payload;
    EXPECT_CALL(*message_bus_, SendMessage(context, response));
    EXPECT_TRUE(root_router_.HandleRequest(context, request));
}

} // namespace ipmid
