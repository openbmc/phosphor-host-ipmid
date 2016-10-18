#include "ipmid-server.hpp"

#include <iterator>
#include "dbus-mocks.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "ipmid-test-utils.hpp"

using std::default_delete;
using std::string;
using std::unique_ptr;
using std::vector;
using ::testing::A;
using ::testing::DoAll;
using ::testing::ElementsAreArray;
using ::testing::Exactly;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::MatcherCast;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::WithArg;
using ::testing::_;

namespace ipmid
{

class MockDBus : public DBus
{
    public:
        MockDBus(unique_ptr<DBusMessageOperations>&& message_ops,
                 unique_ptr<DBusBusOperations>&& bus_ops)
            : DBus(std::move(message_ops), std::move(bus_ops)) {}

        MOCK_METHOD0(Init, int());

        MOCK_METHOD2(GetServiceMapping, bool(const string&, string*));

        MOCK_METHOD3(CallMethod, bool(const DBusMemberInfo&, const DBusInput&,
                                      DBusOutput*));

        MOCK_METHOD0(ProcessMessage, int());

        MOCK_METHOD0(WaitForMessage, int());

        int RegisterHandler(const string& match, DBusHandler* handler) override
        {
            if (match == kHostIpmiMatch)
            {
                ipmi_dbus_handler_ = static_cast<IpmiDBusHandler*>(handler);
            }
            else if (match == kSettingsMatch)
            {
                restricted_mode_dbus_handler_ = static_cast<RestrictedModeDBusHandler*>
                                                (handler);
            }
            return 0;
        }

        IpmiDBusHandler* ipmi_dbus_handler()
        {
            return ipmi_dbus_handler_;
        }

        RestrictedModeDBusHandler* restricted_mode_dbus_handler()
        {
            return restricted_mode_dbus_handler_;
        }

        const MockDBusMessageOperations& mock_dbus_message_operations()
        {
            return static_cast<const MockDBusMessageOperations&>(dbus_message_operations());
        }

    private:
        IpmiDBusHandler* ipmi_dbus_handler_;
        RestrictedModeDBusHandler* restricted_mode_dbus_handler_;
        MockDBusBusOperations* bus_ops_ = new MockDBusBusOperations;
};

class MockRootRouter : public RootRouter
{
    public:
        MockRootRouter(unique_ptr<IpmiMessageBus>&& message_bus)
            : RootRouter(std::move(message_bus)) {}

        MOCK_METHOD4(RegisterIpmidCallbackT, void(ipmi_netfn_t, ipmi_cmd_t,
                     ipmi_context_t, ipmid_callback_t));

        MOCK_METHOD2(HandleRequest, bool(const IpmiContext&, const IpmiMessage&));

        MOCK_METHOD0(mutable_oem_group_router, OemGroupRouter * ());
};

bool operator==(const DBusMemberInfo& left, const DBusMemberInfo& right)
{
    return left.destination == right.destination &&
           left.path == right.path &&
           left.interface == right.interface &&
           left.member == right.member;
}

class IpmidServerTest : public ::testing::Test
{
    protected:
        IpmidServerTest() :
            message_ops_(new NiceMock<MockDBusMessageOperations>),
            bus_ops_(new NiceMock<MockDBusBusOperations>),
            dbus_(new MockDBus(unique_ptr<DBusMessageOperations>(message_ops_),
                               unique_ptr<DBusBusOperations>(bus_ops_))),
            root_router_(new MockRootRouter(unique_ptr<IpmiMessageBus>
                                            (new IpmiMessageBusImpl(dbus_)))),
            server_(unique_ptr<DBus>(dbus_),
                    unique_ptr<RootRouter>(root_router_),
        {{'a', 'b'}, {'c', 'd'}})
        {
            settings_info_.destination = kSettingsDestination;
            settings_info_.path = kSettingsPath;
            settings_info_.interface = kSettingsInterface;
            settings_info_.member = kSettingsMember;

            ipmi_host_info_.interface = kHostIpmiInterface;
            ipmi_host_info_.member = kHostIpmiMember;

            // This gets cleaned up after the test case finishes, so to gmock it looks
            // like a leak.
            Mock::AllowLeak(message_ops_);
            Mock::AllowLeak(bus_ops_);
            Mock::AllowLeak(dbus_);
            Mock::AllowLeak(root_router_);
        }

        MockDBusMessageOperations* message_ops_;
        MockDBusBusOperations* bus_ops_;
        MockDBus* dbus_;
        MockRootRouter* root_router_;
        IpmidServer server_;
        DBusMemberInfo settings_info_;
        DBusMemberInfo ipmi_host_info_;
};

TEST_F(IpmidServerTest, RespectsWhitelist)
{
    sd_bus_message* message_ptr = reinterpret_cast<sd_bus_message*>(56446154656);
    IpmiContext context;
    context.context = message_ptr;
    IpmiMessage message;
    message.netfn = 'x';
    message.lun = 3;
    message.seq = 57;
    message.cmd = 'y';
    message.payload = {'a', 'b', 'c'};
    EXPECT_CALL(*root_router_, HandleRequest(context, message))
    .Times(Exactly(0));

    EXPECT_CALL(*message_ops_, sd_bus_message_read_basic(message_ptr, 'y', _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.seq),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.netfn),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.lun),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.cmd),
                    Return(0)));
    EXPECT_CALL(*message_ops_, sd_bus_message_read_array(message_ptr, 'y', _, _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.payload.data()),
                    SetArgVoidPointee<3>(message.payload.size()),
                    Return(0)));

    dbus_->ipmi_dbus_handler()->HandleMessage(dbus_->dbus_message_operations(),
            message_ptr);
}

TEST_F(IpmidServerTest, UpdateRestrictedMode)
{
    sd_bus_message* message_ptr = reinterpret_cast<sd_bus_message*>(464345364531);
    DBusMemberInfo settings_info;
    settings_info.destination = "dest";
    settings_info.path = kSettingsPath;
    settings_info.interface = kSettingsInterface;
    settings_info.member = kSettingsMember;

    EXPECT_CALL(*dbus_, GetServiceMapping(kSettingsPath, _))
    .WillOnce(DoAll(SetArgPointee<1>(settings_info.destination),
                    Return(true)));

    EXPECT_CALL(*dbus_, CallMethod(settings_info,
                                   MatcherCast<const DBusInput&>(A<const StringPairInput&>()),
                                   MatcherCast<DBusOutput*>(A<BoolOutput*>())))
    .WillOnce(DoAll(WithArg<2>(
                        Invoke([this, &message_ptr](DBusOutput * out)
    {
        out->Parse(dbus_->dbus_message_operations(), message_ptr);
    })),
    Return(true)));

    EXPECT_CALL(*message_ops_, sd_bus_message_read_basic(message_ptr, 'b', _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(false),
                    Return(0)));

    server_.UpdateRestrictedMode();

    IpmiContext context;
    context.context = message_ptr;
    IpmiMessage message;
    message.netfn = 'x';
    message.lun = 3;
    message.seq = 57;
    message.cmd = 'y';
    message.payload = {'a', 'b', 'c'};
    EXPECT_CALL(*root_router_, HandleRequest(context, message))
    .WillOnce(Return(true));

    EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                sd_bus_message_read_basic(message_ptr, 'y', _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.seq),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.netfn),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.lun),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.cmd),
                    Return(0)));
    EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                sd_bus_message_read_array(message_ptr, 'y', _, _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.payload.data()),
                    SetArgVoidPointee<3>(message.payload.size()),
                    Return(0)));

    dbus_->ipmi_dbus_handler()->HandleMessage(dbus_->dbus_message_operations(),
            message_ptr);
}

TEST_F(IpmidServerTest, UpdateRestrictedModeFromDBus)
{
    sd_bus_message* message_ptr = reinterpret_cast<sd_bus_message*>(465468763146);
    DBusMemberInfo settings_info;
    settings_info.destination = "dest";
    settings_info.path = kSettingsPath;
    settings_info.interface = kSettingsInterface;
    settings_info.member = kSettingsMember;

    EXPECT_CALL(*dbus_, GetServiceMapping(kSettingsPath, _))
    .WillOnce(DoAll(SetArgPointee<1>(settings_info.destination),
                    Return(true)));

    EXPECT_CALL(*dbus_, CallMethod(settings_info,
                                   MatcherCast<const DBusInput&>(A<const StringPairInput&>()),
                                   MatcherCast<DBusOutput*>(A<BoolOutput*>())))
    .WillOnce(Return(true));

    dbus_->restricted_mode_dbus_handler()->HandleMessage(
        dbus_->dbus_message_operations(), message_ptr);
}

TEST_F(IpmidServerTest, IpmiMessageFromDBus)
{
    sd_bus_message* message_ptr = reinterpret_cast<sd_bus_message*>(768458746);

    IpmiMessage message;
    message.netfn = 'a';
    message.lun = 3;
    message.seq = 57;
    message.cmd = 'b';
    message.payload = {'a', 'b', 'c'};

    EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                sd_bus_message_read_basic(message_ptr, 'y', _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.seq),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.netfn),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.lun),
                    Return(0)))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.cmd),
                    Return(0)));
    EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                sd_bus_message_read_array(message_ptr, 'y', _, _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.payload.data()),
                    SetArgVoidPointee<3>(message.payload.size()),
                    Return(0)));

    IpmiContext context;
    context.context = message_ptr;
    EXPECT_CALL(*root_router_, HandleRequest(context, message))
    .Times(Exactly(1));

    dbus_->ipmi_dbus_handler()->HandleMessage(dbus_->dbus_message_operations(),
            message_ptr);
}

TEST_F(IpmidServerTest, UnparsableIpmiMessageFromDBus)
{
    sd_bus_message* message_ptr = reinterpret_cast<sd_bus_message*>(6543645463);

    IpmiMessage message;
    message.netfn = 'a';
    message.lun = 3;
    message.seq = 57;
    message.cmd = 'b';
    message.payload = {'a', 'b', 'c'};
    EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                sd_bus_message_read_basic(message_ptr, 'y', _))
    .WillOnce(DoAll(SetArgVoidPointee<2>(message.seq),
                    Return(-1)));

    EXPECT_CALL(*root_router_, HandleRequest(_, _))
    .Times(Exactly(0));

    dbus_->ipmi_dbus_handler()->HandleMessage(dbus_->dbus_message_operations(),
            message_ptr);
}

TEST_F(IpmidServerTest, RootRouterSendResponse)
{
    sd_bus_message* message_ptr = reinterpret_cast<sd_bus_message*>(56446154656);
    DBusMemberInfo ipmi_host_info;
    ipmi_host_info.destination = "dest";
    ipmi_host_info.path = "path";
    ipmi_host_info.interface = kHostIpmiInterface;
    ipmi_host_info.member = kHostIpmiMember;
    EXPECT_CALL(*message_ops_, sd_bus_message_get_sender(message_ptr))
    .WillOnce(Return(const_cast<char*>(ipmi_host_info.destination.c_str())));
    EXPECT_CALL(*message_ops_, sd_bus_message_get_path(message_ptr))
    .WillOnce(Return(const_cast<char*>(ipmi_host_info.path.c_str())));

    IpmiContext context;
    context.context = message_ptr;
    IpmiMessage message;
    message.netfn = 'a';
    message.lun = 3;
    message.seq = 57;
    message.cmd = 'b';
    message.payload = {'a', 'b', 'c'};
    EXPECT_CALL(*dbus_, CallMethod(ipmi_host_info,
                                   MatcherCast<const DBusInput&>(A<const IpmiMessageInput&>()),
                                   MatcherCast<DBusOutput*>(A<VoidOutput*>())))
    .WillOnce(DoAll(WithArg<1>(
                        Invoke([this, &message_ptr](const DBusInput & input)
    {
        input.Compose(dbus_->mock_dbus_message_operations(), message_ptr);
    })),
    Return(true)));

    {
        InSequence seq;
        EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                    sd_bus_message_append_basic(message_ptr, 'y', VoidPointee(message.seq)))
        .Times(Exactly(1))
        .RetiresOnSaturation();
        EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                    sd_bus_message_append_basic(message_ptr, 'y', VoidPointee(message.netfn)))
        .Times(Exactly(1));
        EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                    sd_bus_message_append_basic(message_ptr, 'y', VoidPointee(message.lun)))
        .Times(Exactly(1));
        EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                    sd_bus_message_append_basic(message_ptr, 'y', VoidPointee(message.cmd)))
        .Times(Exactly(1));
        EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                    sd_bus_message_append_basic(message_ptr, 'y', VoidPointee(message.payload[0])))
        .Times(Exactly(1));
        EXPECT_CALL(dbus_->mock_dbus_message_operations(),
                    sd_bus_message_append_array(message_ptr, 'y', VoidArray({'b', 'c'}), 2))
        .Times(Exactly(1));
    }

    root_router_->SendResponse(context, message);
}

} // namespace ipmid
