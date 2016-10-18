#ifndef IPMID_SERVER_HPP_
#define IPMID_SERVER_HPP_

#include <memory>
#include <string>
#include <vector>

#include "dbus.hpp"
#include "ipmid-router.hpp"
#include "host-ipmid/ipmid-api.h"

namespace ipmid
{

extern const char* const kHostIpmiMatch;
extern const char* const kHostIpmiInterface;
extern const char* const kHostIpmiMember;

extern const char* const kSettingsMatch;
extern const char* const kSettingsDestination;
extern const char* const kSettingsPath;
extern const char* const kSettingsInterface;
extern const char* const kSettingsMember;

class IpmiMessageInput : public DBusInput
{
    public:
        explicit IpmiMessageInput(const IpmiMessage& message) : ipmi_message_
            (message) {}

        void Compose(const DBusMessageOperations& ops,
                     sd_bus_message* dbus_message) const override;

    private:
        const IpmiMessage& ipmi_message_;
};

class StringPairInput : public DBusInput
{
    public:
        StringPairInput(const std::string& string1, const std::string& string2)
            : string1_(string1), string2_(string2) {}

        void Compose(const DBusMessageOperations& ops,
                     sd_bus_message* dbus_message) const override;

    private:
        std::string string1_;
        std::string string2_;
};

class VoidOutput : public DBusOutput
{
    public:
        bool Parse(const DBusMessageOperations& ops, sd_bus_message* message) override
        {
            return true;
        }
};

class BoolOutput : public DBusOutput
{
    public:
        explicit BoolOutput(bool* output) : output_(output) {}

        bool Parse(const DBusMessageOperations& ops,
                   sd_bus_message* dbus_message) override;

    private:
        bool* output_;
};

// Passes IPMI messages coming in from D-Bus to the appropriate
class IpmiDBusHandler : public DBusHandler
{
    public:
        IpmiDBusHandler(RootRouter* root_router,
                        const std::vector<std::pair<uint8_t, uint8_t>>& whitelist)
            : root_router_(root_router), whitelist_(whitelist) {}

        int HandleMessage(const DBusMessageOperations& ops,
                          sd_bus_message* dbus_message) override;

        virtual int HandleMessageInternal(const IpmiContext& context,
                                          const IpmiMessage& message);

        virtual void set_restricted_mode(bool restricted_mode)
        {
            restricted_mode_ = restricted_mode;
        }

    private:
        bool restricted_mode_ = true;
        RootRouter* root_router_;
        const std::vector<std::pair<uint8_t, uint8_t>> whitelist_;
};

class RestrictedModeDBusHandler : public DBusHandler
{
    public:
        RestrictedModeDBusHandler(IpmiDBusHandler* dbus_handler, DBus* dbus)
            : dbus_handler_(dbus_handler), dbus_(dbus) {}

        virtual void UpdateRestrictedMode();

        int HandleMessage(const DBusMessageOperations& ops,
                          sd_bus_message* message) override
        {
            UpdateRestrictedMode();
            return 0;
        }

    private:
        IpmiDBusHandler* dbus_handler_;
        DBus* dbus_;
};

class IpmiMessageBusImpl : public IpmiMessageBus
{
    public:
        IpmiMessageBusImpl(DBus* dbus)
            : ops_(dbus->dbus_message_operations()), dbus_(dbus) {}

        void SendMessage(const IpmiContext& context,
                         const IpmiMessage& message) override;

    private:
        const DBusMessageOperations& ops_;
        DBus* dbus_;
};

class IpmidServer
{
    public:
        IpmidServer(std::unique_ptr<DBus>&& dbus,
                    std::unique_ptr<RootRouter>&& root_router,
                    const std::vector<std::pair<uint8_t, uint8_t>>& whitelist);

        virtual int HandleRequest();

        virtual int WaitForRequest();

        virtual void UpdateRestrictedMode()
        {
            restricted_mode_dbus_handler_.UpdateRestrictedMode();
        }

        virtual RootRouter* mutable_root_router()
        {
            return root_router_.get();
        }

        virtual DBus* mutable_dbus()
        {
            return dbus_.get();
        }

    private:
        std::unique_ptr<DBus> dbus_;
        std::unique_ptr<RootRouter> root_router_;
        IpmiDBusHandler ipmi_dbus_handler_;
        RestrictedModeDBusHandler restricted_mode_dbus_handler_;
};

} // namespace ipmid

#endif // IPMID_SERVER_HPP_
