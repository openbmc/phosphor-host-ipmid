#include "ipmid-server.hpp"

#include <algorithm>
#include <utility>
#include <string.h>
#include <glog/logging.h>

using std::pair;
using std::unique_ptr;
using std::vector;

namespace ipmid
{

const char* const kHostIpmiMatch = "type='signal',interface='org.openbmc.HostIpmi',member='ReceivedMessage'";
const char* const kHostIpmiInterface = "org.openbmc.HostIpmi";
const char* const kHostIpmiMember = "sendMessage";

const char* const kSettingsMatch =
    "type='signal',interface='org.freedesktop.DBus.Properties',"
    "path='/org/openbmc/settings/host0'";
const char* const kSettingsDestination = "org.freedesktop.DBus.Properties";
const char* const kSettingsPath = "/org/openbmc/settings/host0";
const char* const kSettingsInterface = "org.freedesktop.DBus.Properties";
const char* const kSettingsMember = "Get";

void IpmiMessageInput::Compose(const DBusMessageOperations& ops,
                               sd_bus_message* dbus_message) const
{
    ops.sd_bus_message_append_basic(dbus_message, 'y', &ipmi_message_.seq);
    ops.sd_bus_message_append_basic(dbus_message, 'y', &ipmi_message_.netfn);
    ops.sd_bus_message_append_basic(dbus_message, 'y', &ipmi_message_.lun);
    ops.sd_bus_message_append_basic(dbus_message, 'y', &ipmi_message_.cmd);
    ops.sd_bus_message_append_basic(dbus_message, 'y', &ipmi_message_.payload[0]);
    ops.sd_bus_message_append_array(dbus_message, 'y',
                                    ipmi_message_.payload.data() + 1,
                                    ipmi_message_.payload.size() - 1);
}

void StringPairInput::Compose(const DBusMessageOperations& ops,
                              sd_bus_message* dbus_message) const
{
    ops.sd_bus_message_append_basic(dbus_message, 's', string1_.c_str());
    ops.sd_bus_message_append_basic(dbus_message, 's', string2_.c_str());
}

bool BoolOutput::Parse(const DBusMessageOperations& ops,
                       sd_bus_message* dbus_message)
{
    if (ops.sd_bus_message_enter_container(dbus_message, 'v', "b") < 0)
    {
        return false;
    }
    if (ops.sd_bus_message_read_basic(dbus_message, 'b', output_) < 0)
    {
        return false;
    }
    return true;
}

int IpmiDBusHandler::HandleMessage(const DBusMessageOperations& ops,
                                   sd_bus_message* dbus_message)
{
    IpmiMessage message;
    const char* payload;
    size_t payload_size;

    if (ops.sd_bus_message_read_basic(dbus_message, 'y', &message.seq) < 0)
    {
        return -1;
    }
    if (ops.sd_bus_message_read_basic(dbus_message, 'y', &message.netfn) < 0)
    {
        return -1;
    }
    if (ops.sd_bus_message_read_basic(dbus_message, 'y', &message.lun) < 0)
    {
        return -1;
    }
    if (ops.sd_bus_message_read_basic(dbus_message, 'y', &message.cmd) < 0)
    {
        return -1;
    }
    if (ops.sd_bus_message_read_array(dbus_message, 'y',
                                      reinterpret_cast<const void**>(&payload),
                                      &payload_size) < 0)
    {
        return -1;
    }
    message.payload.assign(payload, payload + payload_size);
    IpmiContext context;
    context.context = dbus_message;
    return HandleMessageInternal(context, message);
}

int IpmiDBusHandler::HandleMessageInternal(const IpmiContext& context,
        const IpmiMessage& ipmi_message)
{
    // TODO: This is from the original implementation. I am not sure what
    // restricted mode is actually for; this should be discussed further.
    if (restricted_mode_ &&
        !std::binary_search(whitelist_.cbegin(),
                            whitelist_.cend(),
                            std::make_pair(ipmi_message.netfn, ipmi_message.cmd)))
    {
        LOG(WARNING) << "Recieved non-whitelisted IPMI message: " << ipmi_message;
        return IPMI_CC_INSUFFICIENT_PRIVILEGE;
    }
    VLOG(1) << "Sending message to router: " << ipmi_message;
    if (root_router_->HandleRequest(context, ipmi_message))
    {
        VLOG(1) << "IPMI message handled by router.";
        return 0;
    }
    else
    {
        LOG(WARNING) << "IPMI message was not handled by router: " << ipmi_message;
        return IPMI_CC_INVALID;
    }
}

void RestrictedModeDBusHandler::UpdateRestrictedMode()
{
    bool restricted_mode;
    StringPairInput input("org.openbmc.settings.Host", "restricted_mode");
    BoolOutput output(&restricted_mode);
    DBusMemberInfo info;
    if (!dbus_->GetServiceMapping(kSettingsPath, &info.destination))
    {
        return;
    }
    info.path = kSettingsPath;
    info.interface = kSettingsInterface;
    info.member = kSettingsMember;
    if (!dbus_->CallMethod(info, input, &output))
    {
        LOG(WARNING) << "DBus call failed.";
        return;
    }
    dbus_handler_->set_restricted_mode(restricted_mode);
    LOG(INFO) << "Restricted mode updated.";
}

void IpmiMessageBusImpl::SendMessage(const IpmiContext& context,
                                     const IpmiMessage& message)
{
    DBusMemberInfo info;
    info.destination = ops_.sd_bus_message_get_sender(context.context);
    info.path = ops_.sd_bus_message_get_path(context.context);
    info.interface = kHostIpmiInterface;
    info.member = kHostIpmiMember;
    IpmiMessageInput input(message);
    VoidOutput output;
    dbus_->CallMethod(info, input, &output);
}

IpmidServer::IpmidServer(unique_ptr<DBus>&& dbus,
                         unique_ptr<RootRouter>&& root_router,
                         const vector<pair<uint8_t, uint8_t>>& whitelist)
    : dbus_(std::move(dbus)),
      root_router_(std::move(root_router)),
      ipmi_dbus_handler_(root_router_.get(), whitelist),
      restricted_mode_dbus_handler_(&ipmi_dbus_handler_, dbus_.get())
{
    dbus_->RegisterHandler(kHostIpmiMatch, &ipmi_dbus_handler_);
    dbus_->RegisterHandler(kSettingsMatch, &restricted_mode_dbus_handler_);
}

int IpmidServer::HandleRequest()
{
    return dbus_->ProcessMessage();
}

int IpmidServer::WaitForRequest()
{
    return dbus_->WaitForMessage();
}

} // namespace ipmid
