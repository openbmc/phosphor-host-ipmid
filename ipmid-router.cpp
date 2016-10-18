#include "ipmid-router.hpp"

#include <string.h>

using std::unique_ptr;

namespace ipmid
{
namespace
{
std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& vec)
{
    bool first_element = true;
    for (uint8_t elem : vec)
    {
        if (!first_element)
        {
            os << " ";
        }
        os << elem + 0;
        first_element = false;
    }
    return os;
}
} // namespace

bool IpmiMessage::operator==(const IpmiMessage& other) const
{
    return
        netfn == other.netfn &&
        lun == other.lun &&
        seq == other.seq &&
        cmd == other.cmd &&
        payload == other.payload;
}

std::ostream& operator<<(std::ostream& os, const OemGroup& oem_group)
{
    std::ios_base::fmtflags fmtflags = os.flags();
    os << std::hex;
    os << oem_group[0] << " " << oem_group[1] << " " << oem_group[2];
    os.flags(fmtflags);
    return os;
}

std::ostream& operator<<(std::ostream& os, const IpmiMessage& message)
{
    std::ios_base::fmtflags fmtflags = os.flags();
    os << std::hex;
    os << "netfn: " << message.netfn + 0 << ", "
       << "lun: " << message.lun + 0 << ", "
       << "seq: " << message.seq + 0 << ", "
       << "cmd: " << message.cmd + 0 << ", "
       << "payload: " << message.payload;
    os.flags(fmtflags);
    return os;
}

RootRouter::RootRouter(std::unique_ptr<IpmiMessageBus>&& message_bus)
    : message_bus_(std::move(message_bus)),
      oem_group_router_(new OemGroupRouter(this))
{
    RegisterHandler(kOemGroupNetFnRequest,
                    unique_ptr<IpmiHandler>(oem_group_router_));
}

void RootRouter::SendResponse(const IpmiContext& context,
                              const IpmiMessage& message)
{
    message_bus_->SendMessage(context, message);
}

bool RootRouter::HandleRequest(const IpmiContext& context,
                               const IpmiMessage& message)
{
    auto iter = handler_map_.find(message.netfn);
    if (iter == handler_map_.end())
    {
        LOG(WARNING) << "No netfn handler registered for message: " << message;
        return false;
    }
    return iter->second->HandleRequest(context, message);
}

void RootRouter::RegisterIpmidCallbackT(ipmi_netfn_t netfn,
                                        ipmi_cmd_t cmd,
                                        ipmi_context_t context,
                                        ipmid_callback_t handler)
{
    auto iter = handler_map_.find(netfn);
    if (iter == handler_map_.end())
    {
        RegisterHandler(netfn, unique_ptr<IpmiHandler>(new CommandRouter(this)));
    }
    CommandRouter* command_router = static_cast<CommandRouter*>
                                    (handler_map_[netfn].get());
    command_router->RegisterHandler(
            cmd,
            unique_ptr<IpmiHandler>(new IpmidCallbackTAdapterHandler(
                    command_router, handler, context)));
}

void OemGroupRouter::SendResponse(const IpmiContext& context,
                                  const IpmiMessage& message)
{
    root_router_->SendResponse(context, message);
}

bool OemGroupRouter::HandleRequest(const IpmiContext& context,
                                   const IpmiMessage& message)
{
    OemGroup oem_group;
    memcpy(oem_group.data(), message.payload.data(), kOemGroupMagicSize);
    auto iter = handler_map_.find(oem_group);
    if (iter == handler_map_.end())
    {
        LOG(WARNING) << "No OEM group handler registered for message: " << message
                     << " with oem_group: " << oem_group;
        return false;
    }
    return iter->second->HandleRequest(context, message);
}

void CommandRouter::SendResponse(const IpmiContext& context,
                                 const IpmiMessage& message)
{
    root_router_->SendResponse(context, message);
}

bool CommandRouter::HandleRequest(const IpmiContext& context,
                                  const IpmiMessage& message)
{
    auto iter = handler_map_.find(message.cmd);
    if (iter == handler_map_.end())
    {
        LOG(WARNING) << "No cmd handler registered for message: " << message;
        return false;
    }
    return iter->second->HandleRequest(context, message);
}

bool IpmidCallbackTAdapterHandler::HandleRequest(const IpmiContext& context,
                                                 const IpmiMessage& request)
{
    IpmiMessage response;
    response.netfn = request.netfn | 1;
    response.lun = request.lun;
    response.seq = request.seq;
    response.cmd = request.cmd;
    response.payload.resize(kIpmiMaxPayloadSize);

    size_t size = request.payload.size();
    ipmi_request_t request_payload = const_cast<uint8_t*>(request.payload.data());
    ipmi_response_t response_payload = response.payload.data();
    callback_(request.netfn, request.cmd, request_payload, response_payload, &size,
              context_);
    response.payload.resize(size);
    router_->SendResponse(context, response);
    return true;
}

} // namespace ipmid
