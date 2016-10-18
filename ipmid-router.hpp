#ifndef IPMID_ROUTER_HPP_
#define IPMID_ROUTER_HPP_

#include <array>
#include <map>
#include <memory>
#include <vector>

#include <glog/logging.h>
#include "host-ipmid/ipmid-api.h"

namespace ipmid
{

static const uint8_t kOemGroupNetFnRequest = 0x2e;
static const uint8_t kOemGroupNetFnResponse = 0x2f;
static const size_t kOemGroupMagicSize = 3;

typedef std::array<uint8_t, kOemGroupMagicSize> OemGroup;

static const size_t kIpmiMaxMessageSize = 255;
static const size_t kIpmiMaxHeaderSize = 3;
static const size_t kIpmiMaxPayloadSize = kIpmiMaxMessageSize -
        kIpmiMaxHeaderSize;

// Any context required for the IpmiMessageBus that does not fit nicely into an
// IpmiMessage.
struct IpmiContext
{
    sd_bus_message* context;
};

// Abstract IPMI message, it makes no assumptions about the actual wire format
// or framing of the message.
struct IpmiMessage
{
    uint8_t netfn = 0;
    uint8_t lun = 0;
    uint8_t seq = 0;
    uint8_t cmd = 0;
    std::vector<uint8_t> payload;

    bool operator==(const IpmiMessage& other) const;
};

std::ostream& operator<<(std::ostream& os, const IpmiMessage& message);

std::ostream& operator<<(std::ostream& os, const OemGroup& oem_group);

// Abstraction on top of SD Bus for testing.
class IpmiMessageBus
{
    public:
        virtual ~IpmiMessageBus() {}

        virtual void SendMessage(const IpmiContext& context,
                                 const IpmiMessage& message) = 0;
};

// Interface for anything that handles an IPMI request.
class IpmiHandler
{
    public:
        virtual ~IpmiHandler() {}

        virtual bool HandleRequest(const IpmiContext& context,
                                   const IpmiMessage& message) = 0;
};

// IPMI messages are routed to the appropriate handler through a tree of
// routers.
//
// IPMI messages are broken up into several namespaces of messages by the netfn
// field. If the message is an OEM Group Extension, it is associated with a
// particular OEM/Vendor with the first three bytes of the payload, the
// OemGroup; thus, this is the next level of routing for these messages; it is
// up to the group extension on how to interpret the remaining fields. If the
// message is not an extension, it is routed to the appropriate handler based on
// the cmd field.
template<typename RouterKeyT>
class IpmiRouter : public IpmiHandler
{
    public:
        virtual void RegisterHandler(RouterKeyT router_key,
                                     std::unique_ptr<IpmiHandler>&& handler)
        {
            if (handler_map_.find(router_key) != handler_map_.end())
            {
                LOG(ERROR) << "Attempted to register handler for a key that is already "
                           << "associated with a handler: " << router_key;
            }
            handler_map_[router_key] = std::move(handler);
        }

        virtual void SendResponse(const IpmiContext& context,
                                  const IpmiMessage& message) = 0;

        virtual bool HandleRequest(const IpmiContext& context,
                                   const IpmiMessage& message) override = 0;

    protected:
        std::map<RouterKeyT, std::unique_ptr<IpmiHandler>> handler_map_;
};

class OemGroupRouter;

// The root of the IPMI routing tree, it routes messages to sub-handlers based
// on the netfn field.
class RootRouter : public IpmiRouter<ipmi_netfn_t>
{
    public:
        RootRouter(std::unique_ptr<IpmiMessageBus>&& message_bus);

        virtual void SendResponse(const IpmiContext& context,
                                  const IpmiMessage& message) override;

        // For registering old style ipmid_callback_t handlers.
        virtual void RegisterIpmidCallbackT(ipmi_netfn_t netfn,
                                            ipmi_cmd_t cmd,
                                            ipmi_context_t context,
                                            ipmid_callback_t handler);

        virtual bool HandleRequest(const IpmiContext& context,
                                   const IpmiMessage& message) override;

        OemGroupRouter* mutable_oem_group_router()
        {
            return oem_group_router_;
        }

    private:
        std::unique_ptr<IpmiMessageBus> message_bus_;
        OemGroupRouter* oem_group_router_;
};

// Routes OEM Group Extension messages.
class OemGroupRouter : public IpmiRouter<OemGroup>
{
    public:
        OemGroupRouter(RootRouter* root_router) : root_router_(root_router) {}

        virtual void SendResponse(const IpmiContext& context,
                                  const IpmiMessage& message) override;

        virtual bool HandleRequest(const IpmiContext& context,
                                   const IpmiMessage& message) override;

    private:
        RootRouter* root_router_;
};

// Routes IPMI messages based on the cmd field.
class CommandRouter : public IpmiRouter<ipmi_cmd_t>
{
    public:
        CommandRouter(RootRouter* root_router) : root_router_(root_router) {}

        virtual void SendResponse(const IpmiContext& context,
                                  const IpmiMessage& message) override;

        virtual bool HandleRequest(const IpmiContext& context,
                                   const IpmiMessage& message) override;

    private:
        RootRouter* root_router_;
};

// Adapter for old style ipmid_callback_t handlers.
class IpmidCallbackTAdapterHandler : public IpmiHandler
{
    public:
        IpmidCallbackTAdapterHandler(CommandRouter* router,
                                     ipmid_callback_t callback,
                                     ipmi_context_t context)
            : router_(router), callback_(callback), context_(context) {}

        bool HandleRequest(const IpmiContext& context,
                           const IpmiMessage& message) override;

    private:
        CommandRouter* router_;
        ipmid_callback_t callback_;
        ipmi_context_t context_;
};

} // namespace ipmid

#endif // IPMID_ROUTER_HPP_
