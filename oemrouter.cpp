#include <cstdio>
#include <cstring>
#include <map>
#include <utility>

#include "host-ipmid/oemrouter.hpp"

namespace ipmid
{

using OemKey = std::pair<OemNumber, ipmi_cmd_t>;

// Private implementation of OemRouter Interface.
class OemRouterImpl : public OemRouter
{
    public:
        OemRouterImpl() {}

        // Implement OemRouter Interface.
        void activate() override;
        void registerHandler(OemNumber oen, ipmi_cmd_t cmd,
                             OemHandler handler) override;

        // Actual message routing function.
        ipmi_ret_t routeMsg(ipmi_cmd_t cmd, const Byte* reqBuf,
                            Byte* replyBuf, size_t* dataLen);

    private:
        std::map<OemKey, OemHandler> oemHandlers;
};

// Static global instance for simplicity.
static OemRouterImpl* globalOemRouterImpl;

// TODO Refactor impid to avoid need for singleton here.
OemRouter* mutableOemRouter()
{
    if (!globalOemRouterImpl)
    {
        globalOemRouterImpl = new OemRouterImpl;
    }
    return globalOemRouterImpl;
}

ipmi_ret_t OemRouterImpl::routeMsg(ipmi_cmd_t cmd, const Byte* reqBuf,
                                   Byte* replyBuf, size_t* dataLen)
{
    // Not entirely clear we can route reply without complete OEM group.
    // TODO: consider adding a way to suppress malformed replies.
    if (*dataLen < oemGroupMagicSize)
    {
        fprintf(stderr, "NetFn:[0x2E], OEM:[%lu bytes?], Cmd:[%#04X]\n",
                *dataLen, cmd);
        if (*dataLen)
        {
            memcpy(replyBuf, reqBuf, *dataLen);
        }
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // Find registered handler or reject request.
    auto oemNumber = toOemNumber(reqBuf);
    auto oemCmdKey = std::make_pair(oemNumber, cmd);
    auto iter = oemHandlers.find(oemCmdKey);
    if (iter == oemHandlers.end())
    {
        auto oemWildKey = std::make_pair(oemNumber, IPMI_CMD_WILDCARD);
        iter = oemHandlers.find(oemWildKey);
        if (iter == oemHandlers.end())
        {
            fprintf(stderr, "No Registered handler for NetFn:[0x2E], "
                    "OEM:[%#08X], Cmd:[%#04X]\n", oemNumber, cmd);
            *dataLen = oemGroupMagicSize;
            return IPMI_CC_INVALID;
        }
#ifdef __IPMI_DEBUG__
        fprintf(stderr, "Wildcard NetFn:[0x2E], OEM:[%#08X], Cmd:[%#04X]\n",
                oemNumber, cmd);
#endif
    }
    else
    {
#ifdef __IPMI_DEBUG__
        fprintf(stderr, "Match NetFn:[0x2E], OEM:[%#08X], Cmd:[%#04X]\n",
                oemNumber, cmd);
#endif
    }

    // Copy OEMGroup here, by analogy to IPMI CC code at netfn router;
    // OemHandler should deal only with optional following data bytes.
    memcpy(replyBuf, reqBuf, oemGroupMagicSize);
    size_t oemDataLen = *dataLen - oemGroupMagicSize;
    OemHandler& oemHandler = iter->second;
    auto rc = oemHandler(cmd, reqBuf + oemGroupMagicSize,
                         replyBuf + oemGroupMagicSize, &oemDataLen);
    // Add OEMGroup bytes to nominal reply.
    *dataLen = oemDataLen + oemGroupMagicSize;
    return rc;
}

// Function suitable for use as ipmi_netfn_router() call-back.
// Translates call-back pointer args to more specific types.
ipmi_ret_t ipmi_oem_wildcard_handler(ipmi_netfn_t /* netfn */,
                                     ipmi_cmd_t cmd, ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    // View requests & responses as byte sequences.
    const Byte* reqBuf = static_cast<Byte*>(request);
    Byte* replyBuf = static_cast<Byte*>(response);

    // View context as router object, defaulting nullptr to global object.
    auto oemRouter = static_cast<OemRouterImpl*>(context ? context :
                                                           mutableOemRouter());

    // Send message parameters to dispatcher.
    return oemRouter->routeMsg(cmd, reqBuf, replyBuf, dataLen);
}

// Enable message routing to begin.
void OemRouterImpl::activate()
{
    // Register netfn 0x2e OEM Group, any (wildcard) command.
    printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n",
           NETFUN_OEM_GROUP, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_OEM_GROUP, IPMI_CMD_WILDCARD, this,
                           ipmi_oem_wildcard_handler, PRIVILEGE_OEM);
}

void OemRouterImpl::registerHandler(OemNumber oen, ipmi_cmd_t cmd,
                                    OemHandler handler)
{
    auto oemCmdKey = std::make_pair(oen, cmd);
    auto iter = oemHandlers.find(oemCmdKey);
    if (iter == oemHandlers.end())
    {
        // Add handler if key not already taken.
        oemHandlers.emplace(oemCmdKey, handler);
    }
    else
    {
        fprintf(stderr, "ERROR : Duplicate registration for NetFn:[0x2E], "
                "OEM:[%#08X], Cmd:[%#04X]\n", oen, cmd);
    }
}

}  // namespace ipmid
