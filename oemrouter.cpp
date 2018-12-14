#include <cstdio>
#include <cstring>
#include <ipmid/oemrouter.hpp>
#include <map>
#include <utility>

namespace oem
{

using Key = std::pair<Number, ipmi_cmd_t>;

// Private implementation of OemRouter Interface.
class RouterImpl : public Router
{
  public:
    RouterImpl()
    {
    }

    // Implement OemRouter Interface.
    void activate() override;
    void registerHandler(Number oen, ipmi_cmd_t cmd, Handler handler) override;

    // Actual message routing function.
    ipmi_ret_t routeMsg(ipmi_cmd_t cmd, const uint8_t* reqBuf,
                        uint8_t* replyBuf, size_t* dataLen);

  private:
    std::map<Key, Handler> handlers;
};

// Static global instance for simplicity.
static RouterImpl* globalRouterImpl;

// TODO Refactor ipmid to avoid need for singleton here.
Router* mutableRouter()
{
    if (!globalRouterImpl)
    {
        globalRouterImpl = new RouterImpl;
    }
    return globalRouterImpl;
}

ipmi_ret_t RouterImpl::routeMsg(ipmi_cmd_t cmd, const uint8_t* reqBuf,
                                uint8_t* replyBuf, size_t* dataLen)
{
    // Not entirely clear we can route reply without complete OEM group.
    // TODO: consider adding a way to suppress malformed replies.
    if (*dataLen < groupMagicSize)
    {
        std::fprintf(stderr, "NetFn:[0x2E], OEM:[%zu bytes?], Cmd:[%#04X]\n",
                     *dataLen, cmd);
        (*dataLen) = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // Find registered handler or reject request.
    auto number = toOemNumber(reqBuf);
    auto cmdKey = std::make_pair(number, cmd);

    auto iter = handlers.find(cmdKey);
    if (iter == handlers.end())
    {
        auto wildKey = std::make_pair(number, IPMI_CMD_WILDCARD);
        iter = handlers.find(wildKey);
        if (iter == handlers.end())
        {
            std::fprintf(stderr,
                         "No Registered handler for NetFn:[0x2E], "
                         "OEM:[%#08X], Cmd:[%#04X]\n",
                         number, cmd);
            *dataLen = groupMagicSize;
            return IPMI_CC_INVALID;
        }
#ifdef __IPMI_DEBUG__
        std::fprintf(stderr,
                     "Wildcard NetFn:[0x2E], OEM:[%#08X], Cmd:[%#04X]\n",
                     number, cmd);
#endif
    }
    else
    {
#ifdef __IPMI_DEBUG__
        std::fprintf(stderr, "Match NetFn:[0x2E], OEM:[%#08X], Cmd:[%#04X]\n",
                     number, cmd);
#endif
    }

    // Copy OEMGroup here, by analogy to IPMI CC code at netfn router;
    // OemHandler should deal only with optional following data bytes.
    std::memcpy(replyBuf, reqBuf, groupMagicSize);

    size_t oemDataLen = *dataLen - groupMagicSize;
    Handler& handler = iter->second;

    auto rc = handler(cmd, reqBuf + groupMagicSize, replyBuf + groupMagicSize,
                      &oemDataLen);

    // Add OEMGroup bytes to nominal reply.
    *dataLen = oemDataLen + groupMagicSize;
    return rc;
}

// Function suitable for use as ipmi_netfn_router() call-back.
// Translates call-back pointer args to more specific types.
ipmi_ret_t ipmi_oem_wildcard_handler(ipmi_netfn_t /* netfn */, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    // View requests & responses as byte sequences.
    const uint8_t* reqBuf = static_cast<uint8_t*>(request);
    uint8_t* replyBuf = static_cast<uint8_t*>(response);

    // View context as router object, defaulting nullptr to global object.
    auto router = static_cast<RouterImpl*>(context ? context : mutableRouter());

    // Send message parameters to dispatcher.
    return router->routeMsg(cmd, reqBuf, replyBuf, dataLen);
}

// Enable message routing to begin.
void RouterImpl::activate()
{
    // Register netfn 0x2e OEM Group, any (wildcard) command.
    std::printf("Registering NetFn:[0x%X], Cmd:[0x%X]\n", NETFUN_OEM_GROUP,
                IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_OEM_GROUP, IPMI_CMD_WILDCARD, this,
                           ipmi_oem_wildcard_handler, PRIVILEGE_OEM);
}

void RouterImpl::registerHandler(Number oen, ipmi_cmd_t cmd, Handler handler)
{
    auto cmdKey = std::make_pair(oen, cmd);
    auto iter = handlers.find(cmdKey);
    if (iter == handlers.end())
    {
        // Add handler if key not already taken.
        handlers.emplace(cmdKey, handler);
    }
    else
    {
        std::fprintf(stderr,
                     "ERROR : Duplicate registration for NetFn:[0x2E], "
                     "OEM:[%#08X], Cmd:[%#04X]\n",
                     oen, cmd);
    }
}

} // namespace oem
