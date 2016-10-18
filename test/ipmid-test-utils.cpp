#include "ipmid-test-utils.hpp"

using std::to_string;

namespace ipmid
{

// For verifying argument values. Not a strong enough comparison for anything
// else.
bool operator==(const IpmiContext& left, const IpmiContext& right)
{
    return left.context == right.context;
}

void PrintTo(const IpmiMessage& message, ::std::ostream* os)
{
    *os << "netfn = " << to_string(message.netfn) << ", "
        << "lun = " << to_string(message.lun) << ", "
        << "seq = " << to_string(message.seq) << ", "
        << "cmd = " << to_string(message.cmd) << ", "
        << "payload = " << ::testing::PrintToString(message.payload);
}

} // namespace ipmid
