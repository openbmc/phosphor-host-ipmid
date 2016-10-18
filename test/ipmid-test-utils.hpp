#include <ostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "ipmid-router.hpp"

namespace ipmid
{

// For verifying argument values. Not a strong enough comparison for anything
// else.
bool operator==(const IpmiContext& left, const IpmiContext& right);

void PrintTo(const IpmiMessage& message, ::std::ostream* os);

template <typename T>
class VoidPointeeMatcher : public ::testing::MatcherInterface<const void*>
{
    public:
        VoidPointeeMatcher(const T& expected) : expected_(expected) {}

        bool MatchAndExplain(const void* ptr,
                             ::testing::MatchResultListener*) const override
        {
            return *static_cast<const T*>(ptr) == expected_;
        }

        void DescribeTo(std::ostream* os) const override
        {
            *os << "is equal to " << ::testing::PrintToString(expected_);
        }

        void DescribeNegationTo(std::ostream* os) const override
        {
            *os << "is not equal to " << ::testing::PrintToString(expected_);
        }

    private:
        const T& expected_;
};

template <typename T>
inline ::testing::Matcher<const void*> VoidPointee(const T& expected)
{
    return ::testing::MakeMatcher(new VoidPointeeMatcher<T>(expected));
}

template <typename T>
class VoidArrayMatcher : public ::testing::MatcherInterface<const void*>
{
    public:
        template <typename Iter>
        VoidArrayMatcher(Iter first, Iter last) : expected_container_(first, last) {}

        bool MatchAndExplain(const void* ptr,
                             ::testing::MatchResultListener*) const override
        {
            int i = 0;
            const T* actual_array = static_cast<const T*>(ptr);
            for (const T& expected_elem : expected_container_)
            {
                if (expected_elem != actual_array[i++])
                {
                    return false;
                }
            }
            return true;
        }

        void DescribeTo(std::ostream* os) const override
        {
            *os << "is equal to " << ::testing::PrintToString(expected_container_);
        }

        void DescribeNegationTo(std::ostream* os) const override
        {
            *os << "is not equal to " << ::testing::PrintToString(expected_container_);
        }

    private:
        std::vector<T> expected_container_;
};

template <typename Iter>
inline ::testing::Matcher<const void*> VoidArray(Iter first, Iter last)
{
    typedef typename std::iterator_traits<Iter>::value_type T;
    return ::testing::MakeMatcher(new VoidArrayMatcher<T>(first, last));
}

template <typename Container>
inline ::testing::Matcher<const void*> VoidArray(const Container& expected)
{
    return VoidArray(expected.begin(), expected.end());
}

template <typename T>
inline ::testing::Matcher<const void*> VoidArray(std::initializer_list<T>
        expected)
{
    return VoidArray(expected.begin(), expected.end());
}

template <size_t N, typename T>
class SetArgVoidPointeeAction
{
    public:
        SetArgVoidPointeeAction(const T& value_to_set) : value_to_set_(value_to_set) {}

        template <typename Result, typename Args>
        void Perform(const Args& args)
        {
            // It is possible to have something like const void** passed in and we
            // should still be allowed to set the value.
            *((T*) ::testing::get<N>(args)) = value_to_set_;
        }

    private:
        const T& value_to_set_;
};

template <size_t N, typename T>
::testing::PolymorphicAction<SetArgVoidPointeeAction<N, T>> SetArgVoidPointee(
            T value_to_set)
{
    return ::testing::MakePolymorphicAction(SetArgVoidPointeeAction<N, T>
                                            (value_to_set));
}

} // namespace ipmid
