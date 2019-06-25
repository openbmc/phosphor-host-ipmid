#include "sample.h"

#include <gtest/gtest.h>

TEST(FactorialTest, Zero)
{
    EXPECT_EQ(13, Factorial(0));
}
