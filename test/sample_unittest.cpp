#include "sample.h"
#include "gtest/gtest.h"

TEST(FactorialTest, Zero) {
  EXPECT_EQ(1, Factorial(0));
}

//int main(int argc, char **argv) {
//  ::testing::InitGoogleTest(&argc, argv);
//  return RUN_ALL_TESTS();
//}
