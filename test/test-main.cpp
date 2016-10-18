#include <glog/logging.h>
#include <gtest/gtest.h>

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  ::google::InitGoogleLogging(argv[0]);
  ::google::InstallFailureSignalHandler();
  return RUN_ALL_TESTS();
}
