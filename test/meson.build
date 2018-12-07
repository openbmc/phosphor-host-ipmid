gtest = dependency('gtest', main: true, required: false)
gmock = dependency('gmock', required: false)

if not gtest.found() or not gmock.found()
  assert(build_tests != 'true', 'GMock and GTest are required for tests')
  gtest = disabler()
  gmock = disabler()
endif

if build_examples
  test('sample_unittest',
       executable(
         'sample_unittest',
         'sample_unittest.cpp',
         include_directories: includes,
         implicit_include_directories: false,
         link_with: sample,
         dependencies: [gtest, gmock]))
endif
