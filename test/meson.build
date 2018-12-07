gtest = dependency('gtest', main: true, disabler: true, required: build_tests)
gmock = dependency('gmock', disabler: true, required: build_tests)

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
