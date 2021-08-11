gtest = dependency('gtest', main: true, disabler: true, required: false)
gmock = dependency('gmock', disabler: true, required: false)
if not gtest.found() or not gmock.found()
  gtest_opts = import('cmake').subproject_options()
  gtest_opts.add_cmake_defines({'CMAKE_CXX_FLAGS': '-Wno-pedantic'})
  gtest_proj = import('cmake').subproject(
    'googletest',
    options: gtest_opts,
    required: false)
  if gtest_proj.found()
    gtest = declare_dependency(
      dependencies: [
        dependency('threads'),
        gtest_proj.dependency('gtest'),
        gtest_proj.dependency('gtest_main'),
      ])
    gmock = gtest_proj.dependency('gmock')
  else
    assert(not get_option('tests').enabled(), 'Googletest is required')
  endif
endif

gtests = [
  'entitymap_json',
  # 'oemrouter',
  # 'dbus-sdr/sensorcommands',
  # 'session/closesession',
]

'''
test('entitymap_json', executable(
  'entitymap_json', 'entitymap_json_unittest.cpp',
  '../entity_map_json.cpp',
  include_directories: root_inc,
  build_by_default: false,
  implicit_include_directories: false,
  dependencies: [gtest, gmock]),
)


test('dbus-sdr/sensorcommands', executable(
  'dbus-sdr/sensorcommands', 'dbus-sdr/sensorcommands_unittest.cpp',
  '../dbus-sdr/sensorcommands.cpp',
  include_directories: root_inc,
  build_by_default: false,
  implicit_include_directories: false,
  dependencies: [gtest, gmock]),
)
'''
