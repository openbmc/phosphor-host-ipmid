sdeventplus_dep = dependency('sdeventplus', fallback: ['sdeventplus', 'sdeventplus_dep'])

ipmid_pre = [
  systemd,
  sdbusplus_dep,
]

ipmid_lib = static_library(
  'ipmid_lib',
  'sdbus-asio.cpp',
  'signals.cpp',
  'systemintf-sdbus.cpp',
  'utils.cpp',
  dependencies: ipmid_pre,
  include_directories: root_inc,
)

ipmid_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: ipmid_lib,
)
