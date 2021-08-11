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

shared_module(
  'libipmid',
  implicit_include_directories: false,
  dependencies: [
    ipmid_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)
