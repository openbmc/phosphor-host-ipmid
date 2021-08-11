ipmid_pre = [
  systemd,
  sdbusplus_dep,
]

libipmid = static_library(
  'ipmid',
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
  link_with: libipmid,
)

shared_module(
  'ipmid',
  implicit_include_directories: false,
  dependencies: [
    ipmid_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers',
)

import('pkgconfig').generate(
  libipmid,
  name: 'libipmid',
  version: meson.project_version(),
  description: 'ipmid',
)
