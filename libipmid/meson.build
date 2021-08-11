ipmid_pre = [
  boost_coroutine,
  phosphor_dbus_interfaces_dep,
  sdbusplus_dep,
  systemd,
]

libipmid = library(
  'ipmid',
  'sdbus-asio.cpp',
  'signals.cpp',
  'systemintf-sdbus.cpp',
  'utils.cpp',
  dependencies: ipmid_pre,
  include_directories: root_inc,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir'),
)

ipmid_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: libipmid,
)

import('pkgconfig').generate(
  libipmid,
  name: 'libipmid',
  version: meson.project_version(),
  description: 'ipmid',
)
