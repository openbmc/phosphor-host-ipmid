ipmid_pre = [
  boost_coroutine,
  phosphor_dbus_interfaces_dep,
  phosphor_logging_dep,
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
  version: meson.project_version(),
  include_directories: root_inc,
  install: true,
  install_dir: get_option('libdir'),
  override_options: ['b_lundef=false'])

ipmid_dep = declare_dependency(
  dependencies: ipmid_pre,
  include_directories: root_inc,
  link_with: libipmid)

import('pkgconfig').generate(
  libipmid,
  name: 'libipmid',
  version: meson.project_version(),
  description: 'ipmid')
