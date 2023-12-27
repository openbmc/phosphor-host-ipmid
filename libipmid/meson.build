ipmid_pre = [
  boost_coroutine,
  phosphor_dbus_interfaces_dep,
  phosphor_logging_dep,
  sdbusplus_dep,
  systemd,
]

entity_map_json_lib = static_library(
  'entity_map_json',
  'entity_map_json.cpp',
  include_directories: root_inc,
  dependencies: [nlohmann_json_dep, sdbusplus_dep],
  implicit_include_directories: false)

entity_map_json_dep = declare_dependency(
  link_whole: entity_map_json_lib)

libipmid_src = [
  'sdbus-asio.cpp',
  'signals.cpp',
  'systemintf-sdbus.cpp',
  'utils.cpp',
]

if get_option('use-json').enabled()
  libipmid_src += [
    '../fru_map_json.cpp',
  ]
endif

libipmid = library(
  'ipmid',
  libipmid_src,
  dependencies: [ipmid_pre, entity_map_json_dep],
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
