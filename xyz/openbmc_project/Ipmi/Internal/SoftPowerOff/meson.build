sdbuspp_prog = find_program('sdbus++')

domain = 'xyz.openbmc_project.Ipmi.Internal.SoftPowerOff'
if_yaml_file = files('../SoftPowerOff.interface.yaml')

if_cpp = custom_target(
  'server.cpp',
  output: 'server.cpp',
  input: if_yaml_file,
  capture: true,
  command: [sdbuspp_prog, '-r', root, 'interface', 'server-cpp', domain])

if_hpp = custom_target(
  'server.hpp',
  output: 'server.hpp',
  input: if_yaml_file,
  capture: true,
  command: [sdbuspp_prog, '-r', root, 'interface', 'server-header', domain],
  install: true,
  install_dir: get_option('includedir') / 'xyz/openbmc_project/Ipmi/Internal/SoftPowerOff')

if_common_hpp = custom_target(
  'common.hpp',
  output: 'common.hpp',
  input: if_yaml_file,
  capture: true,
  command: [sdbuspp_prog, '-r', root, 'interface', 'common-header', domain],
  install: true,
  install_dir: get_option('includedir') / 'xyz/openbmc_project/Ipmi/Internal/SoftPowerOff')

softoff_dbus_deps = [
  dependency('phosphor-dbus-interfaces'),
  dependency('sdbusplus'),
]

softoff_dbus_lib = library(
  'softoff-dbus',
  [
    if_cpp,
    if_hpp,
    if_common_hpp,
  ],
  implicit_include_directories: false,
  include_directories: root_inc,
  version: meson.project_version(),
  dependencies: softoff_dbus_deps,
  override_options: ['b_lundef=false'],
  install: true)

softoff_dbus = declare_dependency(
  dependencies: softoff_dbus_deps,
  sources: [if_hpp, if_common_hpp],
  link_with: softoff_dbus_lib)

softoff_dbus_reqs = []
foreach dep : softoff_dbus_deps
  if dep.type_name() == 'pkgconfig'
    softoff_dbus_reqs += dep
  endif
endforeach

import('pkgconfig').generate(
  name: 'softoff-dbus',
  description: 'SoftPowerOff DBus Bindings',
  version: meson.project_version(),
  libraries: softoff_dbus,
  requires: softoff_dbus_reqs)
