user_channel_inc = include_directories('.')

channellayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    crypto,
    ipmid_dep,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    systemd,
  ])

channellayer_src = [
  'channel_layer.cpp',
  'channel_mgmt.cpp',
  'cipher_mgmt.cpp',
]

channellayer_lib = library(
  'channellayer',
  channellayer_src,
  implicit_include_directories: false,
  dependencies: channellayer_pre,
  version: meson.project_version(),
  install: true,
  install_dir: get_option('libdir'),
  override_options: ['b_lundef=false'])

channellayer_dep = declare_dependency(
  link_with: channellayer_lib,
  dependencies: channellayer_pre)

import('pkgconfig').generate(
  channellayer_lib,
  name: 'libchannellayer',
  version: meson.project_version(),
  description: 'libchannellayer')

if not get_option('libuserlayer').disabled()
  userlayer_pre = declare_dependency(
    include_directories: [root_inc, user_channel_inc],
    dependencies: [
      channellayer_dep,
      crypto,
      ipmid_dep,
      nlohmann_json_dep,
      pam,
      phosphor_dbus_interfaces_dep,
      phosphor_logging_dep,
      systemd,
    ])

  userlayer_src = [
    'user_layer.cpp',
    'user_mgmt.cpp',
    'passwd_mgr.cpp',
  ]

  userlayer_lib = library(
    'userlayer',
    userlayer_src,
    implicit_include_directories: false,
    dependencies: userlayer_pre,
    version: meson.project_version(),
    install: true,
    install_dir: get_option('libdir'),
    override_options: ['b_lundef=false'])

  userlayer_dep = declare_dependency(
    link_with: userlayer_lib,
    dependencies: userlayer_pre)

  usercmds_pre = declare_dependency(
    include_directories: [root_inc, user_channel_inc],
    dependencies: [
      mapper,
      phosphor_logging_dep,
      ipmid_dep,
      userlayer_dep,
      channellayer_dep,
    ])

  usercmds_lib = library(
    'usercmds',
    'usercommands.cpp',
    implicit_include_directories: false,
    dependencies: usercmds_pre,
    install: true,
    install_dir: get_option('libdir') / 'ipmid-providers',
    version: meson.project_version(),
    override_options: ['b_lundef=false'])

  import('pkgconfig').generate(
    userlayer_lib,
    name: 'libuserlayer',
    version: meson.project_version(),
    description: 'libuserlayer')

endif
