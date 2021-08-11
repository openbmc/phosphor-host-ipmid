user_channel_inc = include_directories('.')

userlayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
      crypto,
      systemd,
      phosphor_logging_dep,
      phosphor_dbus_interfaces_dep,
      ipmid_dep,
  ],
)

userlayer_lib = static_library(
  'userlayer_lib',
  'user_layer.cpp',
  'user_mgmt.cpp',
  'passwd_mgr.cpp',
  implicit_include_directories: false,
  dependencies: userlayer_pre,
)

userlayer_dep = declare_dependency(
  link_with: userlayer_lib,
  dependencies: userlayer_pre,
)

shared_module(
  'userlayer',
  implicit_include_directories: false,
  dependencies: [
    userlayer_dep,
  ],
  install: true,
  install_dir: get_option('libdir'),
)

channellayer_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    ipmid_dep,
    systemd,
    phosphor_logging_dep,
    phosphor_dbus_interfaces_dep,
  ],
)

channellayer_lib = static_library(
  'channellayer_lib',
  'channel_layer.cpp',
  'channel_mgmt.cpp',
  'user_mgmt.cpp',
  'cipher_mgmt.cpp',
  implicit_include_directories: false,
  dependencies: channellayer_pre,
)

channellayer_dep = declare_dependency(
  link_with: channellayer_lib,
  dependencies: channellayer_pre,
)

shared_module(
  'channellayer',
  implicit_include_directories: false,
  dependencies: [
    channellayer_dep,
  ],
  install: true,
  install_dir: get_option('libdir'),
)

usercmds_pre = declare_dependency(
  include_directories: [root_inc, user_channel_inc],
  dependencies: [
    mapper,
    phosphor_logging_dep,
    ipmid_dep,
    userlayer_dep,
    channellayer_dep,
  ],
)

usercmds_lib = static_library(
  'usercmds_lib',
  'usercommands.cpp',
  implicit_include_directories: false,
  dependencies: usercmds_pre,
)

usercmds_dep = declare_dependency(
  link_with: usercmds_lib,
  dependencies: usercmds_pre,
)

shared_module(
  'usercmds',
  implicit_include_directories: false,
  dependencies: [
    usercmds_dep,
  ],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers,
)
