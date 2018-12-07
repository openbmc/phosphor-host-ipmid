libcrypto = dependency('libcrypto')
libpam = cxx.find_library('pam')

userlayer = library(
  'userlayer',
  [
    'channel_layer.cpp',
    'channel_mgmt.cpp',
    'passwd_mgr.cpp',
    'user_layer.cpp',
    'user_mgmt.cpp',
  ],
  include_directories: includes,
  implicit_include_directories: false,
  dependencies: [
    libcrypto,
    phosphor_dbus_interfaces,
    phosphor_logging,
    sdbusplus,
  ],
  install: true)

shared_library(
  'userchannel',
  [
    'channelcommands.cpp',
    'usercommands.cpp',
  ],
  include_directories: includes,
  implicit_include_directories: false,
  dependencies: [
    libpam,
    phosphor_logging,
  ],
  link_with: userlayer,
  install_dir: ipmid_providers_dir,
  install: true)

install_headers(
  'channel_layer.hpp',
  'user_layer.hpp',
  subdir: 'user_channel')
