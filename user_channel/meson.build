libcrypto = dependency('libcrypto')
libpam = cxx.find_library('pam')

library(
  'userchannel',
  [
    'channelcommands.cpp',
    'channel_layer.cpp',
    'channel_mgmt.cpp',
    'passwd_mgr.cpp',
    'usercommands.cpp',
    'user_layer.cpp',
    'user_mgmt.cpp',
  ],
  include_directories: includes,
  implicit_include_directories: false,
  dependencies: [
    libcrypto,
    libpam,
	phosphor_dbus_interfaces,
	phosphor_logging,
    sdbusplus,
  ],
  install_dir: ipmid_providers_dir,
  install: true)
