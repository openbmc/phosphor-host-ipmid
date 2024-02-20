hybrid_dep = []
hybrid_src = []
if get_option('hybrid-sensors').allowed()
  hybrid_dep = [
    mapper,
  ]

  hybrid_src = [
    'sensorhandler.cpp',
    'sensordatahandler.cpp',
    'ipmisensor.cpp',
    generated_src,
  ]
endif

dbus_sdr_src = [
  'dbus-sdr/sensorcommands.cpp',
  'dbus-sdr/storagecommands.cpp',
  hybrid_src,
]

dbus_sdr_pre = [
  crypto,
  nlohmann_json_dep,
  phosphor_logging_dep,
  ipmid_dep,
]

dbus_sdr_lib = library(
  'dbus_sdr',
  'sensorutils.cpp',
  'sdrutils.cpp',
  'sensorcommands_utils.cpp',
  'storagecommands_utils.cpp',
  include_directories: root_inc,
  dependencies: dbus_sdr_pre,
  implicit_include_directories: false,
  install: true,
  install_dir: get_option('libdir'),
)

dbus_sdr_dep = declare_dependency(
  dependencies: dbus_sdr_pre + hybrid_dep,
  link_with: dbus_sdr_lib
)
