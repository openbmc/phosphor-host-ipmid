sensorutils_lib = static_library(
    'sensorutils',
    'sensorutils.cpp',
    include_directories: root_inc,
    dependencies: phosphor_logging_dep,
    implicit_include_directories: false,
)

sensorutils_dep = declare_dependency(link_with: sensorutils_lib)

hybrid_src = []

if get_option('hybrid-sensors').allowed()
    hybrid_src = [
        'sensorhandler.cpp',
        'sensordatahandler.cpp',
        'ipmisensor.cpp',
        generated_src,
    ]
endif

sensorsoem_src = []
if get_option('sensors-oem').allowed()
    sensorsoem_src = ['dbus-sdr/sensorcommands_oem.cpp']
endif

dbus_sdr_pre = declare_dependency(
    include_directories: root_inc,
    dependencies: [
        crypto,
        nlohmann_json_dep,
        phosphor_logging_dep,
        ipmid_dep,
        sensorutils_dep,
    ],
)

dbus_sdr_src = [
    'dbus-sdr/sdrutils.cpp',
    'dbus-sdr/sensorcommands.cpp',
    'dbus-sdr/storagecommands.cpp',
    hybrid_src,
    sensorsoem_src,
]
