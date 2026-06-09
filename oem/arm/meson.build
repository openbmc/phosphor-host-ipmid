# SPDX-FileCopyrightText: Copyright OpenBMC Authors
# SPDX-License-Identifier: Apache-2.0

# arm OEM library build

arm_oem_src = ['apphandler.cpp']

arm_oem_deps = [
    ipmid_dep,
]

arm_ipmi_oem = library(
    'arm_ipmi_oem',
    arm_oem_src,
    dependencies: arm_oem_deps,
    include_directories: [root_inc],
    install: true,
    install_dir: get_option('libdir') / 'ipmid-providers',
    version: meson.project_version(),
    override_options: ipmi_plugin_options,
)
