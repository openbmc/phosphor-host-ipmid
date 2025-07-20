/*
 * Copyright (c) 2018-2021 Ampere Computing LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>

namespace ipmi
{

static constexpr const char* credBootstrappingInf =
    "xyz.openbmc_project.HostInterface.CredentialBootstrapping";
static constexpr const char* credBootstrapEnabledProp = "Enabled";
static constexpr const char* credEnableAfterResetProp = "EnableAfterReset";
static constexpr const char* credRoleIdProp = "RoleId";

/* 32 bytes of the fingerprint */
static constexpr uint8_t maxFingerPrintLength = 32;

} // namespace ipmi
