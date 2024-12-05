/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once
#include <cstdint>

namespace ipmi
{

/**
 * @enum IPMI set password return codes (refer spec sec 22.30)
 */
enum ipmi_set_password_return_codes : uint8_t
{
    ipmiCCPasswdFailMismatch = 0x80,
    ipmiCCPasswdFailWrongSize = 0x81,
};

static constexpr uint8_t userIdEnabledViaSetPassword = 0x1;
static constexpr uint8_t userIdDisabledViaSetPassword = 0x2;

void registerUserIpmiFunctions();
} // namespace ipmi
