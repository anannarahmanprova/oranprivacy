// Copyright 2022 The Abseil Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// -----------------------------------------------------------------------------
// File: log/internal/config.h
// -----------------------------------------------------------------------------
//

#ifndef ABSL_LOG_INTERNAL_CONFIG_H_
#define ABSL_LOG_INTERNAL_CONFIG_H_

#include "absl/base/config.h"

#ifdef _WIN32
#include <cstdint>
#else
#include <sys/types.h>
#endif

#ifndef PB_ENABLE_SGX
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace log_internal {

#ifdef _WIN32
using Tid = uint32_t;
#else
using Tid = pid_t;
#endif

}  // namespace log_internal
ABSL_NAMESPACE_END
}  // namespace absl
#endif //PB_ENABLE_SGX

#endif  // ABSL_LOG_INTERNAL_CONFIG_H_
