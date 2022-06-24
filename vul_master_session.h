/* Copyright 2016 The TensorFlow Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#ifndef TENSORFLOW_CORE_DISTRIBUTED_RUNTIME_MASTER_SESSION_H_
#define TENSORFLOW_CORE_DISTRIBUTED_RUNTIME_MASTER_SESSION_H_

#include <vector>

#include "tensorflow/core/common_runtime/stats_publisher_interface.h"
#include "tensorflow/core/public/session_options.h"

namespace tensorflow {

class Device;
struct MasterEnv;
class MasterSessionInterface;

namespace internal {

MasterSessionInterface* NewMasterSession(
    const SessionOptions& options, const MasterEnv* env,
    std::vector<Device*>* remote_devs,
    StatsPublisherFactory stats_publisher_factory);

}  // namespace internal
}  // end namespace tensorflow

#endif  // TENSORFLOW_CORE_DISTRIBUTED_RUNTIME_MASTER_SESSION_H_
