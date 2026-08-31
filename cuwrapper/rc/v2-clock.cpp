/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "v2-clock.h"

#include <chrono>

namespace hipObj {
namespace v2 {

namespace {

class SteadyClock : public ClockSource {
public:
  uint64_t nowMs() override {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
  }
};

SteadyClock g_defaultClock;
ClockSource* g_override = nullptr;

} // namespace

ClockSource& clockSource() {
  return g_override ? *g_override : static_cast<ClockSource&>(g_defaultClock);
}

ClockSource* setClockSourceForTest(ClockSource* source) {
  ClockSource* previous = g_override;
  g_override = source;
  return previous;
}

} // namespace v2
} // namespace hipObj
