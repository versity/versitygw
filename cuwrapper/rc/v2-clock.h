/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Injectable monotonic clock for v2 lifetime policies (retired-ring
 * expiry, session timeouts). Production uses a steady-clock
 * implementation; unit tests install a fake to control time. */

#pragma once

#include <cstdint>

namespace hipObj {
namespace v2 {

class ClockSource {
public:
  virtual ~ClockSource() = default;
  virtual uint64_t nowMs() = 0;
};

/* Returns the active clock. Production default unless a test
 * override is installed. */
ClockSource& clockSource();

/* Installs a test clock and returns the previously active source
 * (nullptr when the production default was active). Passing nullptr
 * restores the default. Unit tests only. */
ClockSource* setClockSourceForTest(ClockSource* source);

} // namespace v2
} // namespace hipObj
