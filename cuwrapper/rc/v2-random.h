/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Injectable randomness for v2 policies (client PSNs, completion
 * cookies). Production draws from getrandom(2); unit tests install
 * a deterministic source. */

#pragma once

#include <cstdint>

namespace hipObj {
namespace v2 {

class RandomSource {
public:
  virtual ~RandomSource() = default;

  /* Draws 32 random bits. Returns false only when the underlying
   * entropy source failed; callers treat that as an internal error
   * rather than falling back to a constant. */
  virtual bool next32(uint32_t& out) = 0;
};

/* Returns the active source (production default unless a test
 * override is installed). */
RandomSource& randomSource();

/* Installs a test source and returns the previously active one
 * (nullptr when the production default was active). Passing
 * nullptr restores the default. Unit tests only. */
RandomSource* setRandomSourceForTest(RandomSource* source);

/* Draws a 24-bit non-zero PSN. Retries up to twice when the draw
 * masks to zero; returns false when the source failed or every
 * draw was zero. */
bool nextClientPsn(uint32_t& psn);

/* Draws a full 32-bit completion cookie (0 is a valid cookie). */
bool nextCookie(uint32_t& cookie);

} // namespace v2
} // namespace hipObj
