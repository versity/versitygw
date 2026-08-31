/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "v2-random.h"

#include <cerrno>
#include <cstddef>

#include <sys/random.h>

namespace hipObj {
namespace v2 {

namespace {

class GetrandomSource : public RandomSource {
public:
  bool next32(uint32_t& out) override {
    /* Loop over short reads and EINTR; fail closed on hard errors. */
    size_t filled = 0;
    unsigned char buf[sizeof(uint32_t)];
    while (filled < sizeof(buf)) {
      ssize_t n = ::getrandom(buf + filled, sizeof(buf) - filled, 0);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (n == 0) {
        return false;
      }
      filled += static_cast<size_t>(n);
    }
    uint32_t value = 0;
    for (size_t i = 0; i < sizeof(buf); ++i) {
      value = (value << 8) | buf[i];
    }
    out = value;
    return true;
  }
};

GetrandomSource g_defaultSource;
RandomSource* g_override = nullptr;

} // namespace

RandomSource& randomSource() {
  return g_override ? *g_override : static_cast<RandomSource&>(g_defaultSource);
}

RandomSource* setRandomSourceForTest(RandomSource* source) {
  RandomSource* previous = g_override;
  g_override = source;
  return previous;
}

bool nextClientPsn(uint32_t& psn) {
  for (int attempt = 0; attempt < 3; ++attempt) {
    uint32_t value = 0;
    if (!randomSource().next32(value)) {
      return false;
    }
    value &= 0x00ffffff; /* PSNs are 24-bit on the wire */
    if (value != 0) {
      psn = value;
      return true;
    }
  }
  return false;
}

bool nextCookie(uint32_t& cookie) {
  return randomSource().next32(cookie);
}

} // namespace v2
} // namespace hipObj
