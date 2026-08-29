/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* RDMA vendor/provider identification */

#pragma once

#include <cstdint>
#include <string>

#include "ibv-core.h"

namespace hipObj {

enum class Provider : uint8_t {
  BNXT = 0,
  IONIC = 2,
  UNKNOWN = 0xFF,
};

constexpr uint32_t VENDOR_ID_BROADCOM = 0x14E4;
constexpr uint32_t VENDOR_ID_PENSANDO = 0x1DD8;

inline const char* provider_name(Provider p) {
  switch (p) {
    case Provider::BNXT:
      return "bnxt";
    case Provider::IONIC:
      return "ionic";
    default:
      return "unknown";
  }
}

inline Provider provider_from_string(const std::string& s) {
  if (s == "bnxt" || s == "bnxt_re")
    return Provider::BNXT;
  if (s == "ionic" || s == "pensando")
    return Provider::IONIC;
  return Provider::UNKNOWN;
}

bool isBnxtDevice(uint32_t vendorId);
bool isIonicDevice(uint32_t vendorId);

int configureBnxtQp(struct ibv_qp_attr* attr);
int configureIonicQp(struct ibv_qp_attr* attr);

} // namespace hipObj
