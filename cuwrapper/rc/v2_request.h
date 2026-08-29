/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Server-side request parsers for the v2 control protocol.
 *
 * The wire ABNF is shared with the client (see v2-wire.h); these
 * entry points parse the three control requests the reference
 * server accepts: PREPARE, READY, and CANCEL. Headers arrive as a
 * lowercase-name map plus the raw header block so SigV4 credentials
 * can be verified against the original bytes. */

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "v2-wire.h"

namespace hipObj {
namespace v2 {

enum class ControlOp { kPrepare, kReady, kCancel };

struct PrepareRequest {
  std::string protocol;   /* echo header value */
  std::string token;      /* 88-hex peer token */
  uint32_t clientPsn = 0; /* 1..0xffffff */
  uint32_t cookie = 0;
  std::string op;     /* "GET" | "PUT" */
  std::string target; /* canonical object target (path[?q]) */
  uint64_t size = 0;
  uint64_t offset = 0;
  bool hasOffset = false;
  std::string authorization; /* raw Authorization value */
};

struct ReadyRequest {
  std::string protocol;
  std::string session; /* 32-hex session id */
  uint32_t cookie = 0;
  uint64_t mrAddr = 0; /* client MR address (hex 0x...) */
  uint32_t mrRkey = 0; /* client MR rkey (hex) */
  uint32_t qpn = 0;    /* client QP number (hex) */
  std::string authorization;
};

struct CancelRequest {
  std::string protocol;
  std::string session;
  std::string authorization;
};

/* Parses a PREPARE from the normalized header map. Returns nullopt
 * on any malformed field (caller answers 400). The Authorization
 * value is taken from rawHeaders when present so the exact signed
 * bytes survive. */
std::optional<PrepareRequest> parsePrepareRequest(
  const std::map<std::string, std::string>& headers,
  const std::string& rawHeaders);

std::optional<ReadyRequest> parseReadyRequest(
  const std::map<std::string, std::string>& headers,
  const std::string& rawHeaders);

std::optional<CancelRequest> parseCancelRequest(
  const std::map<std::string, std::string>& headers,
  const std::string& rawHeaders);

} // namespace v2
} // namespace hipObj
