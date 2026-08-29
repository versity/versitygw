/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "v2_request.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>

namespace hipObj {
namespace v2 {

namespace {

bool isHexDigits(const std::string& s, size_t lo, size_t hi) {
  if (s.size() < lo || s.size() > hi) {
    return false;
  }
  for (char c : s) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

bool parseU32Hex(const std::string& s, uint32_t& out) {
  if (s.empty() || s.size() > 8) {
    return false;
  }
  uint32_t v = 0;
  for (char c : s) {
    int d;
    if (std::isdigit(static_cast<unsigned char>(c))) {
      d = c - '0';
    } else {
      char lc = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      d = lc - 'a' + 10;
    }
    v = (v << 4) | static_cast<uint32_t>(d);
  }
  out = v;
  return true;
}

bool parseU64Dec(const std::string& s, uint64_t& out) {
  if (s.empty() || s.size() > 20) {
    return false;
  }
  uint64_t v = 0;
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
    uint64_t d = static_cast<uint64_t>(c - '0');
    if (v > (UINT64_MAX - d) / 10) {
      return false; /* would overflow */
    }
    v = v * 10 + d;
  }
  out = v;
  return true;
}

/* Extracts the exact Authorization header value from the raw block
 * (case-insensitive name match, value preserved byte-for-byte
 * except leading/trailing OWS). */
std::string rawAuthorization(const std::string& raw) {
  const std::string needle = "authorization:";
  std::string lower;
  lower.reserve(raw.size());
  for (char c : raw) {
    lower.push_back(
      static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  size_t pos = 0;
  while (pos < lower.size()) {
    size_t lineEnd = lower.find("\r\n", pos);
    if (lineEnd == std::string::npos) {
      lineEnd = lower.size();
    }
    size_t lineLen = lineEnd - pos;
    if (lower.compare(pos, lineLen < needle.size() ? lineLen : needle.size(),
                      needle) == 0 &&
        lineLen >= needle.size()) {
      std::string v = raw.substr(pos + needle.size(), lineLen - needle.size());
      size_t b = v.find_first_not_of(" \t");
      size_t e = v.find_last_not_of(" \t");
      if (b == std::string::npos) {
        return std::string();
      }
      return v.substr(b, e - b + 1);
    }
    pos = lineEnd + 2;
  }
  return std::string();
}

} // namespace

std::optional<PrepareRequest> parsePrepareRequest(
  const std::map<std::string, std::string>& headers,
  const std::string& rawHeaders) {
  PrepareRequest out;
  auto it = headers.find("x-amz-rdma-protocol");
  if (it == headers.end()) {
    return std::nullopt;
  }
  out.protocol = it->second;

  it = headers.find("x-amz-rdma-token");
  if (it == headers.end()) {
    return std::nullopt;
  }
  /* 88-hex or 88-hex:addr:size */
  const std::string& tok = it->second;
  size_t colon1 = tok.find(':');
  if (colon1 == std::string::npos) {
    if (!isHexDigits(tok, 88, 88)) {
      return std::nullopt;
    }
  } else {
    size_t colon2 = tok.find(':', colon1 + 1);
    if (colon2 == std::string::npos) {
      return std::nullopt;
    }
    std::string base = tok.substr(0, colon1);
    std::string addr = tok.substr(colon1 + 1, colon2 - colon1 - 1);
    std::string size = tok.substr(colon2 + 1);
    if (!isHexDigits(base, 88, 88) || addr.empty() || size.empty() ||
        !isHexDigits(addr, 1, 16) || !isHexDigits(size, 1, 16)) {
      return std::nullopt;
    }
  }
  out.token = tok;

  it = headers.find("x-amz-rdma-psn");
  if (it == headers.end() || !parseU32Hex(it->second, out.clientPsn) ||
      out.clientPsn == 0 || out.clientPsn > 0x00ffffff) {
    return std::nullopt;
  }

  it = headers.find("x-amz-rdma-cookie");
  if (it == headers.end() || !isHexDigits(it->second, 8, 8)) {
    return std::nullopt;
  }
  uint32_t cookie = 0;
  parseU32Hex(it->second, cookie);
  out.cookie = cookie;

  it = headers.find("x-amz-rdma-op");
  if (it == headers.end() || (it->second != "GET" && it->second != "PUT")) {
    return std::nullopt;
  }
  out.op = it->second;

  it = headers.find("x-amz-rdma-target");
  if (it == headers.end() || it->second.empty() || it->second.front() != '/') {
    return std::nullopt;
  }
  out.target = it->second;

  it = headers.find("x-amz-rdma-size");
  if (it == headers.end() || !parseU64Dec(it->second, out.size) ||
      out.size == 0) {
    return std::nullopt;
  }

  it = headers.find("x-amz-rdma-offset");
  if (it != headers.end()) {
    if (!parseU64Dec(it->second, out.offset)) {
      return std::nullopt;
    }
    out.hasOffset = true;
  }

  out.authorization = rawAuthorization(rawHeaders);
  if (out.authorization.empty()) {
    return std::nullopt;
  }
  return out;
}

std::optional<ReadyRequest> parseReadyRequest(
  const std::map<std::string, std::string>& headers,
  const std::string& rawHeaders) {
  ReadyRequest out;
  auto it = headers.find("x-amz-rdma-protocol");
  if (it == headers.end()) {
    return std::nullopt;
  }
  out.protocol = it->second;

  it = headers.find("x-amz-rdma-session");
  if (it == headers.end() || !isHexDigits(it->second, 32, 32)) {
    return std::nullopt;
  }
  out.session = it->second;

  it = headers.find("x-amz-rdma-cookie");
  if (it == headers.end() || !isHexDigits(it->second, 8, 8)) {
    return std::nullopt;
  }
  uint32_t cookie = 0;
  parseU32Hex(it->second, cookie);
  out.cookie = cookie;

  /* Client MR endpoint for the data phase. Optional on a GET that
   * the server stages itself, required for PUT delivery and the
   * GET READ pull. Parsed as bare hex without a 0x prefix. */
  it = headers.find("x-amz-rdma-mr-addr");
  if (it != headers.end()) {
    /* Strict hex, and present-but-empty fails too: a field that
     * exists must carry a valid value. Bare strtoull would also
     * accept prefixes, whitespace and trailing garbage, which
     * would poison the remote address. */
    if (!isHexDigits(it->second, 1, 16)) {
      return std::nullopt;
    }
    out.mrAddr = std::strtoull(it->second.c_str(), nullptr, 16);
  }
  it = headers.find("x-amz-rdma-mr-rkey");
  if (it != headers.end()) {
    if (!isHexDigits(it->second, 1, 8)) {
      return std::nullopt;
    }
    out.mrRkey = static_cast<uint32_t>(
      std::strtoull(it->second.c_str(), nullptr, 16));
  }
  it = headers.find("x-amz-rdma-qpn");
  if (it != headers.end()) {
    if (!isHexDigits(it->second, 1, 8)) {
      return std::nullopt;
    }
    out.qpn = static_cast<uint32_t>(
      std::strtoull(it->second.c_str(), nullptr, 16));
  }

  out.authorization = rawAuthorization(rawHeaders);
  if (out.authorization.empty()) {
    return std::nullopt;
  }
  return out;
}

std::optional<CancelRequest> parseCancelRequest(
  const std::map<std::string, std::string>& headers,
  const std::string& rawHeaders) {
  CancelRequest out;
  auto it = headers.find("x-amz-rdma-protocol");
  if (it == headers.end()) {
    return std::nullopt;
  }
  out.protocol = it->second;

  it = headers.find("x-amz-rdma-session");
  if (it == headers.end() || !isHexDigits(it->second, 32, 32)) {
    return std::nullopt;
  }
  out.session = it->second;

  out.authorization = rawAuthorization(rawHeaders);
  if (out.authorization.empty()) {
    return std::nullopt;
  }
  return out;
}

} // namespace v2
} // namespace hipObj
