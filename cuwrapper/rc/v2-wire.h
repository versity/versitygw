/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* hipobj-rc-v2 wire protocol parsing and formatting.
 *
 * The v2 protocol runs on a dedicated control endpoint and exchanges
 * three request types (prepare/ready/cancel), each answered by a single
 * HTTP response. The READY response doubles as the FINAL outcome: the
 * server performs the RDMA transfer while answering READY, so the
 * exchange completes in exactly two round trips.
 *
 * All parsing functions are pure (no library state) so they can be unit
 * tested without RDMA hardware.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace hipObj {
namespace v2 {

/* Header and path names used by the control protocol. */
constexpr const char* kProtocolHeader = "X-Amz-Rdma-Protocol";
constexpr const char* kProtocolValue = "hipobj-rc-v2";
constexpr const char* kTokenHeader = "X-Amz-Rdma-Token";
constexpr const char* kSessionHeader = "X-Amz-Rdma-Session";
constexpr const char* kCookieHeader = "X-Amz-Rdma-Cookie";
constexpr const char* kPsnHeader = "X-Amz-Rdma-Psn";
constexpr const char* kOpHeader = "X-Amz-Rdma-Op";
constexpr const char* kSizeHeader = "X-Amz-Rdma-Size";
constexpr const char* kOffsetHeader = "X-Amz-Rdma-Offset";
constexpr const char* kTargetHeader = "X-Amz-Rdma-Target";
constexpr const char* kUnsupportedHeader = "X-Amz-Rdma-Protocol-Status";
constexpr const char* kUnsupportedValue = "unsupported";
constexpr const char* kReplyHeader = "X-Amz-Rdma-Reply";
constexpr const char* kBytesHeader = "X-Amz-Rdma-Bytes-Transferred";
constexpr const char* kEtagHeader = "X-Amz-Rdma-Etag";
constexpr const char* kVersionHeader = "X-Amz-Rdma-Version-Id";
constexpr const char* kChecksumHeader = "X-Amz-Rdma-Checksum";
constexpr const char* kControlPathPrefix = "/.hipobj-rc/";

/* Wire limits. */
constexpr size_t kSessionHexLen = 32;  /* 128-bit session id */
constexpr size_t kCookieHexLen = 8;    /* 32-bit cookie */
constexpr size_t kPsnHexLen = 6;       /* 24-bit PSN, 000001..ffffff */
constexpr size_t kTokenHexLen = 88;    /* 44-byte token payload */
constexpr size_t kChecksumB64Len = 12; /* 8-byte CRC64NVME base64 */
constexpr uint32_t kMaxTransferSize = 0x7fffffff; /* 2^31-1 */

struct PrepareReply {
  int httpStatus = 0;
  bool protocolEcho = false;
  bool unsupportedMarker = false;
  std::string serverToken; /* 88 hex chars */
  std::string session;     /* 32 hex chars */
  uint32_t serverPsn = 0;
};

struct FinalReply {
  int httpStatus = 0;
  bool protocolEcho = false;
  uint64_t bytes = 0;
  uint32_t cookieEcho = 0;
  bool cookiePresent = false; /* cookie echo header seen */
  std::string etag;
  std::string versionId;
  std::string checksumB64; /* 12-char canonical base64 text */
};

/* Parses a single "Name: value" header line (without CRLF) into name and
 * value with surrounding OWS trimmed. Returns false for lines without a
 * colon. */
bool splitHeaderLine(const std::string& line, std::string& name,
                     std::string& value);

/* Parses the response to PREPARE. headers is the raw header block with
 * lines separated by \r\n (final empty line optional); httpStatus is the
 * status code from the status line. Returns false when the block is
 * malformed in a way that makes the fields unusable. */
bool parsePrepareReply(int httpStatus, const std::string& headers,
                       PrepareReply& out);

/* Parses the READY/FINAL response. Same conventions as parsePrepareReply.
 * The checksum field, when present, must be "CRC64NVME " followed by
 * exactly 12 canonical base64 characters (11 data + one trailing '=');
 * otherwise parsing fails. */
bool parseFinalReply(int httpStatus, const std::string& headers,
                     FinalReply& out);

/* Validates a canonical CRC64NVME checksum value: "CRC64NVME " prefix
 * plus 12 base64 chars where the last is '=' and the text round-trips
 * through strict decode/re-encode. Returns the 12-char text via out when
 * valid. */
bool validateChecksumText(const std::string& headerValue, std::string& out);

/* Validates a session id (32 lowercase/uppercase hex chars). */
bool isValidSessionHex(const std::string& s);

/* Validates a PSN value string: 6 hex chars, value in 1..0xffffff. */
bool parsePsn(const std::string& s, uint32_t& psn);

/* Formats a cookie or PSN as 8/6 uppercase-zero-padded hex. */
std::string formatCookie(uint32_t cookie);
std::string formatPsn(uint32_t psn);

/* Builds the canonical rdma-target header value from bucket, key and an
 * optional canonical query string (already encoded and sorted, may be
 * empty). Percent-encodes the path per RFC 3986 unreserved rules. */
std::string buildTarget(const std::string& bucket, const std::string& key,
                        const std::string& canonicalQuery);

} // namespace v2
} // namespace hipObj
