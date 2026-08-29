/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* RDMA token encoding/decoding implementation */

#include "token.h"

#include <cstdio>
#include <cstring>
#include <sstream>

namespace hipObj {

namespace {

const char HEX[] = "0123456789abcdef";

constexpr size_t kTokenBinaryLen = 1 + 4 + 16 + 4 + 8 + 8 + 1 + 2;
constexpr size_t kTokenHexLen = kTokenBinaryLen * 2;

int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

bool decodeHexBytePair(char hi, char lo, uint8_t& out) {
  int h = hexNibble(hi);
  int l = hexNibble(lo);
  if (h < 0 || l < 0)
    return false;
  out = static_cast<uint8_t>((h << 4) | l);
  return true;
}

bool isSuccessHttpCode(int code) {
  return code == 200 || code == 204 || code == 206;
}

} // namespace

std::string encodeRdmaToken(const RdmaToken& token) {
  uint8_t buf[kTokenBinaryLen];
  size_t off = 0;

  buf[off++] = token.transport;
  std::memcpy(buf + off, &token.qpNum, 4);
  off += 4;
  std::memcpy(buf + off, token.gid, 16);
  off += 16;
  std::memcpy(buf + off, &token.rkey, 4);
  off += 4;
  std::memcpy(buf + off, &token.remoteAddr, 8);
  off += 8;
  std::memcpy(buf + off, &token.length, 8);
  off += 8;
  buf[off++] = token.portNum;
  std::memcpy(buf + off, &token.lid, 2);
  off += 2;

  std::ostringstream oss;
  for (size_t i = 0; i < off; ++i) {
    oss << HEX[(buf[i] >> 4) & 0xf] << HEX[buf[i] & 0xf];
  }
  return oss.str();
}

bool decodeRdmaTokenHex(const char* tokenHex, RdmaToken& out) {
  if (!tokenHex)
    return false;
  size_t hexLen = std::strlen(tokenHex);
  if (hexLen != kTokenHexLen)
    return false;

  uint8_t buf[kTokenBinaryLen];
  for (size_t i = 0; i < kTokenBinaryLen; ++i) {
    if (!decodeHexBytePair(tokenHex[i * 2], tokenHex[i * 2 + 1], buf[i]))
      return false;
  }

  size_t off = 0;
  out.transport = buf[off++];
  std::memcpy(&out.qpNum, buf + off, 4);
  off += 4;
  std::memcpy(out.gid, buf + off, 16);
  off += 16;
  std::memcpy(&out.rkey, buf + off, 4);
  off += 4;
  std::memcpy(&out.remoteAddr, buf + off, 8);
  off += 8;
  std::memcpy(&out.length, buf + off, 8);
  off += 8;
  out.portNum = buf[off++];
  std::memcpy(&out.lid, buf + off, 2);
  return true;
}

bool parseRdmaReplyHttpCode(const char* reply, size_t replyLen, int& httpCode) {
  if (!reply || replyLen == 0)
    return false;

  size_t len = replyLen;
  while (len > 0 && (reply[len - 1] == '\0' || reply[len - 1] == '\n' ||
                     reply[len - 1] == '\r')) {
    --len;
  }
  if (len == 0)
    return false;

  if (len >= 2 && reply[0] == 'o' && reply[1] == 'k') {
    httpCode = 200;
    return true;
  }
  if (len >= 3 && reply[0] == 'e' && reply[1] == 'r' && reply[2] == 'r') {
    httpCode = -1;
    return true;
  }

  char tmp[512];
  if (len >= sizeof(tmp))
    return false;
  std::memcpy(tmp, reply, len);
  tmp[len] = '\0';

  char* colon = std::strchr(tmp, ':');
  if (colon) {
    *colon = '\0';
  }

  char* end = nullptr;
  long code = std::strtol(tmp, &end, 10);
  if (end == tmp || *end != '\0')
    return false;
  httpCode = static_cast<int>(code);
  return true;
}

bool decodeRdmaReply(const char* reply, size_t replyLen, int& status) {
  int httpCode = 0;
  if (!parseRdmaReplyHttpCode(reply, replyLen, httpCode))
    return false;
  if (httpCode == 501) {
    status = -2;
    return true;
  }
  if (httpCode < 0) {
    status = -1;
    return true;
  }
  if (isSuccessHttpCode(httpCode)) {
    status = 0;
    return true;
  }
  status = -1;
  return true;
}

bool parseClientNicFromTokenHex(const char* tokenHex, char* nicIp,
                                size_t nicIpLen) {
  if (!nicIp || nicIpLen == 0)
    return false;
  nicIp[0] = '\0';
  if (!tokenHex)
    return false;

  RdmaToken token;
  if (!decodeRdmaTokenHex(tokenHex, token))
    return false;

  if (token.gid[10] != 0xff || token.gid[11] != 0xff)
    return true;

  int n = std::snprintf(nicIp, nicIpLen, "%u.%u.%u.%u",
                        static_cast<unsigned>(token.gid[12]),
                        static_cast<unsigned>(token.gid[13]),
                        static_cast<unsigned>(token.gid[14]),
                        static_cast<unsigned>(token.gid[15]));
  if (n < 0 || static_cast<size_t>(n) >= nicIpLen)
    return false;
  return true;
}

std::string formatRdmaHeaderValue(const char* tokenHex, const void* buf,
                                  size_t size) {
  char header[512];
  std::snprintf(header, sizeof(header), "%s:%016lx:%016lx", tokenHex,
                reinterpret_cast<uintptr_t>(buf),
                static_cast<unsigned long>(size));
  return std::string(header);
}

bool parsePeerTokenFromReply(const char* reply, size_t replyLen,
                             RdmaToken& peerToken, int& httpCode) {
  if (!reply || replyLen == 0)
    return false;

  size_t len = replyLen;
  while (len > 0 && (reply[len - 1] == '\0' || reply[len - 1] == '\n' ||
                     reply[len - 1] == '\r')) {
    --len;
  }
  if (len == 0)
    return false;

  const char* colon = static_cast<const char*>(std::memchr(reply, ':', len));
  if (!colon || colon == reply) {
    return false;
  }

  size_t codeLen = static_cast<size_t>(colon - reply);
  char codeBuf[16];
  if (codeLen >= sizeof(codeBuf))
    return false;
  std::memcpy(codeBuf, reply, codeLen);
  codeBuf[codeLen] = '\0';

  char* end = nullptr;
  long code = std::strtol(codeBuf, &end, 10);
  if (end == codeBuf || *end != '\0')
    return false;
  httpCode = static_cast<int>(code);

  const char* tokenHex = colon + 1;
  size_t tokenHexLen = len - codeLen - 1;
  if (tokenHexLen != kTokenHexLen)
    return false;

  char tokenCopy[kTokenHexLen + 1];
  std::memcpy(tokenCopy, tokenHex, tokenHexLen);
  tokenCopy[tokenHexLen] = '\0';
  return decodeRdmaTokenHex(tokenCopy, peerToken);
}

std::string encodeReplyWithPeerToken(int httpCode, const RdmaToken& peerToken) {
  std::ostringstream oss;
  oss << httpCode << ':' << encodeRdmaToken(peerToken);
  return oss.str();
}

} // namespace hipObj
