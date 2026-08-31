/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <cstdint>

#include "ibv-core.h"

namespace hipObj {

struct RdmaToken;

struct RcConnection {
  struct ibv_context* ctx = nullptr;
  struct ibv_pd* pd = nullptr;
  struct ibv_cq* cq = nullptr;
  struct ibv_qp* qp = nullptr;
  uint8_t portNum = 1;
  int gidIndex = -1;
  union ibv_gid localGid = {};
};

int openRdmaDevice(int nicIndex, RcConnection& conn);
int openRdmaDeviceByName(const char* devName, RcConnection& conn);
void closeRdmaDevice(RcConnection& conn);
int createRcQp(RcConnection& conn, int cqSize, int maxSendWr, int maxRecvWr);
int transitionQpToInit(RcConnection& conn);
int transitionQpToRtr(RcConnection& conn, uint32_t destQpNum, uint16_t destLid,
                      union ibv_gid destGid);
int transitionQpToRts(RcConnection& conn);
int connectRcPeer(RcConnection& conn, const RdmaToken& peerToken);
int pollCompletion(RcConnection& conn, int expectedOpcode, int timeoutMs);

} // namespace hipObj
