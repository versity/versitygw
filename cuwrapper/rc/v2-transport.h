/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* v2 transport: device/qp ownership split and release procedure.
 *
 * DeviceHandle is the shared half (context, protection domain,
 * topology) with a connection reference count; RcConnV2 owns one
 * qp/cq pair. v2 entry points route through these helpers so the
 * registry, capacity accounting, and the retired ring stay
 * consistent. Everything runs under v2::apiLock(). */

#pragma once

#include <atomic>
#include <cstdint>

#include "ibv-core.h"
#include "v2-registry.h"

namespace hipObj {

struct DeviceHandle {
  struct ibv_context* ctx = nullptr;
  struct ibv_pd* pd = nullptr;
  uint8_t portNum = 1;
  int gidIndex = -1;
  union ibv_gid localGid = {};
  std::atomic<uint32_t> connRefs{0};
};

namespace v2 {

/* Creates the qp/cq pair on dh. On success conn holds both objects,
 * conn.qpNum is captured, and dh->connRefs was incremented. On
 * failure every partially created object was rolled back (rollback
 * failures are reported via *rollbackFailed so the caller can raise
 * a poisoned tombstone). */
int createRcConnV2(DeviceHandle* dh, RcConnV2& conn,
                   bool* rollbackFailed = nullptr);

/* Destroys conn's qp and cq. Reflects per-object success through
 * the out flags; the caller feeds them to commitDestroy(). */
void destroyRcConnV2(RcConnV2& conn, bool* qpOk, bool* cqOk);

/* QP state transitions taking the device topology from dh. The v1
 * signatures (RcConnection&) remain unchanged. */
int transitionQpToInitV2(DeviceHandle* dh, RcConnV2& conn);
int transitionQpToRtrV2(DeviceHandle* dh, RcConnV2& conn, uint32_t destQpNum,
                        uint16_t destLid, union ibv_gid destGid,
                        uint32_t rqPsn);
int transitionQpToRtsV2(RcConnV2& conn, DeviceHandle* dh, uint32_t sqPsn);

/* Drives a QP from any state (including RTS/ERR after a failed
 * transfer) back to INIT. The verbs state table has no direct
 * RTS->INIT edge, so this goes through RESET, which is valid from
 * every state. */
int rearmQpToInitV2(DeviceHandle* dh, RcConnV2& conn);

/* Creates only a qp on an existing cq (conflict-discard retry uses
 * this so the original cq survives). */
int createRcQpOnly(DeviceHandle* dh, struct ibv_cq* cq, RcConnV2& conn);

/* Retires a live qp whose (qpn, psn) was already used by a peer:
 * reserves a fresh ring slot, destroys the old qp, records the
 * tuple, and recreates the qp on the existing cq. On any failure
 * the entry keeps its live qp and reservation (callers surface the
 * error); the busy return means the retired ring is exhausted. */
int discardAndRecreateQp(ConnId id);

/* Decrements dh->connRefs after a successful releaseRcConnV2 and
 * closes ctx/pd when no MR and no connection remain. */
void releaseDevice(DeviceHandle* dh);

/* Full v2 release procedure for one registry entry: claim, reserve
 * a retired slot for a live qp, destroy, commit, record, erase.
 * Returns a hipObj error code (0 = success, busy = deferred,
 * rdma = leftover/poison). */
int releaseConnection(ConnId id);

/* Posts the zero-SGE receive work request (wr_id = kRecvImm). */
constexpr uint64_t kRecvImm = 0x5245435632494d4dULL; /* "RECV2IMM" */
int postRecvImm(DeviceHandle* dh, RcConnV2& conn);

/* Completion validation for the data phase. A GET consumes one
 * RECV_RDMA_WITH_IMM completion; a PUT consumes one RECV completion
 * carrying the immediate (flags & IBV_WC_WITH_IMM). The immediate
 * carries the session cookie in network order - the byte count
 * travels in the FINAL response instead. */
enum class WcKind { kGet, kPut };

struct WcExpectation {
  WcKind kind;
  uint64_t wrId;   /* expected wr_id (kRecvImm for receives) */
  uint32_t cookie; /* expected immediate value (the cookie) */
};

/* Validates one work completion against the expectation; returns
 * false and fills *reason on mismatch. */
bool validateDataCompletion(const struct ibv_wc& wc,
                            const WcExpectation& expect, const char** reason);

} // namespace v2
} // namespace hipObj
