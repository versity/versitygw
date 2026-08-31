/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Server-side data phase for the v2 protocol.
 *
 * A READY answer performs the RDMA transfer described by the
 * session: a PUT receives the client's WRITE_WITH_IMM into a
 * server-registered staging MR, validating the session cookie in
 * the immediate; a GET pushes the staged object into the client
 * MR with the cookie as the immediate. The wire parameters
 * (client QP, PSN, MR endpoint) arrive in the PREPARE and READY
 * headers and are staged on the session.
 *
 * Everything goes through the same ibverbs wrapper the client
 * uses, so unit tests can swap the function table as usual. */

#pragma once

#include <cstdint>
#include <string>

#include "ibv-core.h"
#include "v2_session.h"

namespace hipObj {
namespace v2 {

/* Outcome of one data-phase execution. */
enum class DataPhaseResult {
  Ok,         /* transfer completed and validated */
  Busy,       /* peer busy - the client should retry (409) */
  Timeout,    /* completion did not arrive within T_exec */
  VerifyFail, /* completion arrived but failed validation */
  WireFail,   /* posting the work request failed */
};

struct DataPhaseStats {
  uint64_t bytes = 0;
  uint32_t cookie = 0;
};

/* Runs the data phase for a session that is already in the
 * Transferring state. `deadlineMs` bounds the completion poll on
 * the monotonic clock. Returns the outcome and fills `stats` on
 * success. */
DataPhaseResult runDataPhase(V2Session& s, uint64_t deadlineMs,
                             DataPhaseStats& stats);

/* Registers the staging buffer for PUT objects of the given size
 * and records the MR on the session. Returns false when the
 * registration fails. */
bool stagePutBuffer(V2Session& s, size_t size, struct ibv_pd* pd);

/* Posts one receive that consumes the client's WRITE_WITH_IMM
 * carrying the session cookie. */
bool postRecvForImm(struct ibv_qp* qp, struct ibv_mr* mr, size_t len);

/* Posts one RDMA WRITE_WITH_IMM pushing `src` into the client MR
 * with the session cookie as the immediate (GET delivery). */
bool postWriteWithImm(struct ibv_qp* qp, struct ibv_mr* src,
                      uint64_t remoteAddr, uint32_t rkey, size_t len,
                      uint32_t immData);

/* Releases the session's staging MR (if any). Safe to call on a
 * session that never staged. */
void releaseStaging(V2Session& s);

} // namespace v2
} // namespace hipObj
