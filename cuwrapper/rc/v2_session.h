/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Server-side v2 session table.
 *
 * One mutex guards the entry map; a single table-scoped condition
 * variable covers state changes so waiters never hold references to
 * erased entries (predicates re-look-up by session id).
 *
 * Lifecycle:
 *
 *   Prepared --PREPARE 200 confirmed--> Publishing --send ok-->
 *     Prepared (deadline re-armed to T_prep)
 *   Prepared --READY--> Transferring --FINAL confirmed-->
 *     Completing --afterSend--> Reaping --> erased
 *   any --expiry (deadlineAt passed, observed under the lock)-->
 *     Reaping; release/cancel likewise.
 *
 * Preserve-errors (bad cookie/credentials, duplicate READY while
 * Transferring or Completing) never change the state - the session
 * stays for the next READY from the original requester.
 *
 * Teardown runs through claimDestroy/commitDestroy exactly like the
 * client registry: single claimant, per-object success reflected
 * into the pointers, poisoned entries stay for a retry.
 */

#pragma once

#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ibv-core.h"
#include "v2-clock.h"
#include "v2-registry.h"

namespace hipObj {

struct DeviceHandle;
struct RcConnV2;

namespace v2 {

/* Session phases. Values are internal; preserve-errors keep the
 * current phase untouched. */
enum class SessState : uint8_t {
  Prepared = 0,
  Publishing,
  Transferring,
  Completing,
  Reaping,
};

struct V2Session {
  std::string id; /* 32 hex */
  SessState state = SessState::Prepared;
  std::string op;
  std::string target;
  uint64_t size = 0;
  uint64_t offset = 0;
  std::string authorization; /* credential identity reference */
  std::string accessKey;     /* verified access key (identity) */
  uint32_t cookie = 0;
  uint32_t clientPsn = 0;
  uint32_t serverPsn = 0;
  uint32_t serverQpn = 0;
  uint64_t reservationId = 0;    /* retired-ring slot */
  uint64_t clientDeadlineAt = 0; /* ms, absolute (clockSource) */
  uint64_t txDeadlineAt = 0;     /* response transmission bound */
  int ioActive = 0;
  /* Origin of the outstanding io reference: true while the
   * worker holds it from READY entry to the final send. The
   * reaper force-releases only references still awaiting a
   * Publishing response; a Completing reference (live staging
   * data) is released by the cooperative finalizer. */
  bool ioFromCompleting = false;
  /* This session holds one device connection reference (set
   * when a QP was created for it, consumed exactly once when
   * that QP destroys successfully). Guards the CQ-only retry
   * and INIT-failure paths from double or missing releases. */
  bool connRefHeld = false;
  bool published = false;
  bool destroyClaimed = false;
  bool destroying = false;
  bool poisoned = false;
  /* Transport objects owned by the session. */
  struct ibv_qp* qp = nullptr;
  struct ibv_cq* cq = nullptr;
  DeviceHandle* device = nullptr;
  /* Client wire endpoints from the READY headers. */
  uint64_t clientMrAddr = 0; /* client MR address (PUT dest / GET src) */
  uint32_t clientMrRkey = 0; /* client MR rkey */
  uint32_t clientQpn = 0;    /* client QP to pair against */
  /* Peer endpoint decoded from the 88-hex token: routes the RTR
   * address handle to the real client GID instead of our own. */
  union ibv_gid peerGid;
  bool hasPeerGid = false;
  /* PUT staging (host buffer + MR owned by the session). */
  void* staging = nullptr;
  struct ibv_mr* stagingMr = nullptr;
};

class SessionTable {
public:
  /* Inserts a fresh session (ioActive = 1, caller owns the count).
   * Returns false when the id already exists. */
  bool insert(V2Session&& session);

  /* Snapshot look-up; fn must not mutate the table. */
  template <typename F>
  bool withSession(const std::string& id, F&& fn) {
    std::lock_guard<std::mutex> guard(mtx_);
    auto it = entries_.find(id);
    if (it == entries_.end()) {
      return false;
    }
    fn(it->second);
    return true;
  }

  /* Transitions Prepared -> Publishing, arming txDeadlineAt.
   * Returns false unless currently Prepared. */
  bool beginPublishing(const std::string& id);

  /* After a successful PREPARE send: Publishing -> Prepared with
   * the client deadline re-armed from now + tPrepMs. */
  bool finishPublishing(const std::string& id, uint64_t tPrepMs);

  /* Transferring transition from a READY (only from Prepared). */
  bool beginTransferring(const std::string& id, uint64_t tExecMs);

  /* FINAL response confirmed: Transferring -> Completing. */
  bool beginCompleting(const std::string& id);

  /* Expiry/terminal transition into Reaping (idempotent). */
  bool toReaping(const std::string& id);

  /* Wakes when the session leaves Publishing (waitDeadline is a
   * value copied by the caller). Returns the state observed (or
   * Reaping for an erased id). */
  SessState awaitNotPublishing(const std::string& id, uint64_t waitDeadlineMs);

  /* States helper for handlers. */
  SessState stateOf(const std::string& id);

  /* Destroy gate: single claimant per entry. */
  bool claimDestroy(const std::string& id);

  /* Reflects per-object destroy success; erases fully-destroyed
   * entries (caller feeds the retired ring before calling). */
  void commitDestroy(const std::string& id, bool qpOk, bool cqOk);

  bool eraseSession(const std::string& id);

  size_t size() const;

  /* Snapshot ids for iteration (reaper, shutdown drain). */
  std::vector<std::string> ids() const;

  /* Retired-ring operations, all serialized under the table lock
   * so concurrent workers and the reaper cannot interleave ring
   * mutations with session state changes. */
  uint64_t ringReserve();
  void ringUnreserve(uint64_t reservationId);
  void ringRecord(uint64_t reservationId, uint32_t qpn, uint32_t psn);
  void ringCollectExpired(uint64_t nowMs);

  /* Acquires (ioActive++) and releases the handler reference for a
   * session. Release returns the post-decrement count. */
  bool acquireIo(const std::string& id);
  int releaseIo(const std::string& id);

private:
  mutable std::mutex mtx_;
  std::map<std::string, V2Session> entries_;
  /* Table-scoped CV: safe against entry erase. */
  std::condition_variable cv_;
  /* (qpn, psn) reuse guard ring; guarded by mtx_. */
  RetiredRing ring_;
};

} // namespace v2
} // namespace hipObj
