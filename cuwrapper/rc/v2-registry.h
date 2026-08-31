/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Per-token connection registry for the v2 protocol.
 *
 * Ownership model: the shared DeviceHandle owns
 * ctx/pd plus topology; each RcConnV2 owns exactly one qp/cq pair.
 * The registry serializes every mutation behind the library-wide
 * apiLock, so entries, capacity accounting, and the retired ring are
 * consistent without additional locks.
 *
 * Entry lifecycle:
 *
 *   Live ──claimDestroy──▶ Destroying ──commitDestroy(remains)──▶
 *   Poisoned ──claimDestroy(retry)──▶ Destroying ──commitDestroy(all
 *   gone)──▶ Destroyed ──eraseDestroyed──▶ (removed)
 *
 * abortClaim() cancels a claim before any destroy verb ran; it is a
 * TU-private helper called from exactly one place in
 * releaseConnection().
 *
 * Retired ring: guards against (qpn, psn) reuse by stale peers. A
 * reservation (Reserved, no expiry) is bound to the entry that will
 * need to record its QP; recording flips it to Recorded with a 60 s
 * expiry. Invariant: entry.reservationId != 0 implies entry.qp !=
 * nullptr (one-directional; Busy-deferred entries legally hold a
 * live QP with no reservation).
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include "ibv-core.h"
#include "v2-clock.h"

namespace hipObj {

struct DeviceHandle;

struct RcConnV2 {
  struct ibv_cq* cq = nullptr;
  struct ibv_qp* qp = nullptr;
  uint32_t qpNum = 0;
};

namespace v2 {

/* releaseConnection() result codes (mapped to hipObj errors at the
 * API boundary). */
constexpr int kReleaseOk = 0;
constexpr int kReleaseBusy = 1;
constexpr int kReleaseLeftover = 2;

using ConnId = uint64_t;

/* Protocol phase tracked per entry (v2-state machine). */
enum class Phase : uint8_t;

struct ConnectionEntryV2 {
  RcConnV2 conn;
  DeviceHandle* device = nullptr;
  uint64_t reservationId = 0; /* retired-ring slot for this QP */
  uint32_t clientPsn = 0;     /* client PSN (recorded on destroy) */
  uint8_t phase = 0;          /* v2::Phase, opaque here */
  bool poisoned = false;
  bool destroyClaimed = false;
  bool destroying = false;
};

/* Retired (qpn, psn) reuse guard ring. */
class RetiredRing {
public:
  static constexpr size_t kCapacity = 4096;
  static constexpr uint64_t kExpiryMs = 60'000;

  /* Collects expired Recorded slots; returns slots collected. */
  size_t collectExpired(uint64_t nowMs);

  /* Reserves a slot; 0 when the ring is full after collection. */
  uint64_t reserve();

  /* Releases a Reserved reservation (never recorded). */
  void unreserve(uint64_t reservationId);

  /* Reserved -> Recorded with (qpn, psn) and a fresh expiry.
   * Precondition: reservationId is Reserved and owned by the caller
   * (guaranteed by construction: all callers hold the apiLock and
   * the single-entry ownership invariant). */
  void record(uint64_t reservationId, uint32_t qpn, uint32_t psn);

  bool contains(uint32_t qpn, uint32_t psn) const;

  size_t used() const;
  size_t reservedCount() const;
  size_t recordedCount() const;

private:
  struct Slot {
    uint64_t reservationId = 0; /* 0 = free */
    bool recorded = false;
    uint64_t expireAtMs = 0;
    uint32_t qpn = 0;
    uint32_t psn = 0;
  };

  std::vector<Slot> slots_ = std::vector<Slot>(kCapacity);
  uint64_t nextReservationId_ = 1;
  size_t used_ = 0;
  size_t reserved_ = 0;
};

/* Library-wide lock. All v2 operations (and v1 entry points touching
 * shared state) run under this non-recursive mutex. Callbacks must
 * not re-enter the library; the contract is documented on the public
 * ops structures. */
std::mutex& apiLock();

class ConnectionRegistry {
public:
  static constexpr size_t kMaxConnections = 64;

  /* Capacity reservation; pairs with insert()/unreserveSlot(). */
  bool reserveSlot();
  void unreserveSlot();

  /* Inserts an entry (consumes one pending reserve). 0 when the
   * entry would exceed the capacity. */
  ConnId insert(ConnectionEntryV2&& entry);

  /* Lookup-only visitor; must not call registry mutations or public
   * callbacks from fn. */
  template <typename F>
  bool withEntry(ConnId id, F&& fn) {
    auto it = entries_.find(id);
    if (it == entries_.end()) {
      return false;
    }
    fn(it->second);
    return true;
  }

  /* Live|Poisoned -> Destroying; single claimant. */
  bool claimDestroy(ConnId id);

  /* Destroying -> Poisoned|Destroyed, reflecting destroyed objects. */
  void commitDestroy(ConnId id, bool qpGone, bool cqGone);

  /* Destroyed -> removed; releases capacity and the MR ref the entry
   * held. Returns false when the id is unknown or not Destroyed. */
  bool eraseDestroyed(ConnId id);

  bool isPoisoned(ConnId id) const;
  size_t size() const;
  size_t pendingReserves() const;

  /* Snapshot iteration: fn receives every live id. Mutations from
   * fn are forbidden (lookup-only contract). */
  template <typename F>
  void forEachId(F&& fn) const {
    for (const auto& [id, entry] : entries_) {
      fn(id);
    }
  }

  /* Access to the shared retired ring (apiLock held by callers). */
  RetiredRing& retired();

#ifdef HIPOBJ_UNIT_TESTS
  /* Test-only direct insertion bypassing reserveSlot() and
   * retiredReserve(); used to construct states the normal
   * sequencing cannot reach (for example a live qp without a
   * retired-ring reservation, to exercise the defensive busy
   * path). */
  ConnId insertRawForTest(ConnectionEntryV2&& entry);
#endif

private:
  ConnectionEntryV2* find(ConnId id);
  const ConnectionEntryV2* find(ConnId id) const;

  std::map<ConnId, ConnectionEntryV2> entries_;
  size_t pendingReserves_ = 0;
  RetiredRing retired_;
  ConnId nextId_ = 1;
};

/* Global v2 registry accessor (single instance). */
ConnectionRegistry& registry();

/* Test-only registry replacement; returns the previous one. */
ConnectionRegistry* setRegistryForTest(ConnectionRegistry* r);

} // namespace v2
} // namespace hipObj
