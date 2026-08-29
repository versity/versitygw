/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "v2-registry.h"

#include <utility>

namespace hipObj {
namespace v2 {

std::mutex& apiLock() {
  static std::mutex lock;
  return lock;
}

// ---- RetiredRing ---------------------------------------------------

size_t RetiredRing::collectExpired(uint64_t nowMs) {
  size_t collected = 0;
  for (auto& slot : slots_) {
    if (slot.reservationId != 0 && slot.recorded && nowMs >= slot.expireAtMs) {
      slot = Slot{};
      --used_;
      ++collected;
    }
  }
  return collected;
}

uint64_t RetiredRing::reserve() {
  for (auto& slot : slots_) {
    if (slot.reservationId == 0) {
      slot.reservationId = nextReservationId_++;
      slot.recorded = false;
      slot.expireAtMs = 0;
      slot.qpn = 0;
      slot.psn = 0;
      ++used_;
      ++reserved_;
      return slot.reservationId;
    }
  }
  return 0;
}

void RetiredRing::unreserve(uint64_t reservationId) {
  if (reservationId == 0) {
    return;
  }
  for (auto& slot : slots_) {
    if (slot.reservationId == reservationId && !slot.recorded) {
      slot = Slot{};
      --used_;
      --reserved_;
      return;
    }
  }
}

void RetiredRing::record(uint64_t reservationId, uint32_t qpn, uint32_t psn) {
  /* Precondition: reservationId refers to a Reserved slot owned by
   * the caller. All call sites hold the apiLock and the entry
   * invariant, so a miss is a programming error; treat it as a
   * no-op rather than corrupting the ring. */
  for (auto& slot : slots_) {
    if (slot.reservationId == reservationId && !slot.recorded) {
      slot.recorded = true;
      slot.expireAtMs = clockSource().nowMs() + kExpiryMs;
      slot.qpn = qpn;
      slot.psn = psn;
      --reserved_;
      return;
    }
  }
}

bool RetiredRing::contains(uint32_t qpn, uint32_t psn) const {
  for (const auto& slot : slots_) {
    if (slot.reservationId != 0 && slot.recorded && slot.qpn == qpn &&
        slot.psn == psn) {
      return true;
    }
  }
  return false;
}

size_t RetiredRing::used() const {
  return used_;
}

size_t RetiredRing::reservedCount() const {
  return reserved_;
}

size_t RetiredRing::recordedCount() const {
  return used_ - reserved_;
}

// ---- ConnectionRegistry ---------------------------------------------

bool ConnectionRegistry::reserveSlot() {
  if (entries_.size() + pendingReserves_ >= kMaxConnections) {
    return false;
  }
  ++pendingReserves_;
  return true;
}

void ConnectionRegistry::unreserveSlot() {
  if (pendingReserves_ > 0) {
    --pendingReserves_;
  }
}

ConnId ConnectionRegistry::insert(ConnectionEntryV2&& entry) {
  if (pendingReserves_ == 0 ||
      entries_.size() + pendingReserves_ > kMaxConnections) {
    return 0;
  }
  --pendingReserves_;
  ConnId id = nextId_++;
  entries_.emplace(id, std::move(entry));
  return id;
}

bool ConnectionRegistry::claimDestroy(ConnId id) {
  auto it = entries_.find(id);
  if (it == entries_.end()) {
    return false;
  }
  ConnectionEntryV2& entry = it->second;
  /* Single claimant: a live entry claims once; a poisoned entry may
   * be re-claimed for the destroy retry. */
  if (entry.destroying || (entry.destroyClaimed && !entry.poisoned)) {
    return false;
  }
  entry.destroying = true;
  entry.destroyClaimed = true;
  return true;
}

void ConnectionRegistry::commitDestroy(ConnId id, bool qpGone, bool cqGone) {
  auto it = entries_.find(id);
  if (it == entries_.end()) {
    return;
  }
  ConnectionEntryV2& entry = it->second;
  if (!entry.destroying) {
    return;
  }
  if (qpGone) {
    entry.conn.qp = nullptr;
    entry.conn.qpNum = 0;
  }
  if (cqGone) {
    entry.conn.cq = nullptr;
  }
  if (entry.conn.qp == nullptr && entry.conn.cq == nullptr) {
    entry.poisoned = false;
    entry.destroying = false;
    /* entry stays until eraseDestroyed(); destroyClaimed remains
     * true so no new claim can race the erase. */
  } else {
    entry.poisoned = true;
    entry.destroying = false;
  }
}

bool ConnectionRegistry::eraseDestroyed(ConnId id) {
  auto it = entries_.find(id);
  if (it == entries_.end()) {
    return false;
  }
  ConnectionEntryV2& entry = it->second;
  if (entry.conn.qp != nullptr || entry.conn.cq != nullptr) {
    return false;
  }
  entries_.erase(it);
  return true;
}

bool ConnectionRegistry::isPoisoned(ConnId id) const {
  auto it = entries_.find(id);
  return it != entries_.end() && it->second.poisoned;
}

size_t ConnectionRegistry::size() const {
  return entries_.size();
}

size_t ConnectionRegistry::pendingReserves() const {
  return pendingReserves_;
}

RetiredRing& ConnectionRegistry::retired() {
  return retired_;
}

#ifdef HIPOBJ_UNIT_TESTS
ConnId ConnectionRegistry::insertRawForTest(ConnectionEntryV2&& entry) {
  ConnId id = nextId_++;
  entries_.emplace(id, std::move(entry));
  return id;
}
#endif

namespace {

ConnectionRegistry g_registry;
ConnectionRegistry* g_registryOverride = nullptr;

} // namespace

ConnectionRegistry& registry() {
  return g_registryOverride ? *g_registryOverride
                            : static_cast<ConnectionRegistry&>(g_registry);
}

ConnectionRegistry* setRegistryForTest(ConnectionRegistry* r) {
  ConnectionRegistry* previous = g_registryOverride;
  g_registryOverride = r;
  return previous;
}

} // namespace v2
} // namespace hipObj
