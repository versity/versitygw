/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "v2-transport.h"

#include <atomic>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>

#include "rc_ibv_host.h"
#include "transport.h"
#include "vendor-ops.h"

namespace hipObj {
namespace v2 {

namespace {

constexpr int kCqSize = 16;
constexpr int kMaxSendWr = 16;
constexpr int kMaxRecvWr = 16;

/* TU-private cancel for a claim that never reached a destroy verb.
 * Called from exactly one place in releaseConnection(), before the
 * destroy_qp branch; after any destroy attempt the procedure must
 * end in commitDestroy() instead. The entry lands back in Poisoned
 * so a retry can claim it again. */
bool abortClaim(ConnId id) {
  ConnectionRegistry& reg = registry();
  bool ok = false;
  reg.withEntry(id, [&](ConnectionEntryV2& entry) {
    if (entry.destroying) {
      entry.destroying = false;
      entry.poisoned = true;
      ok = true;
    }
  });
  return ok;
}

/* Vendor QP attributes depend only on the device, not on the
 * connection struct, so both v1 and v2 transitions share the same
 * helpers below (mirrors transport.cpp's applyVendorQpAttrs). */
void applyVendorQpAttrs(struct ibv_context* ctx, struct ibv_qp_attr* attr) {
  if (!ctx || !attr) {
    return;
  }
  struct ibv_device_attr devAttr;
  std::memset(&devAttr, 0, sizeof(devAttr));
  if (ibv.query_device(ctx, &devAttr) != 0) {
    return;
  }
#ifdef HIPOBJ_BNXT
  if (isBnxtDevice(devAttr.vendor_id)) {
    configureBnxtQp(attr);
  }
#endif
#ifdef HIPOBJ_IONIC
  if (isIonicDevice(devAttr.vendor_id)) {
    configureIonicQp(attr);
  }
#endif
}

int modifyQpToInit(DeviceHandle* dh, struct ibv_qp* qp) {
  struct ibv_qp_attr attr;
  std::memset(&attr, 0, sizeof(attr));
  attr.qp_state = IBV_QPS_INIT;
  attr.pkey_index = 0;
  attr.port_num = dh->portNum;
  attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
  applyVendorQpAttrs(dh->ctx, &attr);
  int mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
             IBV_QP_ACCESS_FLAGS;
  return ibv.modify_qp(qp, &attr, mask);
}

int modifyQpToRtr(struct ibv_context* ctx, struct ibv_qp* qp,
                  uint32_t destQpNum, uint16_t destLid, union ibv_gid destGid,
                  int gidIndex, uint32_t rqPsn, uint8_t portNum) {
  struct ibv_qp_attr attr;
  std::memset(&attr, 0, sizeof(attr));
  attr.qp_state = IBV_QPS_RTR;
  /* The path MTU must not exceed the port's active MTU: emulated
   * devices commonly report 1024 while HCAs run 4096, and a
   * larger value fails the transition with EINVAL. */
  {
    struct ibv_port_attr pa;
    std::memset(&pa, 0, sizeof(pa));
    if (ibv.query_port(ctx, portNum, &pa) == 0 &&
        pa.active_mtu >= IBV_MTU_512) {
      attr.path_mtu = static_cast<enum ibv_mtu>(pa.active_mtu);
    } else {
      attr.path_mtu = IBV_MTU_1024;
    }
  }
  applyVendorQpAttrs(ctx, &attr);
  attr.dest_qp_num = destQpNum;
  attr.rq_psn = rqPsn;
  attr.max_dest_rd_atomic = 1;
  attr.min_rnr_timer = 12;
  /* hipObject targets RoCEv2: the GRH with the peer GID is
   * the routing path; the LID stays unused on RoCE links. */
  attr.ah_attr.is_global = 1;
  attr.ah_attr.dlid = 0;
  attr.ah_attr.grh.dgid = destGid;
  attr.ah_attr.grh.hop_limit = 64;
  attr.ah_attr.grh.sgid_index = gidIndex;
  attr.ah_attr.grh.traffic_class = 0;
  attr.ah_attr.sl = 0;
  attr.ah_attr.src_path_bits = 0;
  /* Service type needs the port in the address handle; leaving
   * it zero fails the transition on providers that validate it
   * (the emulated NIC rejects port 0 with EINVAL). */
  attr.ah_attr.port_num = portNum;
  int mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
             IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
  return ibv.modify_qp(qp, &attr, mask);
}

int modifyQpToRts(struct ibv_context* ctx, struct ibv_qp* qp, uint32_t sqPsn) {
  struct ibv_qp_attr attr;
  std::memset(&attr, 0, sizeof(attr));
  attr.qp_state = IBV_QPS_RTS;
  applyVendorQpAttrs(ctx, &attr);
  attr.timeout = 14;
  attr.retry_cnt = 7;
  attr.rnr_retry = 7;
  attr.sq_psn = sqPsn;
  attr.max_rd_atomic = 1;
  int mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
             IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
  return ibv.modify_qp(qp, &attr, mask);
}

} // namespace

int createRcConnV2(DeviceHandle* dh, RcConnV2& conn, bool* rollbackFailed) {
  if (rollbackFailed) {
    *rollbackFailed = false;
  }
  bool sawCq = false;
  conn.cq = ibv.create_cq(dh->ctx, kCqSize, nullptr, nullptr, 0);
  if (!conn.cq) {
    return -1;
  }
  sawCq = true;
  struct ibv_qp_init_attr init;
  std::memset(&init, 0, sizeof(init));
  init.qp_type = IBV_QPT_RC;
  init.send_cq = conn.cq;
  init.recv_cq = conn.cq;
  init.cap.max_send_wr = kMaxSendWr;
  init.cap.max_recv_wr = kMaxRecvWr;
  init.cap.max_send_sge = 1;
  init.cap.max_recv_sge = 1;
  conn.qp = ibv.create_qp(dh->pd, &init);
  if (!conn.qp) {
    bool cqOk = true;
    if (ibv.destroy_cq(conn.cq) != 0) {
      cqOk = false;
      /* Keep conn.cq when the destroy failed: clearing it would
       * lose the handle the caller needs for the reaper retry. */
    } else {
      conn.cq = nullptr;
    }
    if (!cqOk) {
      if (rollbackFailed) {
        *rollbackFailed = true;
      }
      return -1;
    }
    return -1;
  }
  conn.qpNum = conn.qp->qp_num;
  /* Threaded callers share the device handle; the counter must
   * be atomic to avoid a data race on concurrent PREPAREs. */
  dh->connRefs.fetch_add(1, std::memory_order_relaxed);
  return 0;
}

void destroyRcConnV2(RcConnV2& conn, bool* qpOk, bool* cqOk) {
  if (qpOk) {
    *qpOk = true;
  }
  if (cqOk) {
    *cqOk = true;
  }
  /* A successful destroy clears the handle so callers storing
   * the surviving pointers never re-destroy them. */
  if (conn.qp) {
    if (ibv.destroy_qp(conn.qp) == 0) {
      conn.qp = nullptr;
    } else if (qpOk) {
      *qpOk = false;
    }
  }
  if (conn.cq) {
    if (ibv.destroy_cq(conn.cq) == 0) {
      conn.cq = nullptr;
    } else if (cqOk) {
      *cqOk = false;
    }
  }
}

int createRcQpOnly(DeviceHandle* dh, struct ibv_cq* cq, RcConnV2& conn) {
  if (!cq) {
    return -1;
  }
  struct ibv_qp_init_attr init;
  std::memset(&init, 0, sizeof(init));
  init.qp_type = IBV_QPT_RC;
  init.send_cq = cq;
  init.recv_cq = cq;
  init.cap.max_send_wr = kMaxSendWr;
  init.cap.max_recv_wr = kMaxRecvWr;
  init.cap.max_send_sge = 1;
  init.cap.max_recv_sge = 1;
  conn.qp = ibv.create_qp(dh->pd, &init);
  if (!conn.qp) {
    return -1;
  }
  conn.qpNum = conn.qp->qp_num;
  return 0;
}

int transitionQpToInitV2(DeviceHandle* dh, RcConnV2& conn) {
  return modifyQpToInit(dh, conn.qp);
}

int rearmQpToInitV2(DeviceHandle* dh, RcConnV2& conn) {
  /* RESET is the only transition valid from every QP state. */
  struct ibv_qp_attr attr;
  std::memset(&attr, 0, sizeof(attr));
  attr.qp_state = IBV_QPS_RESET;
  if (ibv.modify_qp(conn.qp, &attr, IBV_QP_STATE) != 0) {
    return -1;
  }
  return modifyQpToInit(dh, conn.qp);
}

int transitionQpToRtrV2(DeviceHandle* dh, RcConnV2& conn, uint32_t destQpNum,
                        uint16_t destLid, union ibv_gid destGid,
                        uint32_t rqPsn) {
  return modifyQpToRtr(dh->ctx, conn.qp, destQpNum, destLid, destGid,
                       dh->gidIndex, rqPsn, dh->portNum);
}

int transitionQpToRtsV2(RcConnV2& conn, DeviceHandle* dh, uint32_t sqPsn) {
  return modifyQpToRts(dh->ctx, conn.qp, sqPsn);
}

void releaseDevice(DeviceHandle* dh) {
  if (!dh) {
    return;
  }
  uint32_t cur = dh->connRefs.load(std::memory_order_relaxed);
  while (cur > 0 &&
         !dh->connRefs.compare_exchange_weak(cur, cur - 1,
                                             std::memory_order_relaxed)) {
  }
  /* PD/context close happens only when the buffer map is empty too;
   * the caller (hipObjShutdown stage) checks both. */
}

int postRecvImm(DeviceHandle* dh, RcConnV2& conn) {
  (void)dh;
  struct ibv_recv_wr wr;
  struct ibv_recv_wr* bad = nullptr;
  struct ibv_sge sge; /* zero-SGE: no scatter entry */
  std::memset(&wr, 0, sizeof(wr));
  std::memset(&sge, 0, sizeof(sge));
  wr.wr_id = kRecvImm;
  wr.sg_list = nullptr;
  wr.num_sge = 0;
  return ibv.post_recv(conn.qp, &wr, &bad);
}

int releaseConnection(ConnId id) {
  ConnectionRegistry& reg = registry();
  if (!reg.claimDestroy(id)) {
    return 0; /* claimed elsewhere or already gone: idempotent */
  }
  bool hasQp = false;
  uint64_t rid = 0;
  uint32_t qpn = 0;
  reg.withEntry(id, [&](ConnectionEntryV2& entry) {
    hasQp = entry.conn.qp != nullptr;
    rid = entry.reservationId;
    qpn = entry.conn.qpNum;
    entry.reservationId = 0; /* local ownership during destroy */
  });
  if (hasQp && rid == 0) {
    /* Defensive: the normal creation sequence always inserts an
     * entry with a live reservation, so a live qp without one is
     * not expected. Keep the handling anyway so the teardown path
     * stays complete: reserve a slot now, and report busy when the
     * retired ring is exhausted so the caller can retry later. */
    rid = reg.retired().reserve();
    if (rid == 0) {
      abortClaim(id); /* pre-destroy cancel; stays reclaimable */
      return kReleaseBusy;
    }
    reg.withEntry(id, [&](ConnectionEntryV2& entry) {
      entry.reservationId = rid;
    });
  }
  bool qpOk = true;
  bool cqOk = true;
  uint32_t psn = 0;
  reg.withEntry(id, [&](ConnectionEntryV2& entry) {
    psn = entry.clientPsn; /* recorded into the retired ring below */
    if (entry.conn.qp) {
      qpOk = ibv.destroy_qp(entry.conn.qp) == 0;
      if (qpOk) {
        if (rid != 0) {
          /* Record the destroyed pair immediately; the tuple tracks
           * the QP lifetime, independent of the CQ result below. */
          reg.retired().record(rid, qpn, psn);
        }
        entry.conn.qp = nullptr;
        entry.conn.qpNum = 0;
      } else {
        entry.reservationId = rid; /* keep for the retry */
      }
    } else if (rid != 0) {
      /* No live qp: the reservation serves no future destroy. */
      reg.retired().unreserve(rid);
    }
    if (entry.conn.cq) {
      cqOk = ibv.destroy_cq(entry.conn.cq) == 0;
      if (cqOk) {
        entry.conn.cq = nullptr;
      }
    }
  });
  reg.commitDestroy(id, qpOk, cqOk);
  if (qpOk && cqOk) {
    reg.eraseDestroyed(id);
    return 0;
  }
  return kReleaseLeftover;
}

int discardAndRecreateQp(ConnId id) {
  ConnectionRegistry& reg = registry();

  /* Local slot B guards the tuple we are about to retire. */
  uint64_t slotB = reg.retired().reserve();
  if (slotB == 0) {
    return kReleaseBusy;
  }

  struct Captured {
    struct ibv_qp* qp = nullptr;
    struct ibv_cq* cq = nullptr;
    DeviceHandle* device = nullptr;
    uint64_t rid = 0;
    uint32_t qpn = 0;
    uint32_t psn = 0;
  } cap;

  bool found = reg.withEntry(id, [&](ConnectionEntryV2& entry) {
    cap.qp = entry.conn.qp;
    cap.cq = entry.conn.cq;
    cap.device = entry.device;
    cap.rid = entry.reservationId;
    cap.qpn = entry.conn.qpNum;
    cap.psn = entry.clientPsn;
  });
  if (!found || !cap.qp || !cap.cq || cap.rid == 0) {
    /* Nothing to discard or the entry is mid-teardown. */
    reg.retired().unreserve(slotB);
    return kReleaseLeftover;
  }

  /* Destroy the old qp; on failure keep the live qp and return. */
  if (ibv.destroy_qp(cap.qp) != 0) {
    reg.retired().unreserve(slotB);
    return kReleaseLeftover;
  }
  reg.retired().record(slotB, cap.qpn, cap.psn);

  /* The old reservation A is released back: the tuple it guarded is
   * now recorded through slot B, tied to the destroyed qp. */
  reg.retired().unreserve(cap.rid);

  /* Move ownership of A's slot to the caller and clear the fields
   * before the recreate attempt, so the entry never holds a live
   * reservationId without a qp. */
  reg.withEntry(id, [&](ConnectionEntryV2& entry) {
    entry.reservationId = 0;
    entry.conn.qp = nullptr;
    entry.conn.qpNum = 0;
  });

  RcConnV2 fresh;
  if (createRcQpOnly(cap.device, cap.cq, fresh) != 0) {
    /* No qp: release through the normal teardown path (the cq is
     * destroyed there) and report the failure. */
    int rc = releaseConnection(id);
    if (rc != 0) {
      return rc;
    }
    return kReleaseLeftover;
  }

  reg.withEntry(id, [&](ConnectionEntryV2& entry) {
    entry.conn.qp = fresh.qp;
    entry.conn.qpNum = fresh.qpNum;
    entry.reservationId = cap.rid;
  });
  return 0;
}

bool validateDataCompletion(const struct ibv_wc& wc,
                            const WcExpectation& expect, const char** reason) {
  if (wc.status != IBV_WC_SUCCESS) {
    *reason = "completion status is not success";
    return false;
  }
  if (wc.wr_id != expect.wrId) {
    *reason = "unexpected wr_id";
    return false;
  }
  if (expect.kind == WcKind::kGet) {
    if (wc.opcode != IBV_WC_RECV_RDMA_WITH_IMM) {
      *reason = "expected RECV_RDMA_WITH_IMM";
      return false;
    }
  } else {
    if (wc.opcode != IBV_WC_RECV) {
      *reason = "expected RECV";
      return false;
    }
    if (!(wc.wc_flags & IBV_WC_WITH_IMM)) {
      *reason = "immediate flag missing";
      return false;
    }
  }
  if (ntohl(wc.imm_data) != expect.cookie) {
    *reason = "immediate cookie mismatch";
    return false;
  }
  *reason = "";
  return true;
}

} // namespace v2
} // namespace hipObj
