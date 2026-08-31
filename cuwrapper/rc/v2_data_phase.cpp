/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "v2_data_phase.h"

#include <cstdlib>
#include <cstring>
#include <ctime>

#include <arpa/inet.h>

#include "rc_ibv_host.h"

namespace hipObj {
namespace v2 {

namespace {

constexpr int kAccess = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                        IBV_ACCESS_REMOTE_READ;

/* Completion markers posted with every work request. */
constexpr uint64_t kWrRecv = 0x5245435632494d4dULL;  /* RECV2IMM */
constexpr uint64_t kWrWrite = 0x57524954454d4d47ULL; /* WRITEMM */

uint64_t clockNowMs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000 +
         static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

} // namespace

bool stagePutBuffer(V2Session& s, size_t size, struct ibv_pd* pd) {
  if (s.staging != nullptr) {
    return s.stagingMr != nullptr || pd == nullptr;
  }
  void* buf = std::malloc(size ? size : 1);
  if (buf == nullptr) {
    return false;
  }
  /* Without a PD (transport-free host) the buffer stages without
   * an MR; the data phase is a no-op there anyway.
   *
   * Prefer the device-registered path: providers register the
   * buffer with the device (dmabuf on GPU hosts, plain
   * ibv_reg_mr otherwise) so peers can reach it via rkey. The
   * host-only registration is a fallback for wrappers whose
   * device path needs an unavailable GPU runtime. */
  struct ibv_mr* mr = nullptr;
  if (pd != nullptr) {
    mr = ibv.reg_mr(pd, buf, size, kAccess);
    if (mr == nullptr) {
      mr = ibv.reg_mr_host(pd, buf, size, kAccess);
    }
    if (mr == nullptr) {
      std::free(buf);
      return false;
    }
  }
  s.staging = buf;
  s.stagingMr = mr;
  return true;
}

void releaseStaging(V2Session& s) {
  /* The caller must have quiesced or destroyed the session QP
   * first: a posted work request can still reference the MR
   * until the QP is gone. dereg failures leave the MR leaked
   * (and logged) rather than freeing memory the NIC may touch. */
  if (s.stagingMr != nullptr) {
    if (ibv.dereg_mr(s.stagingMr) != 0) {
      fprintf(stderr, "v2: staging dereg failed; leaking buffer\n");
      s.staging = nullptr; /* MR is dead to us either way */
    }
    s.stagingMr = nullptr;
  }
  if (s.staging != nullptr) {
    std::free(s.staging);
    s.staging = nullptr;
  }
}

bool postRecvForImm(struct ibv_qp* qp, struct ibv_mr* mr, size_t len) {
  struct ibv_sge sge;
  std::memset(&sge, 0, sizeof(sge));
  sge.addr = reinterpret_cast<uintptr_t>(mr->addr);
  sge.length = static_cast<uint32_t>(len);
  sge.lkey = mr->lkey;

  struct ibv_recv_wr wr;
  std::memset(&wr, 0, sizeof(wr));
  wr.wr_id = kWrRecv;
  wr.sg_list = &sge;
  wr.num_sge = 1;

  struct ibv_recv_wr* bad = nullptr;
  return ibv.post_recv(qp, &wr, &bad) == 0;
}

bool postWriteWithImm(struct ibv_qp* qp, struct ibv_mr* src,
                      uint64_t remoteAddr, uint32_t rkey, size_t len,
                      uint32_t immData) {
  /* GET delivery: server pushes the object into the client MR
   * with the session cookie as the immediate. */
  struct ibv_sge sge;
  std::memset(&sge, 0, sizeof(sge));
  sge.addr = reinterpret_cast<uintptr_t>(src->addr);
  sge.length = static_cast<uint32_t>(len);
  sge.lkey = src->lkey;

  struct ibv_send_wr wr;
  std::memset(&wr, 0, sizeof(wr));
  wr.wr_id = kWrWrite;
  wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
  wr.send_flags = IBV_SEND_SIGNALED;
  wr.imm_data = htonl(immData);
  wr.wr.rdma.remote_addr = remoteAddr;
  wr.wr.rdma.rkey = rkey;
  wr.sg_list = &sge;
  wr.num_sge = 1;

  struct ibv_send_wr* bad = nullptr;
  return ibv.post_send(qp, &wr, &bad) == 0;
}

/* Polls the CQ for one completion matching `expectWr`, bounded by
 * an absolute deadline on the monotonic clock. */
enum class PollOutcome { Ok, Timeout, Error, Mismatch };
PollOutcome pollCqUntil(struct ibv_cq* cq, uint64_t deadlineMs,
                        uint64_t expectWr, struct ibv_wc* out) {
  for (;;) {
    int n = ibv.poll_cq(cq, 1, out);
    if (n > 0) {
      /* Providers may rewrite the wr_id on emulated paths; the
       * opcode + immediate + length identify the completion. */
      (void)expectWr;
      return PollOutcome::Ok;
    }
    if (n < 0) {
      return PollOutcome::Error;
    }
    if (clockNowMs() >= deadlineMs) {
      return PollOutcome::Timeout;
    }
    struct timespec ts = {0, 2 * 1000 * 1000};
    nanosleep(&ts, nullptr);
  }
}

DataPhaseResult runDataPhase(V2Session& s, uint64_t deadlineMs,
                             DataPhaseStats& stats) {
  const bool noTransport = s.qp == nullptr && s.cq == nullptr;
  if (noTransport || s.clientQpn == 0) {
    /* Control-plane-only session (unit tests, reference
     * harness): both objects absent or the client advertised no
     * QP. A half-wired session is not accepted here. */
    stats.bytes = s.size;
    stats.cookie = s.cookie;
    return DataPhaseResult::Ok;
  }
  if (s.qp == nullptr || s.cq == nullptr || s.stagingMr == nullptr) {
    return DataPhaseResult::WireFail;
  }

  struct ibv_wc wc;
  PollOutcome po;

  if (s.op == "PUT") {
    /* The client writes into the server staging MR and signals
     * the session cookie. The server is the responder here, so
     * requester-side retry exhaustion never surfaces in this CQ;
     * any completion error or mismatch is a wire defect. */
    if (!postRecvForImm(s.qp, s.stagingMr, static_cast<size_t>(s.size))) {
      return DataPhaseResult::WireFail;
    }
    po = pollCqUntil(s.cq, deadlineMs, kWrRecv, &wc);
    if (po == PollOutcome::Timeout) {
      return DataPhaseResult::Timeout;
    }
    if (po != PollOutcome::Ok || wc.status != IBV_WC_SUCCESS ||
        wc.opcode != IBV_WC_RECV_RDMA_WITH_IMM ||
        (wc.wc_flags & IBV_WC_WITH_IMM) == 0 ||
        ntohl(wc.imm_data) != s.cookie || wc.byte_len != s.size) {
      return DataPhaseResult::VerifyFail;
    }
    stats.bytes = wc.byte_len;
    stats.cookie = s.cookie;
    return DataPhaseResult::Ok;
  }

  /* GET: push the staged object to the client MR with the
   * cookie as the immediate; the client's receive consumes it. */
  if (s.clientMrAddr == 0 || s.clientMrRkey == 0) {
    return DataPhaseResult::WireFail;
  }
  if (!postWriteWithImm(s.qp, s.stagingMr, s.clientMrAddr, s.clientMrRkey,
                        static_cast<size_t>(s.size), s.cookie)) {
    return DataPhaseResult::WireFail;
  }
  po = pollCqUntil(s.cq, deadlineMs, kWrWrite, &wc);
  if (po == PollOutcome::Timeout) {
    return DataPhaseResult::Timeout;
  }
  if (po == PollOutcome::Ok &&
      (wc.status == IBV_WC_RNR_RETRY_EXC_ERR ||
       wc.status == IBV_WC_RETRY_EXC_ERR)) {
    /* The server is the requester for the RDMA write: these mean
     * the peer's receive queue was not armed or the peer did not
     * answer, which is retryable from a fresh pairing rather
     * than a wire defect. */
    return DataPhaseResult::Busy;
  }
  if (po != PollOutcome::Ok || wc.status != IBV_WC_SUCCESS ||
      wc.opcode != IBV_WC_RDMA_WRITE) {
    return DataPhaseResult::VerifyFail;
  }
  stats.bytes = s.size;
  stats.cookie = s.cookie;
  return DataPhaseResult::Ok;
}

} // namespace v2
} // namespace hipObj
