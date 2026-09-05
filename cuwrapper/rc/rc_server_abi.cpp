/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "rc_server_abi.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <cstdarg>
#include <cstdio>

#include "rc_ibv_host.h"
#include "v2_data_phase.h"
#include "v2-random.h"
#include "v2_session.h"
#include "v2-registry.h"
#include "token.h"
#include "v2-transport.h"

namespace {

using hipObj::v2::SessState;
using hipObj::v2::SessionTable;
using hipObj::v2::V2Session;

constexpr size_t kMaxTransfer = 0x7fffffff;

/* Product limits for metadata echoed on the wire. */
constexpr size_t kMaxEtag = 127;
constexpr size_t kMaxVersion = 127;
constexpr size_t kMaxTarget = 2047;

struct RcSession {
  V2Session core;
  uint64_t epoch = 0;
  std::atomic<uint64_t> next_nonce{1};
  /* staged metadata from finish_staging (GET) or finish_put. */
  std::string etag;
  std::string version_id;
  bool stage_done = false;
  bool reap_pending = false;
  /* Absolute deadlines (ms since the monotonic clock epoch);
   * zero disables the check. */
  uint64_t prep_deadline_ms = 0;
  uint64_t exec_deadline_ms = 0;
  /* staging allocation owned by the session. */
  uint8_t *staging_buf = nullptr;
  size_t staging_len = 0;
  struct ibv_mr *staging_mr = nullptr;
  /* handle bookkeeping: consume-once per issue. */
  rc_handle staging_lease{};
  rc_handle put_view{};
  rc_principal_id principal{};
  /* completion refs: activeRef pins the session from READY entry
   * until the finalizer (finish_final / finish_put); putRef pins
   * a borrowed put view until finish_put consumes it. */
  uint32_t active_ref = 0;
  uint32_t put_ref = 0;
  /* Last data-phase outcome (RC_READY_*), valid after a READY. */
  int last_outcome = RC_READY_OK;
  /* Peer endpoint decoded from the PREPARE token, when present. */
  bool has_peer_gid = false;
};

std::string strIn(rc_str_in s) {
  return s.ptr ? std::string(s.ptr, s.len) : std::string();
}

bool handleValid(const rc_handle &h) { return h.nonce != 0; }

void clearHandle(rc_handle &h) { h.nonce = 0; }

/* Reaper condition: the session may only lose its transport
 * objects once every reference has been handed back. */
bool reaperReady(const RcSession &s) {
  return (s.reap_pending || s.core.state == SessState::Reaping);
}

}  // namespace

struct rc_server {
  hipObj::DeviceHandle *device = nullptr;
  SessionTable table;
  rc_device_opts opts{};
  /* Diagnostic sink: null keeps stderr-only error reporting.
   * Reads/writes are plain loads/stores; the sink is installed
   * once at init time (before the reaper starts) and only
   * cleared by destroy after the reaper joined, so no thread
   * races an in-flight sink pointer swap. */
  rc_log_fn log_fn = nullptr;
  void *log_ctx = nullptr;
  std::atomic<uint64_t> epoch_counter{1};
  /* resource accounting (global buckets; per-principal map). */
  std::mutex acct_mtx;
  uint32_t sessions = 0;
  uint64_t staging_bytes = 0;
  uint32_t qps = 0;
  std::unordered_map<std::string, std::pair<uint32_t, uint64_t>>
      per_user; /* key = principal id hex -> {sessions, staging} */
  std::unordered_map<std::string, std::unique_ptr<RcSession>>
      sessions_map;
  std::mutex map_mtx;
  std::atomic<bool> closing{false};
  /* concurrency slots. */
  std::atomic<uint32_t> ready_slots{0};
  std::atomic<uint32_t> stage_slots{0};
  /* expiry reaper thread: marks sessions past their prepare or
   * execute deadline for reaping. Joined by rc_server_destroy. */
  std::thread reaper;
  std::atomic<bool> reaper_stop{false};
  /* Set when a reaped session could not be fully torn down (QP/
   * CQ destroy or MR dereg failed): surviving verbs objects may
   * still reference the shared PD, so destroy must not close the
   * device under them. */
  std::atomic<bool> reap_failure{false};
};

namespace {

/* Emits a diagnostic line to the installed sink (level 0 keeps
 * the stderr error stream intact by also printing there, so
 * existing deployments do not lose the only log they had).
 * Callers must not hold map_mtx/acct_mtx when calling. */
void rcLog(const rc_server *srv, int level, const char *file, int line,
           const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (level <= 0) fprintf(stderr, "%s\n", buf);
  rc_log_fn fn = srv->log_fn;
  if (fn) fn(srv->log_ctx, level, buf, file, line);
}

RcSession *findSession(rc_server *srv, const std::string &id) {
  auto it = srv->sessions_map.find(id);
  return it == srv->sessions_map.end() ? nullptr : it->second.get();
}

std::string principalKey(const rc_principal_id &p) {
  return std::string(reinterpret_cast<const char *>(p.id),
                     sizeof(p.id));
}

bool principalEq(const rc_principal_id &a, const rc_principal_id &b) {
  return std::memcmp(a.id, b.id, sizeof(a.id)) == 0;
}

bool limitsTake(rc_server *srv, const rc_principal_id &who,
                uint64_t staging) {
  std::lock_guard<std::mutex> g(srv->acct_mtx);
  if (srv->sessions + 1 > srv->opts.max_sessions) return false;
  if (srv->staging_bytes + staging > srv->opts.max_staging_bytes)
    return false;
  if (srv->qps + 1 > srv->opts.max_qps) return false;
  auto &u = srv->per_user[principalKey(who)];
  if (u.first + 1 > srv->opts.max_user_sessions) return false;
  if (u.second + staging > srv->opts.max_user_staging_bytes)
    return false;
  /* Each session owns exactly one QP, so the per-user QP budget
   * bounds the session count the same way the global one does. */
  if (srv->opts.max_user_qps && u.first + 1 > srv->opts.max_user_qps)
    return false;
  srv->sessions++;
  srv->staging_bytes += staging;
  srv->qps++;
  u.first++;
  u.second += staging;
  return true;
}

void limitsRelease(rc_server *srv, const rc_principal_id &who,
                   uint64_t staging) {
  std::lock_guard<std::mutex> g(srv->acct_mtx);
  if (srv->sessions) srv->sessions--;
  if (srv->staging_bytes >= staging)
    srv->staging_bytes -= staging;
  if (srv->qps) srv->qps--;
  auto it = srv->per_user.find(principalKey(who));
  if (it != srv->per_user.end()) {
    if (it->second.first) it->second.first--;
    if (it->second.second >= staging)
      it->second.second -= staging;
    if (it->second.first == 0 && it->second.second == 0)
      srv->per_user.erase(it);
  }
}

/* Tears the session's transport objects down and erases it. The
 * caller holds no lock and every ref must already be zero. The
 * QP/CQ go first: a QP still referencing the staging MR must not
 * outlive the memory region it posts against. When a destroy
 * fails (the verbs kept the object), the staging MR and buffer
 * stay alive and owned by the leaked object: freeing memory the
 * NIC may still touch would be a use-after-free. */
void reapSession(rc_server *srv, RcSession *s) {
  bool q_ok = true, c_ok = true;
  hipObj::RcConnV2 conn;
  conn.qp = s->core.qp;
  conn.cq = s->core.cq;
  hipObj::v2::destroyRcConnV2(conn, &q_ok, &c_ok);
  s->core.qp = conn.qp;   /* null on success, survivor on failure */
  s->core.cq = conn.cq;
  bool destroyed = q_ok && c_ok;
  /* Terminal record for every session teardown path (expiry,
   * CANCEL, and destroy); reap_pass may have missed the final
   * state, so the last outcome observed at READY time travels
   * with the log line. */
  rcLog(srv, 2, __FILE__, __LINE__,
        "rc: session reaped id=%s op=%s target=%.96s staged=%llu "
        "qp_destroyed=%d",
        s->core.id.c_str(), s->core.op.c_str(),
        s->core.target.c_str(),
        (unsigned long long)s->staging_len, (int)destroyed);
  if (destroyed) {
    /* Same policy as releaseStaging: a failed dereg leaves the
     * MR registered against the shared PD, so the buffer stays
     * alive (leaked) rather than feeding freed memory to
     * outstanding remote accesses. */
    bool freed = true;
    if (s->staging_mr) {
      if (hipObj::ibv.dereg_mr(s->staging_mr) != 0) {
        fprintf(stderr,
                "rc: staging dereg failed; leaking buffer\n");
        freed = false;
      }
      s->staging_mr = nullptr;
    }
    if (freed) {
      if (s->staging_buf) std::free(s->staging_buf);
      s->staging_buf = nullptr;
    }
    if (!freed) srv->reap_failure.store(true);
  } else {
    fprintf(stderr,
            "rc: QP/CQ destroy failed; leaking staging MR/buffer\n");
    srv->reap_failure.store(true);
  }
  /* Pair the connRef taken at QP creation, but only when the QP
   * is actually gone: a surviving QP still holds the device. */
  if (destroyed) hipObj::v2::releaseDevice(srv->device);
  limitsRelease(srv, s->principal, s->staging_len);
}

/* Runs the reap pass: sessions marked reap_pending (or in the
 * Reaping state) whose refs have all drained are destroyed here.
 * Called at the end of ABI mutations so the state table stays
 * self-cleaning without a background thread. */
void reapPass(rc_server *srv) {
  std::vector<std::unique_ptr<RcSession>> owned;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    for (auto it = srv->sessions_map.begin();
         it != srv->sessions_map.end();) {
      RcSession &s = *it->second;
      if (reaperReady(s) && s.staging_lease.nonce == 0 &&
          s.put_view.nonce == 0 && s.active_ref == 0 &&
          s.put_ref == 0) {
        owned.push_back(std::move(it->second));
        it = srv->sessions_map.erase(it);
      } else {
        ++it;
      }
    }
  }
  /* Transport teardown runs outside the map lock; the detached
   * sessions free with the vector. */
  for (auto &s : owned) reapSession(srv, s.get());
}

/* Encodes the server endpoint as the reply token. */
std::string encodeReplyToken(hipObj::DeviceHandle *dh, uint32_t qpn) {
  hipObj::RdmaToken tok{};
  tok.qpNum = qpn;
  std::memcpy(tok.gid, &dh->localGid, 16);
  tok.transport = hipObj::TRANSPORT_RC;
  tok.portNum = dh->portNum;
  return hipObj::encodeRdmaToken(tok);
}

}  // namespace

extern "C" {

void rc_server_set_log_sink(rc_server *srv, rc_log_fn fn, void *ctx) {
  if (!srv) return;
  srv->log_fn = fn;
  srv->log_ctx = ctx;
}

int rc_server_init(const rc_device_opts *opts, rc_server **out) {
  if (!opts || !out) return RC_E_ARG;
  if (!hipObj::ibv.ensureLoaded()) {
    fprintf(stderr, "rc: cannot load libibverbs (dlopen/dlsym failed)\n");
    return RC_E_INTERNAL;
  }
  std::unique_ptr<rc_server> srv(new rc_server());
  srv->opts = *opts;
  /* ibv port numbers are 1-based; treat an unset (0) port as 1 so
   * a zero-value DeviceOpts does not reach GID queries or QP
   * transitions with an invalid port_num. */
  if (srv->opts.port == 0) srv->opts.port = 1;
  srv->ready_slots.store(opts->max_ready_slots
                             ? opts->max_ready_slots
                             : 64);
  srv->stage_slots.store(opts->max_stage_slots
                             ? opts->max_stage_slots
                             : 32);

  int n = 0;
  struct ibv_device **devs = hipObj::ibv.get_device_list(&n);
  if (!devs || n == 0) {
    fprintf(stderr, "rc: no RDMA devices found (ibv_get_device_list)\n");
    return RC_E_INTERNAL;
  }
  struct ibv_device *chosen = devs[0];
  /* GID hint: pick the first device/port whose GID starts with it.
   * Query with srv->opts.port, which the normalization above has
   * already made 1-based. */
  struct ibv_context *ctx = nullptr;
  for (int i = 0; i < n && !ctx; i++) {
    struct ibv_context *c = hipObj::ibv.open_device(devs[i]);
    if (!c) continue;
    if (opts->gid_hint) {
      union ibv_gid g;
      char dotted[64];
      for (int gi = 0; gi < 8; gi++) {
        if (hipObj::ibv.query_gid(c, srv->opts.port, gi, &g) != 0) break;
        snprintf(dotted, sizeof(dotted), "%x:%x:%x:%x", g.raw[0],
                 g.raw[1], g.raw[2], g.raw[3]);
        if (strncmp(dotted, opts->gid_hint,
                    strlen(opts->gid_hint)) == 0) {
          srv->opts.gid_index = gi;
          ctx = c;
          chosen = devs[i];
          break;
        }
      }
      if (!ctx) {
        hipObj::ibv.close_device(c);
        continue;
      }
    } else {
      ctx = c;
    }
  }
  if (!ctx) {
    hipObj::ibv.free_device_list(devs);
    fprintf(stderr, "rc: no verbs device matches gid_hint %.32s\n",
            opts->gid_hint ? opts->gid_hint : "");
    return RC_E_INTERNAL;
  }
  struct ibv_pd *pd = hipObj::ibv.alloc_pd(ctx);
  hipObj::ibv.free_device_list(devs);
  if (!pd) {
    hipObj::ibv.close_device(ctx);
    fprintf(stderr, "rc: alloc_pd failed\n");
    return RC_E_INTERNAL;
  }
  srv->device = new hipObj::DeviceHandle();
  srv->device->ctx = ctx;
  srv->device->pd = pd;
  srv->device->portNum = srv->opts.port;
  srv->device->gidIndex = srv->opts.gid_index;
  hipObj::ibv.query_gid(ctx, srv->opts.port, srv->opts.gid_index,
                        &srv->device->localGid);
  /* Expiry reaper: wakes periodically, marks sessions past
   * their prepare/execute deadlines, and runs the reap pass
   * itself so an abandoned session (one whose owner never sent
   * READY, or whose data phase stalled) can never pin the
   * global or per-principal limits. reapPass still waits for
   * every borrowed handle and completion ref to drain before
   * tearing a session down. */
  srv->reaper = std::thread([s = srv.get()]() {
    while (!s->reaper_stop.load()) {
      uint64_t now = hipObj::v2::clockSource().nowMs();
      {
        std::lock_guard<std::mutex> g(s->map_mtx);
        for (auto &kv : s->sessions_map) {
          RcSession &rs = *kv.second;
          if (rs.reap_pending) continue;
          if ((rs.prep_deadline_ms &&
               now > rs.prep_deadline_ms) ||
              (rs.exec_deadline_ms && now > rs.exec_deadline_ms)) {
            rs.reap_pending = true;
          }
        }
      }
      reapPass(s);
      for (int i = 0; i < 50 && !s->reaper_stop.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  });
  *out = srv.release();
  return RC_OK;
}

void rc_server_destroy(rc_server *srv) {
  if (!srv) return;
  srv->closing.store(true);
  srv->reaper_stop.store(true);
  if (srv->reaper.joinable()) srv->reaper.join();
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    for (auto &kv : srv->sessions_map) {
      kv.second->reap_pending = true;
    }
  }
  /* Wait for borrowed handles and completion refs to drain, then
   * tear every session down through the shared reap path (QP
   * first, then staging MR/buffer, then limit release). reapPass
   * runs inside the loop so sessions whose refs drain mid-wait
   * are collected here rather than after an unbounded wait. */
  for (bool drained = false; !drained;) {
    reapPass(srv);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    std::lock_guard<std::mutex> g(srv->map_mtx);
    drained = srv->sessions_map.empty();
    for (auto &kv : srv->sessions_map) {
      RcSession &rs = *kv.second;
      if (rs.staging_lease.nonce != 0 || rs.put_view.nonce != 0 ||
          rs.active_ref != 0 || rs.put_ref != 0) {
        drained = false;
      }
    }
  }
  reapPass(srv);
  /* Close the device only after every session (and its connRef)
   * is gone AND nothing survived a failed teardown: dealloc_pd
   * fails on outstanding MRs, and the context must not close
   * under a live QP. When a reap failed, the PD/context stay
   * open for the leaked objects' lifetime (still freed with the
   * process, and logged above). */
  if (srv->device && !srv->reap_failure.load()) {
    if (srv->device->pd) hipObj::ibv.dealloc_pd(srv->device->pd);
    if (srv->device->ctx) hipObj::ibv.close_device(srv->device->ctx);
  }
  delete srv->device;
  delete srv;
}

int rc_prepare(rc_server *srv, const rc_prepare_req *req,
               rc_prepare_resp *resp) {
  if (!srv || !req || !resp) return RC_E_ARG;
  if (req->op > 1) return RC_E_ARG;
  if (req->size == 0 || req->size > kMaxTransfer) return RC_E_ARG;
  /* offset+size must stay within the transfer window without
   * wrapping; the subtraction form rejects overflow. */
  if (req->offset > kMaxTransfer - req->size) return RC_E_ARG;
  if (!limitsTake(srv, req->principal, req->size)) return RC_E_LIMIT;

  std::string target = strIn(req->target);
  if (target.size() > kMaxTarget) {
    limitsRelease(srv, req->principal, req->size);
    return RC_E_TRUNC;
  }

  auto rs_up = std::make_unique<RcSession>();
  RcSession &rs = *rs_up;
  rs.principal = req->principal;
  rs.core.accessKey.assign(reinterpret_cast<const char *>(req->principal.id), 32);
  rs.core.op = req->op == 0 ? "GET" : "PUT";
  rs.core.target = target;
  rs.core.size = req->size;
  rs.core.offset = req->offset;
  rs.core.clientPsn = req->client_psn;
  rs.core.cookie = req->cookie;
  rs.epoch = srv->epoch_counter.fetch_add(1);

  /* Decode the client token so RTR can route to the peer GID.
   * A zero token is the explicit loopback marker; a nonzero
   * token that fails decode (or names another transport) is a
   * client error, not a silent fallback. */
  std::string tokenHex = strIn(req->client_token);
  if (!tokenHex.empty()) {
    bool allZero = true;
    for (char c : tokenHex) {
      if (c != '0') { allZero = false; break; }
    }
    if (!allZero) {
      /* The wire token is either bare 88-hex or the extended
       * 88hex:addr:size form; decode the base and validate the
       * suffix shape (both parts 1..16 hex digits), matching the
       * reference parser. */
      std::string base = tokenHex;
      if (tokenHex.find(':') != std::string::npos) {
        size_t colon1 = tokenHex.find(':');
        size_t colon2 = tokenHex.find(':', colon1 + 1);
        bool suffixOk = colon2 != std::string::npos &&
                        colon2 > colon1 + 1 &&
                        tokenHex.find(':', colon2 + 1) ==
                            std::string::npos;
        if (suffixOk) {
          std::string addr = tokenHex.substr(colon1 + 1,
                                             colon2 - colon1 - 1);
          std::string sz = tokenHex.substr(colon2 + 1);
          suffixOk = addr.size() <= 16 && sz.size() <= 16 &&
                     !addr.empty() && !sz.empty();
          for (char c : addr)
            if (!isxdigit((unsigned char)c)) suffixOk = false;
          for (char c : sz)
            if (!isxdigit((unsigned char)c)) suffixOk = false;
        }
        if (!suffixOk) {
          limitsRelease(srv, req->principal, req->size);
          return RC_E_ARG;
        }
        base = tokenHex.substr(0, colon1);
      }
      hipObj::RdmaToken tok{};
      if (base.size() != 88 ||
          !hipObj::decodeRdmaTokenHex(base.c_str(), tok)) {
        limitsRelease(srv, req->principal, req->size);
        return RC_E_ARG;
      }
      if (tok.transport != hipObj::TRANSPORT_RC) {
        limitsRelease(srv, req->principal, req->size);
        return RC_E_ARG;
      }
      std::memcpy(&rs.core.peerGid, tok.gid, 16);
      rs.has_peer_gid = true;
      /* Stash the client MR endpoint when the token carries one
       * (PUT destination advertised at PREPARE time). */
      rs.core.clientMrAddr = tok.remoteAddr;
      rs.core.clientMrRkey = tok.rkey;
    }
  }

  /* QP + staging on the shared device (session-scoped). The
   * rollback helper records any survivor (a QP/CQ the verbs
   * refused to destroy) on the server: those objects still
   * reference the shared PD, so destroy must not close the
   * device under them. It also returns the device reference
   * createRcConnV2 took. */
  auto rollbackConn = [srv](hipObj::RcConnV2 &c) {
    bool q_ok = true, c_ok = true;
    hipObj::v2::destroyRcConnV2(c, &q_ok, &c_ok);
    if (!q_ok || !c_ok) srv->reap_failure.store(true);
  };
  hipObj::RcConnV2 conn;
  bool rollback_failed = false;
  if (hipObj::v2::createRcConnV2(srv->device, conn,
                                 &rollback_failed) != 0) {
    if (rollback_failed) srv->reap_failure.store(true);
    limitsRelease(srv, req->principal, req->size);
    return RC_E_INTERNAL;
  }
  if (hipObj::v2::transitionQpToInitV2(srv->device, conn) != 0) {
    rollbackConn(conn);
    limitsRelease(srv, req->principal, req->size);
    return RC_E_INTERNAL;
  }
  /* staging MR (host) */
  void *buf = std::calloc(1, req->size ? req->size : 1);
  if (!buf) {
    rollbackConn(conn);
    limitsRelease(srv, req->principal, req->size);
    return RC_E_INTERNAL;
  }
  struct ibv_mr *mr = hipObj::ibv.reg_mr_host(
      srv->device->pd, buf, req->size,
      IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
  if (!mr) {
    std::free(buf);
    rollbackConn(conn);
    limitsRelease(srv, req->principal, req->size);
    return RC_E_INTERNAL;
  }
  rs.core.qp = conn.qp;
  rs.core.cq = conn.cq;
  rs.core.serverQpn = conn.qpNum;
  rs.core.device = srv->device;
  rs.core.connRefHeld = true;
  /* Wire the staging endpoint into the session core so the data
   * phase posts against this MR; runDataPhase reads
   * core.staging/core.stagingMr, not the ABI-side fields. */
  rs.core.staging = buf;
  rs.core.stagingMr = mr;

  /* Session id: 128 random bits rendered as 32 lowercase hex
   * chars (the wire format clients validate), drawn from the
   * injectable v2 randomness source. Collision with a live id is
   * practically impossible; the map insert below still guards. */
  std::string id;
  id.reserve(32);
  for (int i = 0; i < 4; i++) {
    uint32_t v;
    if (!hipObj::v2::randomSource().next32(v)) {
      if (hipObj::ibv.dereg_mr(mr) != 0)
        srv->reap_failure.store(true); /* MR survives: leak buf */
      else
        std::free(buf);
      rollbackConn(conn);
      limitsRelease(srv, req->principal, req->size);
      return RC_E_INTERNAL;
    }
    char part[9];
    snprintf(part, sizeof(part), "%08x", v);
    id += part;
  }
  rs.prep_deadline_ms =
      srv->opts.t_prep_ms
          ? hipObj::v2::clockSource().nowMs() + srv->opts.t_prep_ms
          : 0;
  /* The session record carries its own id copy: reap logging and the
   * terminal teardown record read core.id, while the map key is the
   * only other place the id lives. */
  rs.core.id = id;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    rs.staging_buf = reinterpret_cast<uint8_t *>(buf);
    rs.staging_len = req->size;
    rs.staging_mr = mr;
    auto [it, ok] = srv->sessions_map.emplace(id, std::move(rs_up));
    if (!ok) {
      if (hipObj::ibv.dereg_mr(mr) != 0)
        srv->reap_failure.store(true); /* MR survives: leak buf */
      else
        std::free(buf);
      rollbackConn(conn);
      limitsRelease(srv, req->principal, req->size);
      return RC_E_INTERNAL;
    }
  }

  memset(resp, 0, sizeof(*resp));
  snprintf(resp->session_id, sizeof(resp->session_id), "%s", id.c_str());
  resp->session_len = (uint32_t)id.size();
  resp->server_qpn = conn.qpNum;
  resp->server_psn = rs.core.serverPsn = conn.qpNum & 0xffffff;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    RcSession *s = findSession(srv, id);
    if (s) {
      s->core.serverPsn = resp->server_psn;
      std::string hex = encodeReplyToken(srv->device, conn.qpNum);
      memcpy(resp->reply_token, hex.data(),
             hex.size() < 88 ? hex.size() : 88);
      resp->reply_len = (uint32_t)(hex.size() < 88 ? hex.size() : 88);
      resp->staging_addr = (uint64_t)(uintptr_t)buf;
      resp->staging_rkey = mr->rkey;
    }
  }
  return RC_OK;
}

int rc_finish_prepare(rc_server *srv, rc_str_in session_id,
                      int prepare_committed) {
  if (!srv) return RC_E_ARG;
  std::string id = strIn(session_id);
  int rc;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    RcSession *s = findSession(srv, id);
    if (!s) return RC_E_NO_SESSION;
    if (s->core.state != SessState::Prepared) return RC_E_STALE;
    if (!prepare_committed) {
      s->reap_pending = true;
      rc = RC_OK;
    } else {
      if (s->core.op == "GET" && !s->stage_done) return RC_E_STATE;
      s->core.published = true;
      /* Published sessions drop the *prepare* deadline only at
       * READY claim time; until then the execute window has not
       * opened yet, so a client that never sends READY must
       * still expire through prep_deadline_ms. */
      rc = RC_OK;
    }
  }
  reapPass(srv);
  return rc;
}

int rc_borrow_staging(rc_server *srv, rc_str_in session_id,
                      rc_staging_lease *lease) {
  if (!srv || !lease) return RC_E_ARG;
  std::string id = strIn(session_id);
  std::lock_guard<std::mutex> g(srv->map_mtx);
  RcSession *s = findSession(srv, id);
  if (!s) return RC_E_NO_SESSION;
  if (s->core.state != SessState::Prepared) return RC_E_STALE;
  if (handleValid(s->staging_lease)) return RC_E_DOUBLE;
  lease->buf = s->staging_buf;
  lease->capacity = s->staging_len;
  lease->handle = {s->epoch, s->next_nonce.fetch_add(1)};
  s->staging_lease = lease->handle;
  return RC_OK;
}

int rc_finish_staging(rc_server *srv, rc_staging_lease lease, int ok,
                      size_t written, rc_str_in etag,
                      rc_str_in version_id) {
  if (!srv) return RC_E_ARG;
  if (!handleValid(lease.handle)) return RC_E_STALE;
  int rc = RC_E_STALE;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    for (auto &kv : srv->sessions_map) {
      RcSession &s = *kv.second;
      /* Match the full handle (epoch and nonce): nonces restart at
       * one per session, so the epoch is what keeps a handle from
       * consuming another session's lease. */
      if (!handleValid(s.staging_lease) ||
          s.staging_lease.nonce != lease.handle.nonce ||
          s.staging_lease.session_epoch !=
              lease.handle.session_epoch)
        continue;
      /* consume exactly once */
      clearHandle(s.staging_lease);
      rc = RC_OK;
      if (!ok || written != s.core.size) {
        s.reap_pending = true;
        rc = ok ? RC_E_SHORT : RC_OK;
        break;
      }
      s.etag = strIn(etag);
      s.version_id = strIn(version_id);
      if (s.etag.size() > kMaxEtag ||
          s.version_id.size() > kMaxVersion) {
        s.reap_pending = true;
        rc = RC_E_TRUNC;
        break;
      }
      s.stage_done = true;
      break;
    }
  }
  reapPass(srv);
  return rc;
}

int rc_session_info(rc_server *srv, rc_str_in session_id,
                    rc_principal_id who, rc_session_info_resp *out) {
  if (!srv || !out) return RC_E_ARG;
  std::string id = strIn(session_id);
  std::lock_guard<std::mutex> g(srv->map_mtx);
  RcSession *s = findSession(srv, id);
  if (!s) return RC_E_NO_SESSION;
  if (!principalEq(s->principal, who)) return RC_E_SESSION;
  out->op = s->core.op == "GET" ? 0 : 1;
  size_t n = s->core.target.size();
  if (n > kMaxTarget) return RC_E_TRUNC;
  memcpy(out->target, s->core.target.data(), n);
  out->target[n] = 0;
  out->target_len = (uint32_t)n;
  return RC_OK;
}

int rc_ready_transfer(rc_server *srv, const rc_ready_req *req,
                      rc_ready_resp *resp) {
  if (!srv || !req || !resp) return RC_E_ARG;
  if (srv->closing.load()) return RC_E_INTERNAL;
  std::string id = strIn(req->session_id);

  uint32_t slots = srv->ready_slots.load();
  do {
    if (slots == 0) return RC_E_LIMIT;
  } while (!srv->ready_slots.compare_exchange_weak(slots, slots - 1));
  struct ReadyGuard {
    rc_server *srv;
    ~ReadyGuard() { srv->ready_slots.fetch_add(1); }
  } ready_guard{srv};

  std::unique_lock<std::mutex> g(srv->map_mtx);
  RcSession *s = findSession(srv, id);
  if (!s) return RC_E_NO_SESSION;
  if (!principalEq(s->principal, req->principal)) return RC_E_SESSION;
  if (s->core.state == SessState::Transferring ||
      s->core.state == SessState::Completing)
    return RC_E_STATE; /* duplicate READY */
  if (s->core.state != SessState::Prepared) return RC_E_STALE;
  if (!s->core.published) return RC_E_STATE;
  if (s->reap_pending) return RC_E_STALE; /* cancelled/expired */
  if (req->cookie != s->core.cookie) return RC_E_SESSION;

  /* Record the READY wire parameters on the session and claim the
   * transfer under the lock: state and the completion ref move
   * before the QP transitions so a concurrent READY cannot pass
   * the same checks and race the same QP. */
  s->core.clientQpn = req->client_qpn;
  if (req->client_mr_addr) s->core.clientMrAddr = req->client_mr_addr;
  if (req->client_mr_rkey) s->core.clientMrRkey = req->client_mr_rkey;
  s->core.ioActive = 1;
  s->core.state = SessState::Transferring;
  s->active_ref = 1; /* completion ref: held until finalizer */
  s->prep_deadline_ms = 0;
  if (srv->opts.t_exec_ms)
    s->exec_deadline_ms =
        hipObj::v2::clockSource().nowMs() + srv->opts.t_exec_ms;

  /* Pair the QP: RTR against the peer endpoint, then RTS. The
   * peer GID comes from the PREPARE token when the client sent
   * one, otherwise our own GID (same-HCA loopback). */
  union ibv_gid destGid = {};
  if (s->has_peer_gid) {
    destGid = s->core.peerGid;
  } else {
    destGid = srv->device->localGid;
  }
  hipObj::RcConnV2 conn;
  conn.qp = s->core.qp;
  conn.cq = s->core.cq;
  conn.qpNum = s->core.serverQpn;
  g.unlock();
  if (hipObj::v2::transitionQpToRtrV2(srv->device, conn,
                                      req->client_qpn,
                                      /*destLid*/ 0, destGid,
                                      s->core.clientPsn) != 0) {
    g.lock();
    s->reap_pending = true;
    s->active_ref = 0; /* roll the completion ref back: no data
                        * phase will run for this session */
    return RC_E_WIRE;
  }
  if (hipObj::v2::transitionQpToRtsV2(conn, srv->device,
                                      s->core.serverPsn) != 0) {
    g.lock();
    s->reap_pending = true;
    s->active_ref = 0;
    return RC_E_WIRE;
  }
  g.lock();

  /* Data phase on a local snapshot, outside the map lock. The
   * io reference taken above keeps the objects alive. */
  hipObj::v2::DataPhaseStats stats{};
  uint64_t deadline =
      hipObj::v2::clockSource().nowMs() + srv->opts.t_exec_ms;
  V2Session snapshot;
  {
    /* Copy only the fields runDataPhase reads; pointers move with
     * the session while refs are held, so pass by reference under
     * a second lock scope instead of copying transport objects. */
  }
  RcSession *live = findSession(srv, id);
  if (!live) return RC_E_NO_SESSION;
  g.unlock();
  hipObj::v2::DataPhaseResult r =
      hipObj::v2::runDataPhase(live->core, deadline, stats);
  g.lock();
  RcSession *after = findSession(srv, id);
  if (!after) return RC_E_NO_SESSION;

  /* Keep the wire-level reason (poll status vs post failure vs
   * timeout) alongside the outcome the response carries, so a
   * VerifyFail is diagnosable without re-running the transfer.
   * Logged with the lock dropped: the sink must not block under
   * map_mtx. */
  int rlog = (r == hipObj::v2::DataPhaseResult::Ok)
                 ? 2
                 : (r == hipObj::v2::DataPhaseResult::Busy ? 2 : 0);
  rcLog(srv, rlog, __FILE__, __LINE__,
        "rc: ready data phase session=%s op=%s outcome=%d bytes=%llu",
        id.c_str(), after->core.op.c_str(), (int)r,
        (unsigned long long)stats.bytes);

  switch (r) {
    case hipObj::v2::DataPhaseResult::Ok:
      after->last_outcome = RC_READY_OK;
      after->core.state = SessState::Completing;
      break;
    case hipObj::v2::DataPhaseResult::Busy:
      after->last_outcome = RC_READY_BUSY;
      /* Peer busy: roll the transfer claim back so the client can
       * retry READY against the same session. Keep the completion
       * ref held while the QP is re-armed (RESET then INIT: the
       * verbs state table has no RTS->INIT edge) outside the map
       * lock -- modify_qp can stall on slow providers and must
       * not freeze every other session operation. The ref keeps
       * the reaper away from the QP mid-transition; it is dropped
       * after a successful re-arm, and the session is torn down
       * otherwise. A bounded prepare window is restored either
       * way so resources cannot be pinned forever. */
      after->core.ioActive = 0;
      after->exec_deadline_ms = 0;
      after->prep_deadline_ms =
          srv->opts.t_prep_ms
              ? hipObj::v2::clockSource().nowMs() + srv->opts.t_prep_ms
              : 0;
      {
        hipObj::RcConnV2 reset;
        reset.qp = after->core.qp;
        reset.cq = after->core.cq;
        g.unlock();
        bool rearmed =
            hipObj::v2::rearmQpToInitV2(srv->device, reset) == 0;
        g.lock();
        after = findSession(srv, id);
        if (!after) return RC_E_NO_SESSION;
        /* CANCEL or expiry may have marked the session while the
         * lock was dropped for the QP reset: honor it instead of
         * reviving a torn-down session. */
        if (after->reap_pending) rearmed = false;
        if (rearmed) {
          after->core.state = SessState::Prepared;
          if (after->active_ref > 0) after->active_ref--;
        } else {
          /* Cannot re-arm the QP (or the session died mid-reset):
           * not retryable. */
          after->reap_pending = true;
          if (after->active_ref > 0) after->active_ref--;
          return RC_E_WIRE;
        }
      }
      break;
    case hipObj::v2::DataPhaseResult::Timeout:
      after->last_outcome = RC_READY_TIMEOUT;
      after->reap_pending = true;
      after->active_ref = 0;
      return RC_E_WIRE;
    case hipObj::v2::DataPhaseResult::VerifyFail:
    case hipObj::v2::DataPhaseResult::WireFail:
      after->last_outcome = RC_READY_WIRE_FAIL;
      after->reap_pending = true;
      after->active_ref = 0;
      return RC_E_WIRE;
  }

  memset(resp, 0, sizeof(*resp));
  resp->bytes_transferred = stats.bytes;
  resp->cookie_echo = stats.cookie;
  resp->outcome = after->last_outcome;
  size_t en = after->etag.size();
  size_t vn = after->version_id.size();
  if (en > kMaxEtag) en = kMaxEtag;
  if (vn > kMaxVersion) vn = kMaxVersion;
  memcpy(resp->etag, after->etag.data(), en);
  resp->etag_len = (uint32_t)en;
  memcpy(resp->version_id, after->version_id.data(), vn);
  resp->version_len = (uint32_t)vn;
  return RC_OK;
}

int rc_get_put_data(rc_server *srv, rc_str_in session_id,
                    rc_put_view *view) {
  if (!srv || !view) return RC_E_ARG;
  std::string id = strIn(session_id);
  std::lock_guard<std::mutex> g(srv->map_mtx);
  RcSession *s = findSession(srv, id);
  if (!s) return RC_E_NO_SESSION;
  if (s->core.state != SessState::Completing) return RC_E_STATE;
  if (s->core.op != "PUT") return RC_E_STATE;
  if (handleValid(s->put_view)) return RC_E_DOUBLE;
  view->buf = s->staging_buf;
  view->len = s->staging_len;
  view->handle = {s->epoch, s->next_nonce.fetch_add(1)};
  s->put_view = view->handle;
  /* Hand the completion ref to the put view atomically (in the
   * same lock): aR-- and pR++ move together so the reaper never
   * sees a window with no reference at all. */
  if (s->active_ref > 0) s->active_ref--;
  s->put_ref++;
  return RC_OK;
}

int rc_finish_put(rc_server *srv, rc_put_view view, int committed,
                  rc_str_in etag, rc_str_in version_id) {
  if (!srv) return RC_E_ARG;
  if (!handleValid(view.handle)) return RC_E_STALE;
  int rc = RC_E_STALE;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    for (auto &kv : srv->sessions_map) {
      RcSession &s = *kv.second;
      /* Match the full handle (epoch and nonce): nonces restart at
       * one per session, so the epoch is what keeps a view from
       * consuming another session's put ref. */
      if (!handleValid(s.put_view) ||
          s.put_view.nonce != view.handle.nonce ||
          s.put_view.session_epoch != view.handle.session_epoch)
        continue;
      clearHandle(s.put_view);
      if (s.put_ref > 0) s.put_ref--;
      rc = RC_OK;
      if (committed) {
        s.etag = strIn(etag);
        s.version_id = strIn(version_id);
        if (s.etag.size() > kMaxEtag ||
            s.version_id.size() > kMaxVersion) {
          rc = RC_E_TRUNC;
          s.reap_pending = true;
          break;
        }
      }
      s.reap_pending = true;
      break;
    }
  }
  reapPass(srv);
  return rc;
}

int rc_finish_final(rc_server *srv, rc_str_in session_id) {
  if (!srv) return RC_E_ARG;
  std::string id = strIn(session_id);
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    RcSession *s = findSession(srv, id);
    if (!s) return RC_E_NO_SESSION;
    if (s->core.state == SessState::Reaping) return RC_E_STALE;
    if (s->active_ref > 0) s->active_ref--;
    s->reap_pending = true;
  }
  reapPass(srv);
  return RC_OK;
}

int rc_cancel(rc_server *srv, rc_str_in session_id,
              rc_principal_id who) {
  if (!srv) return RC_E_ARG;
  std::string id = strIn(session_id);
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    RcSession *s = findSession(srv, id);
    if (!s) return RC_E_NO_SESSION;
    if (!principalEq(s->principal, who)) return RC_E_SESSION;
    s->reap_pending = true;
  }
  reapPass(srv);
  return RC_OK;
}

int rc_try_acquire_ready(rc_server *srv) {
  if (!srv) return RC_E_ARG;
  uint32_t slots = srv->ready_slots.load();
  do {
    if (slots == 0) return RC_E_LIMIT;
  } while (!srv->ready_slots.compare_exchange_weak(slots, slots - 1));
  return RC_OK;
}

void rc_release_ready(rc_server *srv) {
  if (srv) srv->ready_slots.fetch_add(1);
}

int rc_try_acquire_stage(rc_server *srv) {
  if (!srv) return RC_E_ARG;
  uint32_t slots = srv->stage_slots.load();
  do {
    if (slots == 0) return RC_E_LIMIT;
  } while (!srv->stage_slots.compare_exchange_weak(slots, slots - 1));
  return RC_OK;
}

void rc_release_stage(rc_server *srv) {
  if (srv) srv->stage_slots.fetch_add(1);
}

void rc_cancel_all(rc_server *srv) {
  if (!srv) return;
  {
    std::lock_guard<std::mutex> g(srv->map_mtx);
    for (auto &kv : srv->sessions_map)
      kv.second->reap_pending = true;
  }
  reapPass(srv);
}

}  /* extern "C" */
