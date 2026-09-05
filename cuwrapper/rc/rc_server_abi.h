/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * Copyright (c) Gluesys Inc. and Jihyeon Gim. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* C ABI over the ported hipObject RC session core. The gateway
 * (Go) owns routing, authentication, and the object backend; this
 * server owns sessions, QP/CQ/MR lifetimes, the data phase, and
 * the reaper. See plans/2026-08-29-rc-dataplane-design-v0.13.md
 * for the state table and lease contracts this implements.
 */

#ifndef RC_SERVER_ABI_H
#define RC_SERVER_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. */
enum {
  RC_OK = 0,
  RC_E_ARG = 1,        /* invalid argument */
  RC_E_STATE = 2,      /* wrong-state call; session preserved */
  RC_E_SESSION = 3,    /* owner/cookie mismatch; session preserved */
  RC_E_STALE = 4,      /* invalid/duplicate handle or gone session */
  RC_E_NO_SESSION = 5, /* session id not found */
  RC_E_DOUBLE = 6,     /* duplicate borrow/view issue */
  RC_E_WIRE = 7,       /* verbs transfer failure */
  RC_E_SHORT = 8,      /* staged bytes != requested */
  RC_E_TRUNC = 9,      /* string too long for output buffer */
  RC_E_LIMIT = 10,     /* session/resource limit reached */
  RC_E_INTERNAL = 11
};

typedef struct { const char *ptr; uint32_t len; } rc_str_in;

/* Diagnostic log sink. Called from RC server threads (request
 * goroutines via cgo and the expiry reaper) without any server
 * lock held. `msg` and `file` are only valid for the duration of
 * the call; the sink must copy them if it needs them longer.
 * `level` is 0 (error) or 2 (debug). Passing a null sink (or
 * installing it after init) keeps stderr-only error reporting. */
typedef void (*rc_log_fn)(void *ctx, int level, const char *msg,
                          const char *file, int line);

typedef struct rc_server rc_server;

void rc_server_set_log_sink(rc_server *srv, rc_log_fn fn, void *ctx);

/* Device selection: matching GID prefix when gid_hint is set,
 * otherwise the first verbs device. */
typedef struct {
  const char *gid_hint; /* nullable; dotted GID prefix */
  uint8_t port;
  int gid_index;
  uint32_t max_sessions;
  uint32_t max_user_sessions;
  uint64_t max_staging_bytes;
  uint64_t max_user_staging_bytes;
  uint32_t max_qps;
  uint32_t max_user_qps;
  uint64_t t_prep_ms;
  uint64_t t_exec_ms;
  uint32_t max_ready_slots; /* 0 = default 64 */
  uint32_t max_stage_slots; /* 0 = default 32 */
} rc_device_opts;

typedef struct {
  uint8_t id[32]; /* SHA-256 of the canonical principal string */
} rc_principal_id;

typedef struct {
  uint64_t session_epoch;
  uint64_t nonce;
} rc_handle;

typedef struct {
  rc_principal_id principal;
  uint8_t op; /* 0 = GET, 1 = PUT */
  rc_str_in target; /* canonical object target */
  uint64_t offset;
  uint64_t size;
  uint32_t client_psn;
  uint32_t cookie;
  rc_str_in client_token; /* 88-hex, optional (all-zero = loopback) */
} rc_prepare_req;

typedef struct {
  char session_id[33];
  uint32_t session_len;
  uint32_t server_qpn;
  uint32_t server_psn;
  uint64_t staging_addr;
  uint32_t staging_rkey;
  char reply_token[88];
  uint32_t reply_len;
} rc_prepare_resp;

typedef struct {
  uint8_t *buf;
  size_t capacity;
  rc_handle handle;
} rc_staging_lease;

typedef struct {
  rc_handle handle;
  const uint8_t *buf;
  size_t len;
} rc_put_view;

typedef struct {
  rc_principal_id principal;
  rc_str_in session_id;
  uint32_t cookie;
  uint32_t client_qpn;
  uint64_t client_mr_addr;
  uint32_t client_mr_rkey;
} rc_ready_req;

typedef struct {
  uint64_t bytes_transferred;
  uint32_t cookie_echo;
  /* Outcome of this READY, from the RC_READY_* enum below.
   * Returned atomically with the call so a concurrent READY
   * cannot rewrite it between the transfer and the read. */
  int32_t outcome;
  char etag[128];
  uint32_t etag_len;
  char version_id[128];
  uint32_t version_len;
} rc_ready_resp;

/* Transfer outcome for a completed READY (mirrors the ported
 * DataPhaseResult; Busy maps to a client-retryable 409). */
enum {
  RC_READY_OK = 0,
  RC_READY_BUSY = 1,
  RC_READY_TIMEOUT = 2,
  RC_READY_VERIFY_FAIL = 3,
  RC_READY_WIRE_FAIL = 4,
};

typedef struct {
  char target[2048];
  uint32_t target_len;
  uint8_t op;
} rc_session_info_resp;

/* Lifecycle. destroy waits for active calls and the reaper. */
int rc_server_init(const rc_device_opts *opts, rc_server **out);
void rc_server_destroy(rc_server *srv);

/* Session API — see the state table in the design doc. */
int rc_prepare(rc_server *srv, const rc_prepare_req *req,
               rc_prepare_resp *resp);
int rc_finish_prepare(rc_server *srv, rc_str_in session_id,
                      int prepare_committed);
int rc_borrow_staging(rc_server *srv, rc_str_in session_id,
                      rc_staging_lease *lease);
int rc_finish_staging(rc_server *srv, rc_staging_lease lease, int ok,
                      size_t written, rc_str_in etag,
                      rc_str_in version_id);
int rc_session_info(rc_server *srv, rc_str_in session_id,
                    rc_principal_id who, rc_session_info_resp *out);
int rc_ready_transfer(rc_server *srv, const rc_ready_req *req,
                      rc_ready_resp *resp);
int rc_get_put_data(rc_server *srv, rc_str_in session_id,
                    rc_put_view *view);
int rc_finish_put(rc_server *srv, rc_put_view view, int committed,
                  rc_str_in etag, rc_str_in version_id);
int rc_finish_final(rc_server *srv, rc_str_in session_id);
int rc_cancel(rc_server *srv, rc_str_in session_id,
              rc_principal_id who);

/* Concurrency + shutdown. Ready/stage slots fail with RC_E_LIMIT
 * when exhausted. cancel_all marks every session for reaping. */
int rc_try_acquire_ready(rc_server *srv);
void rc_release_ready(rc_server *srv);
int rc_try_acquire_stage(rc_server *srv);
void rc_release_stage(rc_server *srv);
void rc_cancel_all(rc_server *srv);

#ifdef __cplusplus
}
#endif

#endif /* RC_SERVER_ABI_H */
