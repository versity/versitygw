// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

/* rdial: a minimal RDMA CM client for the hipobj-rc-v3 gateway path.
 *
 * The gateway dials the RC-CM listener a hipobj-rc-v3 client
 * advertises in its token, then moves one transfer over the
 * negotiated connection: an RDMA READ from the client's memory
 * region for a PUT, or an RDMA WRITE to it for a GET.
 *
 * All staging memory is owned by C for the whole call: the caller
 * never hands a Go allocation in, so nothing C touches can move.
 * Every wait is bounded by an absolute millisecond deadline passed
 * by the caller, so a dead peer cannot pin a gateway handler and
 * repeated EINTR cannot extend the wait.
 */
#ifndef HIPV3_RDIAL_H
#define HIPV3_RDIAL_H

#include <stddef.h>
#include <stdint.h>

struct rdial_conn;

/* Connect to ip:port (IPv4 or IPv6 textual form). Returns 0 on
 * success and stores the connection in *out; returns a negative
 * errno on failure. timeout_ms bounds the whole dial. */
int rdial_dial(const char *ip, uint16_t port, int timeout_ms,
	       struct rdial_conn **out);

/* Connect to ip:port over TCP, exchange QP parameters with the
 * peer's listener (line-based, no rdma_cm), and program the RC QP
 * directly. For fabrics without kernel CM support (for example the
 * rocm-ernic emulation) this is the only way to establish the
 * connection. Returns 0 on success and stores the connection in
 * *out; returns a negative errno on failure. timeout_ms bounds TCP
 * connect, the exchange, and the readiness wait. The connection's
 * transfers use the same read/write entry points as the CM dial. */
int rdial_dial_oob(const char *ip, uint16_t port, int timeout_ms,
		   struct rdial_conn **out);

/* RDMA READ len bytes from the client region (rkey, remote_addr)
 * into a C-owned staging buffer returned via staging_out; the caller
 * releases it with rdial_free. Returns len on success, negative
 * errno on failure. */
long rdial_read(struct rdial_conn *c, uint32_t rkey, uint64_t remote_addr,
		uint64_t len, int timeout_ms, void **staging_out);

/* RDMA WRITE len bytes from the C-owned staging buffer into the
 * client region (rkey, remote_addr). Returns len on success,
 * negative errno on failure. */
long rdial_write(struct rdial_conn *c, const void *staging, uint32_t rkey,
		 uint64_t remote_addr, uint64_t len, int timeout_ms);

/* Allocate staging memory suitable for rdial_write. rdial_write
 * registers it with the connection's protection domain itself. */
void *rdial_alloc(uint64_t len);

/* Free a staging buffer from rdial_alloc or rdial_read. NULL is
 * ignored. */
void rdial_free(void *staging);

/* Disconnect and free every resource of c, waiting up to timeout_ms
 * for the peer's disconnect event first. Safe to call on a
 * connection in any state. */
void rdial_close(struct rdial_conn *c, int timeout_ms);

#endif /* HIPV3_RDIAL_H */
