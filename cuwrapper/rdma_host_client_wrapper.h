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

// Host-memory RDMA client wrapper.
//
// This wrapper implements the *client* side of the cuObject RDMA DC (Dynamically
// Connected) protocol using libibverbs + mlx5 direct-verbs, WITHOUT any CUDA/GPU
// dependency. It is intended for RDMA-capable hosts that have no GPU and cannot
// use the official NVIDIA libcuobjclient library (which requires CUDA).
//
// Role in the protocol: the cuObjServer (gateway) is the RDMA *initiator*
// (it owns the DCI QPs and issues RDMA READ for PUT / RDMA WRITE for GET).
// The client is the passive *target*: it exposes a DC Target (DCT) QP plus a
// registered memory region, and encodes their coordinates into an RDMA
// descriptor token that travels to the server in an S3 request header. During
// the actual data transfer the client CPU is not involved — the NIC services
// the server's reads/writes against the registered region via the DCT.
//
// The C ABI below is CGO-friendly (opaque handle, C linkage, no C++ types).

#ifndef RDMA_HOST_CLIENT_WRAPPER_H
#define RDMA_HOST_CLIENT_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rdma_host_client rdma_host_client_t;

// rdma_host_client_create opens the given RDMA device and builds the passive
// DC target endpoint (PD, CQ, SRQ, DCT QP -> RTR) plus caches the port LID and
// the GID at gid_index. dc_key must match the server's DCKey tunable
// (default 0xffeeddcc). Pass dev_name = NULL to select the first device.
// Returns NULL on failure.
rdma_host_client_t* rdma_host_client_create(const char *dev_name,
                                            uint8_t port_num,
                                            int gid_index,
                                            uint64_t dc_key);

// rdma_host_client_destroy tears down the endpoint and frees any registered
// buffer. Safe to call with NULL.
void rdma_host_client_destroy(rdma_host_client_t *c);

// rdma_host_client_alloc allocates a page-aligned host buffer of size bytes and
// registers it for remote read+write. Any previously allocated buffer is freed
// first. Returns the buffer pointer, or NULL on failure.
void* rdma_host_client_alloc(rdma_host_client_t *c, size_t size);

// rdma_host_client_free deregisters and frees the current buffer, if any.
void rdma_host_client_free(rdma_host_client_t *c);

// rdma_host_client_token returns the RDMA descriptor token for the currently
// registered buffer, or NULL if no buffer is registered. The returned string is
// owned by the client and remains valid until the next alloc/free/destroy.
// See build_token() in rdma_host_client_wrapper.cpp for the wire-format field table.
const char* rdma_host_client_token(rdma_host_client_t *c);

// rdma_host_client_last_error returns a human-readable description of the most
// recent failure, or NULL if none.
const char* rdma_host_client_last_error(rdma_host_client_t *c);

#ifdef __cplusplus
}
#endif

#endif // RDMA_HOST_CLIENT_WRAPPER_H
