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

// C wrapper for the cuObjServer C++ class.
// Provides a C-linkage interface suitable for CGO consumption.

#ifndef CUOBJSERVER_WRAPPER_H
#define CUOBJSERVER_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles
typedef struct cuobj_server cuobj_server_t;
typedef struct rdma_buffer cuobj_rdma_buffer_t;

// Error codes matching cuObjErr_t
#define CUOBJ_OK   0
#define CUOBJ_FAIL 1

// cuobj_server lifecycle
cuobj_server_t* cuobj_server_create(const char *ip, unsigned short port, unsigned proto);
void            cuobj_server_destroy(cuobj_server_t *srv);

// RDMA session
int  cuobj_server_start_session(cuobj_server_t *srv);
void cuobj_server_close_session(cuobj_server_t *srv);
int  cuobj_server_is_connected(cuobj_server_t *srv);

// Host buffer allocation
void* cuobj_server_alloc_host_buffer(cuobj_server_t *srv, size_t size);
void  cuobj_server_free_host_buffer(void *ptr);

// Buffer registration
cuobj_rdma_buffer_t* cuobj_server_register_buffer(cuobj_server_t *srv, void *ptr, size_t size);
void                 cuobj_server_deregister_buffer(cuobj_server_t *srv, cuobj_rdma_buffer_t *buf);

// Channel management
uint16_t cuobj_server_allocate_channel(cuobj_server_t *srv);
void     cuobj_server_free_channel(cuobj_server_t *srv, uint16_t channel_id);

// Data transfer (synchronous, no poll_delay override)
//
// handleGetObject: RDMA WRITE server→client (serves a GET request)
//   Returns bytes transferred or -1 on error.
ssize_t cuobj_server_handle_get(cuobj_server_t *srv,
                                const char *key,
                                cuobj_rdma_buffer_t *local_buf,
                                uint64_t remote_buf_start,
                                size_t size,
                                const char *rdma_descr,
                                uint16_t channel);

// handlePutObject: RDMA READ client→server (serves a PUT request)
//   Returns bytes transferred or -1 on error.
ssize_t cuobj_server_handle_put(cuobj_server_t *srv,
                                const char *key,
                                cuobj_rdma_buffer_t *local_buf,
                                uint64_t remote_buf_start,
                                size_t size,
                                const char *rdma_descr,
                                uint16_t channel);

// Telemetry (optional)
void cuobj_server_setup_telemetry(int use_otel);
void cuobj_server_shutdown_telemetry(void);
void cuobj_server_set_telem_flags(unsigned flags);

// RDMA tunable parameters — flat C struct for CGO compatibility.
// Field names and defaults match cuObjRDMATunableParam in cuobjrdma.h.
typedef struct {
    int           num_dcis;             // default 128
    unsigned      cq_depth;             // default 640
    unsigned long dc_key;               // default 0xffeeddcc
    int           service_level;        // default 0
    uint8_t       timeout;              // default 16
    unsigned      hop_limit;            // default 4
    int           pkey_index;           // default 0
    uint32_t      delay_interval;       // default 5000 ns
    int           delay_mode;           // 0=none 1=batch 2=entry 3=adaptive; default 1
    uint8_t       retry_cnt;            // default 7
    int           qp_reset_on_failure;  // bool as int; default 1 (true)
    unsigned      traffic_class;        // default 96
    int           max_rd_atomic;        // default 0 (auto)
} cuobj_rdma_tunables_t;

// Apply RDMA tuning parameters to an existing connection object.
// Takes effect on the next reconnection if called after session start.
// Returns 0 on success, -1 on error.
int cuobj_server_init_rdma_config(cuobj_server_t *srv, const cuobj_rdma_tunables_t *t);

// Create a cuObjServer with tunable parameters applied before the session
// starts. This is the preferred constructor when non-default tunables are
// needed, since the library starts the RDMA session inside the constructor.
cuobj_server_t* cuobj_server_create_with_config(const char *ip, unsigned short port, unsigned proto, const cuobj_rdma_tunables_t *t);

#ifdef __cplusplus
}
#endif

#endif // CUOBJSERVER_WRAPPER_H
