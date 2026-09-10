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

// C wrapper implementation for cuObjServer.
// Bridges extern "C" functions to the C++ cuObjServer class.

#include "cuobjserver_wrapper.h"
#include "cuobjserver.h"

#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include <iostream>
#include <string>

// ---------------------------------------------------------------------------
// Session management
//
// libcuobjserver does not expose an explicit RDMA session start/close entry
// point. cuObjServer's constructor brings the session up and its destructor
// tears it down.
//
// Earlier revisions of this wrapper resolved startRDMASession/closeRDMASession
// at runtime via dlsym, trying both the RDMAConnection and cuObjServer mangled
// names. Neither symbol was ever exported, so those lookups always failed and
// the fallback paths below are what has always actually run. cuObjServer 2.0.0
// deletes the RDMAConnection base class outright, so the lookup can no longer
// succeed even in principle — it is gone rather than left as dead code.
// ---------------------------------------------------------------------------

// Verbose wrapper logs are enabled when cuobj_server_set_telem_flags includes
// info/debug bits (configured by cuserver -debug).
static std::atomic<bool> g_verbose_logs{false};

extern "C" {

cuobj_server_t* cuobj_server_create(const char *ip, unsigned short port, unsigned proto) {
    try {
        auto *srv = new cuObjServer(ip, port, proto);
        return reinterpret_cast<cuobj_server_t*>(srv);
    } catch (...) {
        return nullptr;
    }
}

// Build a cuObjRDMATunable from the flat C struct for
// cuobj_server_create_with_config.
static cuObjRDMATunable tunables_from_c(const cuobj_rdma_tunables_t *t) {
    cuObjRDMATunable config;
    config.setNumDcis(t->num_dcis);
    config.setCqDepth(t->cq_depth);
    config.setDcKey(t->dc_key);
    config.setServiceLevel(t->service_level);
    config.setTimeout(t->timeout);
    config.setHopLimit(t->hop_limit);
    config.setPkeyIndex(t->pkey_index);
    config.setDelayInterval(t->delay_interval);
    config.setDelayMode(static_cast<cuObjDelayMode_t>(t->delay_mode));
    config.setRetryCount(t->retry_cnt);
    config.setQPResetOnFailure(t->qp_reset_on_failure != 0);
    config.setTrafficClass(t->traffic_class);
    config.setMaxRdAtomic(t->max_rd_atomic);
    return config;
}

cuobj_server_t* cuobj_server_create_with_config(const char *ip, unsigned short port,
                                                unsigned proto,
                                                const cuobj_rdma_tunables_t *t) {
    try {
        cuObjRDMATunable config = tunables_from_c(t);
        auto *srv = new cuObjServer(ip, port, proto, config);
        return reinterpret_cast<cuobj_server_t*>(srv);
    } catch (...) {
        return nullptr;
    }
}

void cuobj_server_destroy(cuobj_server_t *srv) {
    delete reinterpret_cast<cuObjServer*>(srv);
}

int cuobj_server_start_session(cuobj_server_t *srv) {
    // The cuObjServer constructor starts the session. Verify it actually came
    // up instead of unconditionally reporting success.
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    return s->isConnected() ? 0 : -1;
}

void cuobj_server_close_session(cuobj_server_t *srv) {
    // Session teardown is owned by ~cuObjServer(); there is no separate close
    // entry point. cuobj_server_destroy() is what actually closes the session.
    (void)srv;
}

int cuobj_server_is_connected(cuobj_server_t *srv) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    return s->isConnected() ? 1 : 0;
}

void* cuobj_server_alloc_host_buffer(cuobj_server_t *srv, size_t size) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    return s->allocHostBuffer(size);
}

void cuobj_server_free_host_buffer(void *ptr) {
    free(ptr);
}

cuobj_rdma_buffer_t* cuobj_server_register_buffer(cuobj_server_t *srv, void *ptr, size_t size) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    return s->registerBuffer(ptr, size);
}

void cuobj_server_deregister_buffer(cuobj_server_t *srv, cuobj_rdma_buffer_t *buf) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    s->deRegisterBuffer(buf);
}

uint16_t cuobj_server_allocate_channel(cuobj_server_t *srv) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    return s->allocateChannelId();
}

void cuobj_server_free_channel(cuobj_server_t *srv, uint16_t channel_id) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    s->freeChannelId(channel_id);
}

ssize_t cuobj_server_handle_get(cuobj_server_t *srv,
                                const char *key,
                                cuobj_rdma_buffer_t *local_buf,
                                uint64_t remote_buf_start,
                                size_t size,
                                const char *rdma_descr,
                                uint16_t channel) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    std::string k(key);
    std::string descr(rdma_descr);
    ibv_wc_status wc_status = IBV_WC_SUCCESS;
    ssize_t rc = s->handleGetObject(k, local_buf, remote_buf_start, size, descr,
                                    channel, 0, &wc_status);
    if (rc < 0 && g_verbose_logs.load()) {
        fprintf(stderr,
                "cuobjwrapper: handleGetObject rc=%zd channel=%u wc_status=%d\n",
                rc, static_cast<unsigned>(channel), static_cast<int>(wc_status));
    }
    return rc;
}

ssize_t cuobj_server_handle_put(cuobj_server_t *srv,
                                const char *key,
                                cuobj_rdma_buffer_t *local_buf,
                                uint64_t remote_buf_start,
                                size_t size,
                                const char *rdma_descr,
                                uint16_t channel) {
    auto *s = reinterpret_cast<cuObjServer*>(srv);
    std::string k(key);
    std::string descr(rdma_descr);
    ibv_wc_status wc_status = IBV_WC_SUCCESS;
    ssize_t rc = s->handlePutObject(k, local_buf, remote_buf_start, size, descr,
                                    channel, 0, &wc_status);
    if (rc < 0 && g_verbose_logs.load()) {
        fprintf(stderr,
                "cuobjwrapper: handlePutObject rc=%zd channel=%u wc_status=%d\n",
                rc, static_cast<unsigned>(channel), static_cast<int>(wc_status));
    }
    return rc;
}

void cuobj_server_setup_telemetry(int use_otel) {
    cuObjServer::setupTelemetry(use_otel != 0, &std::cout);
}

void cuobj_server_shutdown_telemetry(void) {
    cuObjServer::shutdownTelemetry();
}

void cuobj_server_set_telem_flags(unsigned flags) {
    g_verbose_logs.store((flags & 0x0003u) != 0u);
    // 2.0.0 added a second mask selecting which operations get logged
    // (CUOBJ_LOG_OP_GET / CUOBJ_LOG_OP_PUT). cuObjTelem initialises it to 0,
    // so passing 0 keeps the 1.2.0 behaviour of no per-operation logging.
    cuObjServer::setTelemFlags(flags, 0);
}

} // extern "C"
