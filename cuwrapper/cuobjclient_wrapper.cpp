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

// C wrapper implementation for cuObjClient and CUDA runtime operations.

#include "cuobjclient_wrapper.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>

#include <cuda_runtime_api.h>
#include <cuobjclient.h>

struct cuobj_client_ctx {
    CUObjOps_t ops;
    cuObjClient *client;
};

static ssize_t noop_get(const void *, char *, size_t, loff_t, const cufileRDMAInfo_t *) {
    return -EOPNOTSUPP;
}

static ssize_t noop_put(const void *, const char *, size_t, loff_t, const cufileRDMAInfo_t *) {
    return -EOPNOTSUPP;
}

extern "C" {

cuobj_client_ctx_t* cuobj_client_create(void) {
    try {
        auto *ctx = new cuobj_client_ctx_t();
        ctx->ops.get = noop_get;
        ctx->ops.put = noop_put;
        ctx->client = new cuObjClient(ctx->ops, CUOBJ_PROTO_RDMA_DC_V1);
        return ctx;
    } catch (...) {
        return nullptr;
    }
}

void cuobj_client_destroy(cuobj_client_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    delete ctx->client;
    delete ctx;
}

void* cuobj_client_cuda_malloc(size_t size) {
    void *ptr = nullptr;
    cudaError_t rc = cudaMalloc(&ptr, size);
    if (rc != cudaSuccess) {
        return nullptr;
    }
    return ptr;
}

int cuobj_client_cuda_free(void *ptr) {
    cudaError_t rc = cudaFree(ptr);
    return static_cast<int>(rc);
}

int cuobj_client_cuda_memset(void *ptr, int value, size_t size) {
    cudaError_t rc = cudaMemset(ptr, value, size);
    return static_cast<int>(rc);
}

int cuobj_client_cuda_memcpy_h2d(void *dst_dev, const void *src_host, size_t size) {
    cudaError_t rc = cudaMemcpy(dst_dev, src_host, size, cudaMemcpyHostToDevice);
    return static_cast<int>(rc);
}

int cuobj_client_cuda_memcpy_d2h(void *dst_host, const void *src_dev, size_t size) {
    cudaError_t rc = cudaMemcpy(dst_host, src_dev, size, cudaMemcpyDeviceToHost);
    return static_cast<int>(rc);
}

const char* cuobj_client_cuda_error_string(int cuda_err) {
    return cudaGetErrorString(static_cast<cudaError_t>(cuda_err));
}

int cuobj_client_register_descriptor(cuobj_client_ctx_t *ctx, void *ptr, size_t size) {
    if (!ctx || !ctx->client || !ptr || size == 0) {
        return 1;
    }
    cuObjErr_t rc = ctx->client->cuMemObjGetDescriptor(ptr, size);
    return static_cast<int>(rc);
}

int cuobj_client_unregister_descriptor(cuobj_client_ctx_t *ctx, void *ptr) {
    if (!ctx || !ctx->client || !ptr) {
        return 1;
    }
    cuObjErr_t rc = ctx->client->cuMemObjPutDescriptor(ptr);
    // Synchronize the device to ensure the hardware-level RDMA deregistration
    // (memory unpinning, hardware lock release) completes before this call
    // returns. Without this, a subsequent process that immediately calls
    // cuMemObjGetDescriptor on a new allocation can race with the driver's
    // asynchronous cleanup and receive a hardware rejection.
    cudaDeviceSynchronize();
    return static_cast<int>(rc);
}

char* cuobj_client_get_rdma_token(cuobj_client_ctx_t *ctx,
                                  void *ptr,
                                  size_t size,
                                  size_t buffer_offset,
                                  int operation) {
    if (!ctx || !ctx->client || !ptr || size == 0) {
        return nullptr;
    }
    cuObjOpType_t op;
    if (operation == CUOBJCLIENT_OP_GET) {
        op = CUOBJ_GET;
    } else if (operation == CUOBJCLIENT_OP_PUT) {
        op = CUOBJ_PUT;
    } else {
        return nullptr;
    }

    char *token = nullptr;
    cuObjErr_t rc = ctx->client->cuMemObjGetRDMAToken(ptr, size, buffer_offset, op, &token);
    if (rc != CU_OBJ_SUCCESS) {
        return nullptr;
    }
    return token;
}

int cuobj_client_put_rdma_token(cuobj_client_ctx_t *ctx, char *token) {
    if (!ctx || !ctx->client || !token) {
        return 1;
    }
    cuObjErr_t rc = ctx->client->cuMemObjPutRDMAToken(token);
    return static_cast<int>(rc);
}

uint64_t cuobj_client_ptr_to_u64(void *ptr) {
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptr));
}

} // extern "C"
