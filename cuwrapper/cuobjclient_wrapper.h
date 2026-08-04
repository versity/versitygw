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

// C wrapper for cuObjClient + CUDA runtime APIs.
// Exposes a C ABI suitable for CGO.

#ifndef CUOBJCLIENT_WRAPPER_H
#define CUOBJCLIENT_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cuobj_client_ctx cuobj_client_ctx_t;

// cuObj operation values (match cuObjOpType_t in cuobjclient headers).
#define CUOBJCLIENT_OP_GET 0
#define CUOBJCLIENT_OP_PUT 1

// Lifecycle
cuobj_client_ctx_t* cuobj_client_create(void);
void                cuobj_client_destroy(cuobj_client_ctx_t *ctx);

// GPU memory management
void*       cuobj_client_cuda_malloc(size_t size);
int         cuobj_client_cuda_free(void *ptr);
int         cuobj_client_cuda_memset(void *ptr, int value, size_t size);
int         cuobj_client_cuda_memcpy_h2d(void *dst_dev, const void *src_host, size_t size);
int         cuobj_client_cuda_memcpy_d2h(void *dst_host, const void *src_dev, size_t size);
const char* cuobj_client_cuda_error_string(int cuda_err);

// cuObject memory registration
int cuobj_client_register_descriptor(cuobj_client_ctx_t *ctx, void *ptr, size_t size);
int cuobj_client_unregister_descriptor(cuobj_client_ctx_t *ctx, void *ptr);

// RDMA token management.
// Returns an allocated descriptor string on success, NULL on failure.
// Caller must release it via cuobj_client_put_rdma_token.
char* cuobj_client_get_rdma_token(cuobj_client_ctx_t *ctx,
                                  void *ptr,
                                  size_t size,
                                  size_t buffer_offset,
                                  int operation);
int   cuobj_client_put_rdma_token(cuobj_client_ctx_t *ctx, char *token);

// Utility
uint64_t cuobj_client_ptr_to_u64(void *ptr);

#ifdef __cplusplus
}
#endif

#endif // CUOBJCLIENT_WRAPPER_H
