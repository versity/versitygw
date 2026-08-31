/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

/* Host-only RDMA verbs shim for the RC session core.
 *
 * The upstream hipObject ibv-wrapper links the GPU runtime for
 * dmabuf-based memory registration. The gateway runs the RC data
 * plane on host memory only, so this shim loads the plain
 * libibverbs entry points with dlopen/dlsym (keeping the gateway
 * free of a hard library dependency at link time) and exposes the
 * same function-table seam the ported core expects. All ibv
 * struct/enum types come from the vendored ibv-core.h, so real
 * verbs headers are not included here.
 */

#pragma once

#include <dlfcn.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "ibv-core.h"

namespace hipObj {

/* Function table type mirrors the upstream seam so the ported
 * session core compiles unchanged. */
struct IbvFuncs {
  struct ibv_device **(*get_device_list)(int *);
  void (*free_device_list)(struct ibv_device **);
  struct ibv_context *(*open_device)(struct ibv_device *);
  int (*close_device)(struct ibv_context *);
  struct ibv_pd *(*alloc_pd)(struct ibv_context *);
  int (*dealloc_pd)(struct ibv_pd *);
  struct ibv_mr *(*reg_mr)(struct ibv_pd *, void *, size_t, int);
  struct ibv_mr *(*reg_mr_host)(struct ibv_pd *, void *, size_t, int);
  int (*dereg_mr)(struct ibv_mr *);
  struct ibv_cq *(*create_cq)(struct ibv_context *, int, void *,
                              struct ibv_comp_channel *, int);
  int (*destroy_cq)(struct ibv_cq *);
  struct ibv_qp *(*create_qp)(struct ibv_pd *,
                              struct ibv_qp_init_attr *);
  int (*destroy_qp)(struct ibv_qp *);
  int (*modify_qp)(struct ibv_qp *, struct ibv_qp_attr *, int);
  int (*poll_cq)(struct ibv_cq *, int, struct ibv_wc *);
  int (*query_device)(struct ibv_context *, struct ibv_device_attr *);
  int (*query_port)(struct ibv_context *, uint8_t,
                    struct ibv_port_attr *);
  int (*query_gid)(struct ibv_context *, uint8_t, int, union ibv_gid *);
  int (*post_recv)(struct ibv_qp *, struct ibv_recv_wr *,
                   struct ibv_recv_wr **);
  int (*post_send)(struct ibv_qp *, struct ibv_send_wr *,
                   struct ibv_send_wr **);
};

class IBVWrapper {
 public:
  IbvFuncs funcs_{};
  bool loaded = false;

  /* Seam passthrough so the ported core keeps calling ibv.x()
   * directly (upstream ibv-wrapper exposed the verbs entry
   * points as members). */
  struct ibv_device **(*get_device_list)(int *) = nullptr;
  void (*free_device_list)(struct ibv_device **) = nullptr;
  struct ibv_context *(*open_device)(struct ibv_device *) = nullptr;
  int (*close_device)(struct ibv_context *) = nullptr;
  struct ibv_pd *(*alloc_pd)(struct ibv_context *) = nullptr;
  int (*dealloc_pd)(struct ibv_pd *) = nullptr;
  struct ibv_mr *(*reg_mr)(struct ibv_pd *, void *, size_t, int) = nullptr;
  struct ibv_mr *(*reg_mr_host)(struct ibv_pd *, void *, size_t, int) = nullptr;
  int (*dereg_mr)(struct ibv_mr *) = nullptr;
  struct ibv_cq *(*create_cq)(struct ibv_context *, int, void *,
                              struct ibv_comp_channel *, int) = nullptr;
  int (*destroy_cq)(struct ibv_cq *) = nullptr;
  struct ibv_qp *(*create_qp)(struct ibv_pd *,
                              struct ibv_qp_init_attr *) = nullptr;
  int (*destroy_qp)(struct ibv_qp *) = nullptr;
  int (*modify_qp)(struct ibv_qp *, struct ibv_qp_attr *, int) = nullptr;
  int (*poll_cq)(struct ibv_cq *, int, struct ibv_wc *) = nullptr;
  int (*query_device)(struct ibv_context *, struct ibv_device_attr *) = nullptr;
  int (*query_port)(struct ibv_context *, uint8_t,
                    struct ibv_port_attr *) = nullptr;
  int (*query_gid)(struct ibv_context *, uint8_t, int, union ibv_gid *) = nullptr;
  int (*post_recv)(struct ibv_qp *, struct ibv_recv_wr *,
                   struct ibv_recv_wr **) = nullptr;
  int (*post_send)(struct ibv_qp *, struct ibv_send_wr *,
                   struct ibv_send_wr **) = nullptr;

  static IBVWrapper &instance();

#ifdef HIPOBJ_UNIT_TESTS
  IbvFuncs &funcsForTest() { return funcs_; }
#endif

  bool ensureLoaded();

 private:
  std::mutex mtx_;
  void *handle_ = nullptr;
};

extern IBVWrapper ibv;

/* Upstream seam spelling used by the ported core (ibv.funcs_.x). */

}  // namespace hipObj
