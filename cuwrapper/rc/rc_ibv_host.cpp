/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "rc_ibv_host.h"

namespace hipObj {

IBVWrapper &IBVWrapper::instance() {
  static IBVWrapper w;
  return w;
}

IBVWrapper ibv __attribute__((init_priority(400)));

bool IBVWrapper::ensureLoaded() {
  std::lock_guard<std::mutex> guard(mtx_);
  if (loaded) {
    return true;
  }
  handle_ = dlopen("libibverbs.so.1", RTLD_NOW | RTLD_GLOBAL);
  if (handle_ == nullptr) {
    handle_ = dlopen("libibverbs.so", RTLD_NOW | RTLD_GLOBAL);
  }
  if (handle_ == nullptr) {
    return false;
  }
  auto load = [&](const char *name) -> void * {
    return dlsym(handle_, name);
  };
  funcs_.get_device_list =
      reinterpret_cast<struct ibv_device **(*)(int *)>(load("ibv_get_device_list"));
  funcs_.free_device_list =
      reinterpret_cast<void (*)(struct ibv_device **)>(load("ibv_free_device_list"));
  funcs_.open_device = reinterpret_cast<struct ibv_context *(*)(struct ibv_device *)>(
      load("ibv_open_device"));
  funcs_.close_device = reinterpret_cast<int (*)(struct ibv_context *)>(
      load("ibv_close_device"));
  funcs_.alloc_pd = reinterpret_cast<struct ibv_pd *(*)(struct ibv_context *)>(
      load("ibv_alloc_pd"));
  funcs_.dealloc_pd = reinterpret_cast<int (*)(struct ibv_pd *)>(
      load("ibv_dealloc_pd"));
  funcs_.reg_mr = reinterpret_cast<struct ibv_mr *(*)(struct ibv_pd *, void *,
                                                      size_t, int)>(load("ibv_reg_mr"));
  /* Host-only build: both spellings land on the plain verbs call. */
  funcs_.reg_mr_host = funcs_.reg_mr;
  funcs_.dereg_mr = reinterpret_cast<int (*)(struct ibv_mr *)>(
      load("ibv_dereg_mr"));
  funcs_.create_cq = reinterpret_cast<struct ibv_cq *(*)(
      struct ibv_context *, int, void *, struct ibv_comp_channel *, int)>(
      load("ibv_create_cq"));
  funcs_.destroy_cq = reinterpret_cast<int (*)(struct ibv_cq *)>(
      load("ibv_destroy_cq"));
  funcs_.create_qp = reinterpret_cast<struct ibv_qp *(*)(
      struct ibv_pd *, struct ibv_qp_init_attr *)>(load("ibv_create_qp"));
  funcs_.destroy_qp = reinterpret_cast<int (*)(struct ibv_qp *)>(
      load("ibv_destroy_qp"));
  funcs_.modify_qp = reinterpret_cast<int (*)(struct ibv_qp *,
                                              struct ibv_qp_attr *, int)>(
      load("ibv_modify_qp"));
  funcs_.poll_cq = reinterpret_cast<int (*)(struct ibv_cq *, int,
                                            struct ibv_wc *)>(load("ibv_poll_cq"));
  funcs_.query_device = reinterpret_cast<int (*)(
      struct ibv_context *, struct ibv_device_attr *)>(load("ibv_query_device"));
  funcs_.query_port = reinterpret_cast<int (*)(
      struct ibv_context *, uint8_t, struct ibv_port_attr *)>(
      load("ibv_query_port"));
  funcs_.query_gid = reinterpret_cast<int (*)(
      struct ibv_context *, uint8_t, int, union ibv_gid *)>(
      load("ibv_query_gid"));
  funcs_.post_recv = reinterpret_cast<int (*)(struct ibv_qp *,
      struct ibv_recv_wr *, struct ibv_recv_wr **)>(load("ibv_post_recv"));
  funcs_.post_send = reinterpret_cast<int (*)(struct ibv_qp *,
      struct ibv_send_wr *, struct ibv_send_wr **)>(load("ibv_post_send"));
  loaded = funcs_.get_device_list != nullptr && funcs_.open_device != nullptr &&
           funcs_.alloc_pd != nullptr && funcs_.create_qp != nullptr &&
           funcs_.modify_qp != nullptr;
  if (loaded) {
    /* poll_cq/post_send/post_recv are static inline wrappers in
     * modern verbs.h (they dispatch through cq->context->ops), so
     * dlsym cannot find them on rdma-core 61+. Resolve them from
     * the ops table of the first successfully opened context
     * instead; every context from the same device shares these
     * providers. */
    int n = 0;
    struct ibv_device **devs = funcs_.get_device_list(&n);
    struct ibv_context *probe = nullptr;
    if (devs && n > 0) probe = funcs_.open_device(devs[0]);
    if (devs) funcs_.free_device_list(devs);
    if (!probe) {
      fprintf(stderr, "rc: no RDMA device to resolve verbs ops\n");
      loaded = false;
    } else {
      funcs_.poll_cq = probe->ops.poll_cq;
      funcs_.post_recv = probe->ops.post_recv;
      funcs_.post_send = probe->ops.post_send;
      funcs_.close_device(probe);
      if (!funcs_.poll_cq || !funcs_.post_recv || !funcs_.post_send) {
        fprintf(stderr, "rc: provider ops table incomplete\n");
        loaded = false;
      }
    }
  }
  if (loaded) {
    /* Mirror into the member seam for direct ibv.x() calls. */
    get_device_list = funcs_.get_device_list;
    free_device_list = funcs_.free_device_list;
    open_device = funcs_.open_device;
    close_device = funcs_.close_device;
    alloc_pd = funcs_.alloc_pd;
    dealloc_pd = funcs_.dealloc_pd;
    reg_mr = funcs_.reg_mr;
    reg_mr_host = funcs_.reg_mr_host;
    dereg_mr = funcs_.dereg_mr;
    create_cq = funcs_.create_cq;
    destroy_cq = funcs_.destroy_cq;
    create_qp = funcs_.create_qp;
    destroy_qp = funcs_.destroy_qp;
    modify_qp = funcs_.modify_qp;
    poll_cq = funcs_.poll_cq;
    query_device = funcs_.query_device;
    query_port = funcs_.query_port;
    query_gid = funcs_.query_gid;
    post_recv = funcs_.post_recv;
    post_send = funcs_.post_send;
  }
  return loaded;
}

}  // namespace hipObj
