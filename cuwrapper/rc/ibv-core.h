/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2004, 2011-2012 Intel Corporation.  All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation.  All rights reserved.
 * Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * InfiniBand verbs type definitions for dynamic
 * libibverbs loading.
 *
 * Derived from ROCm/rocSHMEM src/gda/ibv_core.hpp via
 * rocm-xio src/common/ibv-core.hpp.
 */

#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>

#include <linux/types.h>
#include <pthread.h>

/* -------------------------------------------------------------------------
 * 1. ib_uverbs_access_flags enum and IBV_ACCESS_OPTIONAL_* macros
 * ------------------------------------------------------------------------- */

enum ib_uverbs_access_flags {
  IB_UVERBS_ACCESS_LOCAL_WRITE = 1,
  IB_UVERBS_ACCESS_REMOTE_WRITE = (1 << 1),
  IB_UVERBS_ACCESS_REMOTE_READ = (1 << 2),
  IB_UVERBS_ACCESS_REMOTE_ATOMIC = (1 << 3),
  IB_UVERBS_ACCESS_MW_BIND = (1 << 4),
  IB_UVERBS_ACCESS_ZERO_BASED = (1 << 5),
  IB_UVERBS_ACCESS_ON_DEMAND = (1 << 6),
  IB_UVERBS_ACCESS_HUGETLB = (1 << 7),
  IB_UVERBS_ACCESS_FLUSH_GLOBAL = (1 << 8),
  IB_UVERBS_ACCESS_FLUSH_PERSISTENT = (1 << 9),
  IB_UVERBS_ACCESS_RELAXED_ORDERING = (1 << 20),
};

#define IBV_ACCESS_OPTIONAL_FIRST (1 << 20)
#define IBV_ACCESS_OPTIONAL_LAST (1 << 29)
#define IBV_ACCESS_OPTIONAL_RANGE (((1ULL << 30) - 1) & ~((1ULL << 20) - 1))

/* -------------------------------------------------------------------------
 * 2. union ibv_gid
 * ------------------------------------------------------------------------- */

union ibv_gid {
  uint8_t raw[16];
  struct {
    __be64 subnet_prefix;
    __be64 interface_id;
  } global;
};

/* -------------------------------------------------------------------------
 * 3. ibv_gid_type enum
 * ------------------------------------------------------------------------- */

enum ibv_gid_type {
  IBV_GID_TYPE_IB,
  IBV_GID_TYPE_ROCE_V1,
  IBV_GID_TYPE_ROCE_V2,
};

/* -------------------------------------------------------------------------
 * 4. ibv_gid_entry struct
 * ------------------------------------------------------------------------- */

struct ibv_gid_entry {
  union ibv_gid gid;
  uint32_t gid_index;
  uint32_t port_num;
  uint32_t gid_type;
  uint32_t ndev_ifindex;
};

/* -------------------------------------------------------------------------
 * 5. ibv_node_type, ibv_transport_type, ibv_atomic_cap enums
 * ------------------------------------------------------------------------- */

enum ibv_node_type {
  IBV_NODE_UNKNOWN = -1,
  IBV_NODE_CA = 1,
  IBV_NODE_SWITCH,
  IBV_NODE_ROUTER,
  IBV_NODE_RNIC,
  IBV_NODE_USNIC,
  IBV_NODE_USNIC_UDP,
  IBV_NODE_UNSPECIFIED,
};

enum ibv_transport_type {
  IBV_TRANSPORT_UNKNOWN = -1,
  IBV_TRANSPORT_IB = 0,
  IBV_TRANSPORT_IWARP,
  IBV_TRANSPORT_USNIC,
  IBV_TRANSPORT_USNIC_UDP,
  IBV_TRANSPORT_UNSPECIFIED,
};

enum ibv_atomic_cap { IBV_ATOMIC_NONE, IBV_ATOMIC_HCA, IBV_ATOMIC_GLOB };

/* -------------------------------------------------------------------------
 * 6. ibv_device_attr struct (full)
 * ------------------------------------------------------------------------- */

struct ibv_device_attr {
  char fw_ver[64];
  __be64 node_guid;
  __be64 sys_image_guid;
  uint64_t max_mr_size;
  uint64_t page_size_cap;
  uint32_t vendor_id;
  uint32_t vendor_part_id;
  uint32_t hw_ver;
  int max_qp;
  int max_qp_wr;
  unsigned int device_cap_flags;
  int max_sge;
  int max_sge_rd;
  int max_cq;
  int max_cqe;
  int max_mr;
  int max_pd;
  int max_qp_rd_atom;
  int max_ee_rd_atom;
  int max_res_rd_atom;
  int max_qp_init_rd_atom;
  int max_ee_init_rd_atom;
  enum ibv_atomic_cap atomic_cap;
  int max_ee;
  int max_rdd;
  int max_mw;
  int max_raw_ipv6_qp;
  int max_raw_ethy_qp;
  int max_mcast_grp;
  int max_mcast_qp_attach;
  int max_total_mcast_qp_attach;
  int max_ah;
  int max_fmr;
  int max_map_per_fmr;
  int max_srq;
  int max_srq_wr;
  int max_srq_sge;
  uint16_t max_pkeys;
  uint8_t local_ca_ack_delay;
  uint8_t phys_port_cnt;
};

/* -------------------------------------------------------------------------
 * 7. ibv_mtu enum, ibv_port_state enum, link layer constants
 * ------------------------------------------------------------------------- */

enum ibv_mtu {
  IBV_MTU_256 = 1,
  IBV_MTU_512 = 2,
  IBV_MTU_1024 = 3,
  IBV_MTU_2048 = 4,
  IBV_MTU_4096 = 5
};

enum ibv_port_state {
  IBV_PORT_NOP = 0,
  IBV_PORT_DOWN = 1,
  IBV_PORT_INIT = 2,
  IBV_PORT_ARMED = 3,
  IBV_PORT_ACTIVE = 4,
  IBV_PORT_ACTIVE_DEFER = 5
};

enum {
  IBV_LINK_LAYER_UNSPECIFIED,
  IBV_LINK_LAYER_INFINIBAND,
  IBV_LINK_LAYER_ETHERNET,
};

/* -------------------------------------------------------------------------
 * 8. ibv_port_attr struct (full)
 * ------------------------------------------------------------------------- */

struct ibv_port_attr {
  enum ibv_port_state state;
  enum ibv_mtu max_mtu;
  enum ibv_mtu active_mtu;
  int gid_tbl_len;
  uint32_t port_cap_flags;
  uint32_t max_msg_sz;
  uint32_t bad_pkey_cntr;
  uint32_t qkey_viol_cntr;
  uint16_t pkey_tbl_len;
  uint16_t lid;
  uint16_t sm_lid;
  uint8_t lmc;
  uint8_t max_vl_num;
  uint8_t sm_sl;
  uint8_t subnet_timeout;
  uint8_t init_type_reply;
  uint8_t active_width;
  uint8_t active_speed;
  uint8_t phys_state;
  uint8_t link_layer;
  uint8_t flags;
  uint16_t port_cap_flags2;
  uint32_t active_speed_ex;
};

/* -------------------------------------------------------------------------
 * 9. ibv_wc_status enum, ibv_wc struct
 * ------------------------------------------------------------------------- */

/* Completion flags (wc_flags in struct ibv_wc). */
enum ibv_wc_flags {
  IBV_WC_GRH = 1 << 0,
  IBV_WC_WITH_IMM = 1 << 1,
  IBV_WC_IP_CSUM_OK = 1 << 2,
  IBV_WC_WITH_INV = 1 << 3,
  IBV_WC_TM_SYNC_REQ = 1 << 4,
  IBV_WC_TM_DATA_VALID = 1 << 5,
  IBV_WC_TM_MATCH_REQ = 1 << 6,
  IBV_WC_TM_DATA_VALID_2 = 1 << 7
};

enum ibv_wc_opcode {
  IBV_WC_SEND,
  IBV_WC_RDMA_WRITE,
  IBV_WC_RDMA_READ,
  IBV_WC_COMP_SWAP,
  IBV_WC_FETCH_ADD,
  IBV_WC_BIND_MW,
  IBV_WC_LOCAL_INV,
  IBV_WC_TSO,
  IBV_WC_FLUSH,
  IBV_WC_ATOMIC_WRITE = 9,
  IBV_WC_RECV = 1 << 7,
  IBV_WC_RECV_RDMA_WITH_IMM,
};

enum ibv_wc_status {
  IBV_WC_SUCCESS,
  IBV_WC_LOC_LEN_ERR,
  IBV_WC_LOC_QP_OP_ERR,
  IBV_WC_LOC_EEC_OP_ERR,
  IBV_WC_LOC_PROT_ERR,
  IBV_WC_WR_FLUSH_ERR,
  IBV_WC_MW_BIND_ERR,
  IBV_WC_BAD_RESP_ERR,
  IBV_WC_LOC_ACCESS_ERR,
  IBV_WC_REM_INV_REQ_ERR,
  IBV_WC_REM_ACCESS_ERR,
  IBV_WC_REM_OP_ERR,
  IBV_WC_RETRY_EXC_ERR,
  IBV_WC_RNR_RETRY_EXC_ERR,
  IBV_WC_LOC_RDD_VIOL_ERR,
  IBV_WC_REM_INV_RD_REQ_ERR,
  IBV_WC_REM_ABORT_ERR,
  IBV_WC_INV_EECN_ERR,
  IBV_WC_INV_EEC_STATE_ERR,
  IBV_WC_FATAL_ERR,
  IBV_WC_RESP_TIMEOUT_ERR,
  IBV_WC_GENERAL_ERR,
  IBV_WC_TM_ERR,
  IBV_WC_TM_RNDV_INCOMPLETE,
};

struct ibv_wc {
  uint64_t wr_id;
  enum ibv_wc_status status;
  enum ibv_wc_opcode opcode;
  uint32_t vendor_err;
  uint32_t byte_len;
  union {
    __be32 imm_data;
    uint32_t invalidated_rkey;
  };
  uint32_t qp_num;
  uint32_t src_qp;
  unsigned int wc_flags;
  uint16_t pkey_index;
  uint16_t slid;
  uint8_t sl;
  uint8_t dlid_path_bits;
};

/* -------------------------------------------------------------------------
 * 10. ibv_access_flags enum
 * ------------------------------------------------------------------------- */

enum ibv_access_flags {
  IBV_ACCESS_LOCAL_WRITE = 1,
  IBV_ACCESS_REMOTE_WRITE = (1 << 1),
  IBV_ACCESS_REMOTE_READ = (1 << 2),
  IBV_ACCESS_REMOTE_ATOMIC = (1 << 3),
  IBV_ACCESS_MW_BIND = (1 << 4),
  IBV_ACCESS_ZERO_BASED = (1 << 5),
  IBV_ACCESS_ON_DEMAND = (1 << 6),
  IBV_ACCESS_HUGETLB = (1 << 7),
  IBV_ACCESS_FLUSH_GLOBAL = (1 << 8),
  IBV_ACCESS_FLUSH_PERSISTENT = (1 << 9),
  IBV_ACCESS_RELAXED_ORDERING = IBV_ACCESS_OPTIONAL_FIRST,
};

/* -------------------------------------------------------------------------
 * 11. ibv_pd struct, ibv_mr struct
 * ------------------------------------------------------------------------- */

struct ibv_context;

struct ibv_pd {
  struct ibv_context* context;
  uint32_t handle;
};

struct ibv_mr {
  struct ibv_context* context;
  struct ibv_pd* pd;
  void* addr;
  size_t length;
  uint32_t handle;
  uint32_t lkey;
  uint32_t rkey;
};

/* -------------------------------------------------------------------------
 * 12. ibv_global_route, ibv_ah_attr structs
 * ------------------------------------------------------------------------- */

struct ibv_global_route {
  union ibv_gid dgid;
  uint32_t flow_label;
  uint8_t sgid_index;
  uint8_t hop_limit;
  uint8_t traffic_class;
};

struct ibv_ah_attr {
  struct ibv_global_route grh;
  uint16_t dlid;
  uint8_t sl;
  uint8_t src_path_bits;
  uint8_t static_rate;
  uint8_t is_global;
  uint8_t port_num;
};

/* -------------------------------------------------------------------------
 * 13. ibv_qp_type enum
 * ------------------------------------------------------------------------- */

enum ibv_qp_type {
  IBV_QPT_RC = 2,
  IBV_QPT_UC,
  IBV_QPT_UD,
  IBV_QPT_RAW_PACKET = 8,
  IBV_QPT_XRC_SEND = 9,
  IBV_QPT_XRC_RECV,
  IBV_QPT_DRIVER = 0xff,
};

/* -------------------------------------------------------------------------
 * 14. ibv_qp_cap struct, ibv_qp_init_attr struct
 * ------------------------------------------------------------------------- */

struct ibv_cq;

struct ibv_qp_cap {
  uint32_t max_send_wr;
  uint32_t max_recv_wr;
  uint32_t max_send_sge;
  uint32_t max_recv_sge;
  uint32_t max_inline_data;
};

struct ibv_comp_channel;
struct ibv_srq;

struct ibv_qp_init_attr {
  void* qp_context;
  struct ibv_cq* send_cq;
  struct ibv_cq* recv_cq;
  struct ibv_srq* srq;
  struct ibv_qp_cap cap;
  enum ibv_qp_type qp_type;
  int sq_sig_all;
};

/* -------------------------------------------------------------------------
 * 15. ibv_qp_attr_mask enum
 * ------------------------------------------------------------------------- */

enum ibv_qp_attr_mask {
  IBV_QP_STATE = 1 << 0,
  IBV_QP_CUR_STATE = 1 << 1,
  IBV_QP_EN_SQD_ASYNC_NOTIFY = 1 << 2,
  IBV_QP_ACCESS_FLAGS = 1 << 3,
  IBV_QP_PKEY_INDEX = 1 << 4,
  IBV_QP_PORT = 1 << 5,
  IBV_QP_QKEY = 1 << 6,
  IBV_QP_AV = 1 << 7,
  IBV_QP_PATH_MTU = 1 << 8,
  IBV_QP_TIMEOUT = 1 << 9,
  IBV_QP_RETRY_CNT = 1 << 10,
  IBV_QP_RNR_RETRY = 1 << 11,
  IBV_QP_RQ_PSN = 1 << 12,
  IBV_QP_MAX_QP_RD_ATOMIC = 1 << 13,
  IBV_QP_ALT_PATH = 1 << 14,
  IBV_QP_MIN_RNR_TIMER = 1 << 15,
  IBV_QP_SQ_PSN = 1 << 16,
  IBV_QP_MAX_DEST_RD_ATOMIC = 1 << 17,
  IBV_QP_PATH_MIG_STATE = 1 << 18,
  IBV_QP_CAP = 1 << 19,
  IBV_QP_DEST_QPN = 1 << 20,
  IBV_QP_RATE_LIMIT = 1 << 25,
};

/* -------------------------------------------------------------------------
 * 16. ibv_qp_state enum, ibv_mig_state enum
 * ------------------------------------------------------------------------- */

enum ibv_qp_state {
  IBV_QPS_RESET,
  IBV_QPS_INIT,
  IBV_QPS_RTR,
  IBV_QPS_RTS,
  IBV_QPS_SQD,
  IBV_QPS_SQE,
  IBV_QPS_ERR,
  IBV_QPS_UNKNOWN
};

enum ibv_mig_state { IBV_MIG_MIGRATED, IBV_MIG_REARM, IBV_MIG_ARMED };

/* -------------------------------------------------------------------------
 * 17. ibv_qp_attr struct (full)
 * ------------------------------------------------------------------------- */

struct ibv_qp_attr {
  enum ibv_qp_state qp_state;
  enum ibv_qp_state cur_qp_state;
  enum ibv_mtu path_mtu;
  enum ibv_mig_state path_mig_state;
  uint32_t qkey;
  uint32_t rq_psn;
  uint32_t sq_psn;
  uint32_t dest_qp_num;
  unsigned int qp_access_flags;
  struct ibv_qp_cap cap;
  struct ibv_ah_attr ah_attr;
  struct ibv_ah_attr alt_ah_attr;
  uint16_t pkey_index;
  uint16_t alt_pkey_index;
  uint8_t en_sqd_async_notify;
  uint8_t sq_draining;
  uint8_t max_rd_atomic;
  uint8_t max_dest_rd_atomic;
  uint8_t min_rnr_timer;
  uint8_t port_num;
  uint8_t timeout;
  uint8_t retry_cnt;
  uint8_t rnr_retry;
  uint8_t alt_port_num;
  uint8_t alt_timeout;
  uint32_t rate_limit;
};

/* -------------------------------------------------------------------------
 * 18. ibv_qp struct
 * ------------------------------------------------------------------------- */

struct ibv_qp {
  struct ibv_context* context;
  void* qp_context;
  struct ibv_pd* pd;
  struct ibv_cq* send_cq;
  struct ibv_cq* recv_cq;
  struct ibv_srq* srq;
  uint32_t handle;
  uint32_t qp_num;
  enum ibv_qp_state state;
  enum ibv_qp_type qp_type;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  uint32_t events_completed;
};

/* -------------------------------------------------------------------------
 * 19. ibv_wr_opcode enum
 * ------------------------------------------------------------------------- */

enum ibv_wr_opcode {
  IBV_WR_RDMA_WRITE,
  IBV_WR_RDMA_WRITE_WITH_IMM,
  IBV_WR_SEND,
  IBV_WR_SEND_WITH_IMM,
  IBV_WR_RDMA_READ,
  IBV_WR_ATOMIC_CMP_AND_SWP,
  IBV_WR_ATOMIC_FETCH_AND_ADD,
  IBV_WR_LOCAL_INV,
  IBV_WR_BIND_MW,
  IBV_WR_SEND_WITH_INV,
  IBV_WR_TSO,
  IBV_WR_DRIVER1,
  IBV_WR_FLUSH = 14,
  IBV_WR_ATOMIC_WRITE = 15,
};

/* -------------------------------------------------------------------------
 * 20. ibv_send_flags enum
 * ------------------------------------------------------------------------- */

enum ibv_send_flags {
  IBV_SEND_FENCE = 1 << 0,
  IBV_SEND_SIGNALED = 1 << 1,
  IBV_SEND_SOLICITED = 1 << 2,
  IBV_SEND_INLINE = 1 << 3,
};

/* -------------------------------------------------------------------------
 * 21. ibv_sge struct
 * ------------------------------------------------------------------------- */

struct ibv_sge {
  uint64_t addr;
  uint32_t length;
  uint32_t lkey;
};

/* -------------------------------------------------------------------------
 * 22. ibv_send_wr struct with union for rdma/atomic ops
 * ------------------------------------------------------------------------- */

struct ibv_ah;

struct ibv_send_wr {
  uint64_t wr_id;
  struct ibv_send_wr* next;
  struct ibv_sge* sg_list;
  int num_sge;
  enum ibv_wr_opcode opcode;
  unsigned int send_flags;
  union {
    __be32 imm_data;
    uint32_t invalidate_rkey;
  };
  union {
    struct {
      uint64_t remote_addr;
      uint32_t rkey;
    } rdma;
    struct {
      uint64_t remote_addr;
      uint64_t compare_add;
      uint64_t swap;
      uint32_t rkey;
    } atomic;
    struct {
      struct ibv_ah* ah;
      uint32_t remote_qpn;
      uint32_t remote_qkey;
    } ud;
  } wr;
};

/* -------------------------------------------------------------------------
 * 23. ibv_recv_wr struct
 * ------------------------------------------------------------------------- */

struct ibv_recv_wr {
  uint64_t wr_id;
  struct ibv_recv_wr* next;
  struct ibv_sge* sg_list;
  int num_sge;
};

/* -------------------------------------------------------------------------
 * 24. IBV_SYSFS_NAME_MAX, IBV_SYSFS_PATH_MAX
 * ------------------------------------------------------------------------- */

#define IBV_SYSFS_NAME_MAX 64
#define IBV_SYSFS_PATH_MAX 256

/* -------------------------------------------------------------------------
 * 25. _ibv_device_ops, ibv_device struct
 * ------------------------------------------------------------------------- */

struct _ibv_device_ops {
  struct ibv_context* (*_dummy1)(struct ibv_device* device, int cmd_fd);
  void (*_dummy2)(struct ibv_context* context);
};

struct ibv_device {
  struct _ibv_device_ops _ops;
  enum ibv_node_type node_type;
  enum ibv_transport_type transport_type;
  char name[IBV_SYSFS_NAME_MAX];
  char dev_name[IBV_SYSFS_NAME_MAX];
  char dev_path[IBV_SYSFS_PATH_MAX];
  char ibdev_path[IBV_SYSFS_PATH_MAX];
};

/* -------------------------------------------------------------------------
 * 26. Forward declare ibv_comp_channel and ibv_srq (already above)
 * ------------------------------------------------------------------------- */

struct ibv_comp_channel {
  struct ibv_context* context;
  int fd;
  int refcnt;
};

struct ibv_srq {
  struct ibv_context* context;
  void* srq_context;
  struct ibv_pd* pd;
  uint32_t handle;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  uint32_t events_completed;
};

/* -------------------------------------------------------------------------
 * 27. ibv_cq struct
 * ------------------------------------------------------------------------- */

struct ibv_cq {
  struct ibv_context* context;
  struct ibv_comp_channel* channel;
  void* cq_context;
  uint32_t handle;
  int cqe;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  uint32_t comp_events_completed;
  uint32_t async_events_completed;
};

/* -------------------------------------------------------------------------
 * 28. ibv_context_ops struct
 *    Mirrors the layout of struct ibv_context_ops from libibverbs verbs.h.
 *    poll_cq, post_send and post_recv are static inline functions in
 *    verbs.h that delegate to these ops entries; rdma-core does not
 *    export them as dynamic symbols.
 * ------------------------------------------------------------------------- */

struct ibv_context_ops {
  void* _compat_query_device;
  void* _compat_query_port;
  void* _compat_alloc_pd;
  void* _compat_dealloc_pd;
  void* _compat_reg_mr;
  void* _compat_rereg_mr;
  void* _compat_dereg_mr;
  void* alloc_mw;
  void* bind_mw;
  void* dealloc_mw;
  void* _compat_create_cq;
  int (*poll_cq)(struct ibv_cq* cq, int num_entries, struct ibv_wc* wc);
  void* req_notify_cq;
  void* _compat_cq_event;
  void* _compat_resize_cq;
  void* _compat_destroy_cq;
  void* _compat_create_srq;
  void* _compat_modify_srq;
  void* _compat_query_srq;
  void* _compat_destroy_srq;
  void* post_srq_recv;
  void* _compat_create_qp;
  void* _compat_query_qp;
  void* _compat_modify_qp;
  void* _compat_destroy_qp;
  int (*post_send)(struct ibv_qp* qp, struct ibv_send_wr* wr,
                   struct ibv_send_wr** bad_wr);
  int (*post_recv)(struct ibv_qp* qp, struct ibv_recv_wr* wr,
                   struct ibv_recv_wr** bad_wr);
  void* _compat_create_ah;
  void* _compat_destroy_ah;
  void* _compat_attach_mcast;
  void* _compat_detach_mcast;
  void* _compat_async_event;
};
/* -------------------------------------------------------------------------
 * 29. ibv_context struct
 * ------------------------------------------------------------------------- */

struct ibv_context {
  struct ibv_device* device;
  struct ibv_context_ops ops;
  int cmd_fd;
  int async_fd;
  int num_comp_vectors;
  pthread_mutex_t mutex;
  void* abi_compat;
};
