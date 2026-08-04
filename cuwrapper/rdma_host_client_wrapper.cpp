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

// Host-memory RDMA client wrapper implementation.
//
// Builds a passive DC Target (DCT) endpoint with libibverbs + mlx5 direct
// verbs so a cuObjServer can RDMA READ/WRITE the client's registered host
// memory. No CUDA/GPU dependency.

#include "rdma_host_client_wrapper.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <string>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

struct rdma_host_client {
    struct ibv_context *ctx = nullptr;
    struct ibv_pd      *pd  = nullptr;
    struct ibv_cq      *cq  = nullptr;
    struct ibv_srq     *srq = nullptr;
    struct ibv_qp      *dct = nullptr; // DC target QP

    uint8_t  port_num  = 1;
    int      gid_index = 0;
    uint64_t dc_key    = 0;

    uint16_t     lid   = 0;
    union ibv_gid gid  = {};
    uint32_t     dctn  = 0;

    void       *buf     = nullptr;
    size_t      buf_len = 0;
    struct ibv_mr *mr   = nullptr;

    std::string token;
    std::string last_error;
};

static void set_err(rdma_host_client_t *c, const std::string &msg) {
    if (c) {
        c->last_error = msg;
    }
}

static bool gid_is_zero(const union ibv_gid &gid) {
    for (int i = 0; i < 16; i++) {
        if (gid.raw[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool gid_is_link_local(const union ibv_gid &gid) {
    return gid.raw[0] == 0xfe && (gid.raw[1] & 0xc0) == 0x80;
}

static bool gid_is_ipv4_mapped(const union ibv_gid &gid) {
    for (int i = 0; i < 10; i++) {
        if (gid.raw[i] != 0) {
            return false;
        }
    }
    return gid.raw[10] == 0xff && gid.raw[11] == 0xff;
}

// gid_is_roce_v2 reports whether GID index i is a RoCEv2 entry. mlx5
// commonly exposes a RoCEv1 and RoCEv2 GID pair with identical raw bytes at
// adjacent indices (v1 first), so the raw GID content alone cannot
// distinguish them; only ibv_query_gid_ex()'s reported gid_type can. If the
// query fails (e.g. native InfiniBand link layer, where the v1/v2
// distinction doesn't apply), the GID is not excluded on this basis.
static bool gid_is_roce_v2(struct ibv_context *ctx, uint8_t port_num, int index) {
    struct ibv_gid_entry entry;
    memset(&entry, 0, sizeof(entry));
    if (ibv_query_gid_ex(ctx, port_num, static_cast<uint32_t>(index), &entry, 0)) {
        return true;
    }
    return entry.gid_type == IBV_GID_TYPE_ROCE_V2;
}

static bool select_gid(rdma_host_client_t *c) {
    if (c->gid_index >= 0) {
        if (ibv_query_gid(c->ctx, c->port_num, c->gid_index, &c->gid)) {
            set_err(c, "ibv_query_gid failed");
            return false;
        }
        return true;
    }

    struct ibv_port_attr port_attr;
    memset(&port_attr, 0, sizeof(port_attr));
    if (ibv_query_port(c->ctx, c->port_num, &port_attr)) {
        set_err(c, "ibv_query_port failed while selecting GID");
        return false;
    }

    int fallback_gid_index = -1;
    union ibv_gid fallback_gid = {};
    int v1_fallback_gid_index = -1;
    union ibv_gid v1_fallback_gid = {};
    int v1_non_ipv4_gid_index = -1;
    union ibv_gid v1_non_ipv4_gid = {};

    // Prefer non-zero, non-link-local, non-IPv4-mapped, RoCEv2 GIDs.
    // Use ibv_query_gid() only for broad provider compatibility.
    for (int i = 0; i < port_attr.gid_tbl_len; i++) {
        union ibv_gid gid = {};
        if (ibv_query_gid(c->ctx, c->port_num, i, &gid)) {
            continue;
        }
        if (gid_is_zero(gid)) {
            continue;
        }
        if (gid_is_link_local(gid)) {
            continue;
        }
        bool is_v2 = gid_is_roce_v2(c->ctx, c->port_num, i);
        if (gid_is_ipv4_mapped(gid)) {
            if (is_v2) {
                if (fallback_gid_index < 0) {
                    fallback_gid_index = i;
                    fallback_gid = gid;
                }
            } else if (v1_fallback_gid_index < 0) {
                v1_fallback_gid_index = i;
                v1_fallback_gid = gid;
            }
            continue;
        }
        if (is_v2) {
            c->gid_index = i;
            c->gid = gid;
            return true;
        }
        if (v1_non_ipv4_gid_index < 0) {
            v1_non_ipv4_gid_index = i;
            v1_non_ipv4_gid = gid;
        }
    }

    // Fallbacks, in order of preference: RoCEv2 IPv4-mapped, then any
    // RoCEv1 candidate. RoCEv1 is only used if no RoCEv2 GID is present at
    // all (e.g. non-Mellanox providers where ibv_query_gid_ex reports
    // unknown type for every entry, in which case gid_is_roce_v2 treats all
    // entries as usable and the earlier non-IPv4-mapped branch above already
    // returns on the first candidate).
    if (fallback_gid_index >= 0) {
        c->gid_index = fallback_gid_index;
        c->gid = fallback_gid;
        return true;
    }
    if (v1_non_ipv4_gid_index >= 0) {
        c->gid_index = v1_non_ipv4_gid_index;
        c->gid = v1_non_ipv4_gid;
        return true;
    }
    if (v1_fallback_gid_index >= 0) {
        c->gid_index = v1_fallback_gid_index;
        c->gid = v1_fallback_gid;
        return true;
    }

    set_err(c,
            "no usable GID found on selected RDMA port; "
            "set VGWRDMA_GID_INDEX to a valid RoCE GID index from `ibv_devinfo -v`");
    return false;
}

// build_token encodes the RDMA descriptor for the currently registered region.
//
// IMPORTANT: the exact on-wire token format is defined by the NVIDIA cuObject
// RDMA DC protocol as parsed by libcuobjserver. It is a colon-delimited,
// lowercase-hex string whose 7 fields are, in order:
//
//   # | Field                                     | Type     | Width
//   --|--------------------------------------------|----------|-----------
//   1 | Remote base address (GPUMEM/SYSMEM)         | uint64   | 16 chars
//   2 | Max size of buffer region from base addr    | uint32   | 8 chars
//   3 | Remote key (rkey)                           | uint32   | 8 chars
//   4 | LID of the client NIC                       | uint16   | 4 chars
//   5 | DCTN                                        | uint32   | 6 chars
//   6 | GID present (1|0)                           | bool     | 1 char
//   7 | GID of client NIC                           | 16 bytes | 32 chars
//
// Example: "0102030405060708:01020304:01020304:0102:010203:1:0102030405060708090a0b0c0d0e0f10"
//
// The canonical definition (consumed by the Go gateway) lives in
// cumiddleware/cuobj.go next to HeaderRDMAToken; keep the two in sync.
// Assumptions kept explicit here:
//   1) Field widths and lowercase hex formatting are strict parser contracts.
//   2) GID is serialized as the raw 16 bytes in order (no hextet splitting).
//   3) Descriptor size field is uint32; oversized buffers are rejected.
static void build_token(rdma_host_client_t *c) {
    char gid_hex[33];
    for (int i = 0; i < 16; i++) {
        snprintf(&gid_hex[i * 2], 3, "%02x", c->gid.raw[i]);
    }
    gid_hex[32] = '\0';

    char buf[320];
    snprintf(buf, sizeof(buf),
             "%016llx:%08x:%08x:%04x:%06x:%1x:%s",
             (unsigned long long)(uintptr_t)c->buf,
             static_cast<unsigned>(c->buf_len),
             c->mr ? c->mr->rkey : 0u,
             static_cast<unsigned>(c->lid),
             static_cast<unsigned>(c->dctn),
             1, // GID present (RoCE)
             gid_hex);
    c->token = buf;
}

static bool build_dct(rdma_host_client_t *c) {
    c->cq = ibv_create_cq(c->ctx, 1, nullptr, nullptr, 0);
    if (!c->cq) {
        set_err(c, "ibv_create_cq failed");
        return false;
    }

    struct ibv_srq_init_attr srq_attr;
    memset(&srq_attr, 0, sizeof(srq_attr));
    srq_attr.attr.max_wr  = 1;
    srq_attr.attr.max_sge = 1;
    c->srq = ibv_create_srq(c->pd, &srq_attr);
    if (!c->srq) {
        set_err(c, "ibv_create_srq failed");
        return false;
    }

    struct ibv_qp_init_attr_ex attr_ex;
    memset(&attr_ex, 0, sizeof(attr_ex));
    attr_ex.pd        = c->pd;
    attr_ex.send_cq   = c->cq;
    attr_ex.recv_cq   = c->cq;
    attr_ex.srq       = c->srq;
    attr_ex.qp_type   = IBV_QPT_DRIVER;
    attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;

    struct mlx5dv_qp_init_attr dv_attr;
    memset(&dv_attr, 0, sizeof(dv_attr));
    dv_attr.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_DC;
    dv_attr.dc_init_attr.dc_type         = MLX5DV_DCTYPE_DCT;
    dv_attr.dc_init_attr.dct_access_key  = c->dc_key;

    c->dct = mlx5dv_create_qp(c->ctx, &attr_ex, &dv_attr);
    if (!c->dct) {
        set_err(c, "mlx5dv_create_qp (DCT) failed");
        return false;
    }

    // INIT
    struct ibv_qp_attr qpa;
    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state        = IBV_QPS_INIT;
    qpa.pkey_index      = 0;
    qpa.port_num        = c->port_num;
    qpa.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    if (ibv_modify_qp(c->dct, &qpa,
                      IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                      IBV_QP_ACCESS_FLAGS)) {
        set_err(c, "ibv_modify_qp DCT->INIT failed");
        return false;
    }

    struct ibv_port_attr port_attr;
    memset(&port_attr, 0, sizeof(port_attr));
    if (ibv_query_port(c->ctx, c->port_num, &port_attr)) {
        set_err(c, "ibv_query_port failed");
        return false;
    }
    c->lid = port_attr.lid;

    // RTR — DCT only needs INIT->RTR (no RTS for targets).
    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state           = IBV_QPS_RTR;
    qpa.path_mtu           = port_attr.active_mtu;
    qpa.min_rnr_timer      = 12;
    qpa.ah_attr.is_global  = 1;
    qpa.ah_attr.port_num   = c->port_num;
    qpa.ah_attr.grh.hop_limit     = 4;
    qpa.ah_attr.grh.sgid_index    = (uint8_t)c->gid_index;
    qpa.ah_attr.grh.traffic_class = 0;
    if (ibv_modify_qp(c->dct, &qpa,
                      IBV_QP_STATE | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV |
                      IBV_QP_PATH_MTU)) {
        set_err(c, "ibv_modify_qp DCT->RTR failed");
        return false;
    }

    // Read DCT number after INIT->RTR is complete. Some provider paths may
    // expose qp_num late; encoding 0 here breaks remote addressing.
    c->dctn = c->dct->qp_num;
    if (c->dctn == 0) {
        set_err(c, "DCT number is zero after RTR transition");
        return false;
    }

    return true;
}

extern "C" {

rdma_host_client_t* rdma_host_client_create(const char *dev_name,
                                            uint8_t port_num,
                                            int gid_index,
                                            uint64_t dc_key) {
    auto *c = new (std::nothrow) rdma_host_client();
    if (!c) {
        return nullptr;
    }
    c->port_num  = port_num ? port_num : 1;
    c->gid_index = gid_index;
    c->dc_key    = dc_key;

    int num = 0;
    struct ibv_device **list = ibv_get_device_list(&num);
    if (!list || num == 0) {
        set_err(c, "ibv_get_device_list found no devices");
        if (list) ibv_free_device_list(list);
        return c; // return handle so caller can read last_error
    }

    struct ibv_device *dev = nullptr;
    if (dev_name && dev_name[0]) {
        for (int i = 0; i < num; i++) {
            if (strcmp(ibv_get_device_name(list[i]), dev_name) == 0) {
                dev = list[i];
                break;
            }
        }
        if (!dev) {
            set_err(c, std::string("RDMA device not found: ") + dev_name);
            ibv_free_device_list(list);
            return c;
        }
    } else {
        dev = list[0];
    }

    c->ctx = ibv_open_device(dev);
    ibv_free_device_list(list);
    if (!c->ctx) {
        set_err(c, "ibv_open_device failed");
        return c;
    }

    c->pd = ibv_alloc_pd(c->ctx);
    if (!c->pd) {
        set_err(c, "ibv_alloc_pd failed");
        return c;
    }

    if (!select_gid(c)) {
        return c;
    }

    if (!build_dct(c)) {
        return c;
    }

    c->last_error.clear();
    return c;
}

void rdma_host_client_free(rdma_host_client_t *c) {
    if (!c) {
        return;
    }
    if (c->mr) {
        ibv_dereg_mr(c->mr);
        c->mr = nullptr;
    }
    if (c->buf) {
        free(c->buf);
        c->buf = nullptr;
    }
    c->buf_len = 0;
    c->token.clear();
}

void* rdma_host_client_alloc(rdma_host_client_t *c, size_t size) {
    if (!c || size == 0) {
        return nullptr;
    }
    if (size > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        set_err(c, "requested buffer size exceeds descriptor uint32 max");
        return nullptr;
    }
    rdma_host_client_free(c);

    void *ptr = nullptr;
    if (posix_memalign(&ptr, 4096, size) != 0 || !ptr) {
        set_err(c, "posix_memalign failed");
        return nullptr;
    }
    memset(ptr, 0, size);

    struct ibv_mr *mr = ibv_reg_mr(c->pd, ptr, size,
                                   IBV_ACCESS_LOCAL_WRITE |
                                   IBV_ACCESS_REMOTE_WRITE |
                                   IBV_ACCESS_REMOTE_READ);
    if (!mr) {
        set_err(c, "ibv_reg_mr failed");
        free(ptr);
        return nullptr;
    }

    c->buf     = ptr;
    c->buf_len = size;
    c->mr      = mr;
    build_token(c);
    return ptr;
}

const char* rdma_host_client_token(rdma_host_client_t *c) {
    if (!c || c->token.empty()) {
        return nullptr;
    }
    return c->token.c_str();
}

const char* rdma_host_client_last_error(rdma_host_client_t *c) {
    if (!c || c->last_error.empty()) {
        return nullptr;
    }
    return c->last_error.c_str();
}

void rdma_host_client_destroy(rdma_host_client_t *c) {
    if (!c) {
        return;
    }
    rdma_host_client_free(c);
    if (c->dct) ibv_destroy_qp(c->dct);
    if (c->srq) ibv_destroy_srq(c->srq);
    if (c->cq)  ibv_destroy_cq(c->cq);
    if (c->pd)  ibv_dealloc_pd(c->pd);
    if (c->ctx) ibv_close_device(c->ctx);
    delete c;
}

} // extern "C"
