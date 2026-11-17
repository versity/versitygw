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

#include "rdial_wrapper.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <rdma/rdma_verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct rdial_conn {
	struct rdma_event_channel *ch;
	struct rdma_cm_id *id;
	struct ibv_qp *qp;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_mr *mr; /* registration of the current staging buffer */
	void *staging;     /* the buffer mr covers, or NULL */
	size_t staging_len;
	/* Set when a transfer timed out with a WR still outstanding.
	 * The verbs contract forbids touching the staged buffer (or
	 * reusing the registration) until that WR completes; the only
	 * safe continuation is teardown, which rdial_close performs
	 * by destroying the QP and flushing outstanding work before
	 * the MR is deregistered. */
	int broken;
	/* Set when the connection owns a retained staging buffer: a
	 * READ that timed out handed its allocation over because the
	 * caller can neither use nor safely free it while the WR may
	 * still be writing. rdial_close frees it after the QP and MR
	 * are gone, so nothing can reference the memory anymore. */
	int retain;
	/* oob-only fields; a CM connection keeps ctrl_fd at -1 so the
	 * teardown below never touches them. */
	int ctrl_fd; /* TCP socket carrying the oob exchange */
	int done;    /* 1 after a transfer completed successfully */
	int is_read; /* last transfer was a read (client ack expected) */
	struct ibv_context *dev; /* device opened by the oob dial */
};

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait for the next CM event on ch and require it to be `want`.
 * The deadline is absolute, so repeated EINTR cannot extend the
 * wait. The event is returned unacknowledged for the caller to
 * ack. */
static int expect_event(struct rdma_event_channel *ch,
			enum rdma_cm_event_type want, int64_t deadline_ms,
			struct rdma_cm_event **ev_out)
{
	struct pollfd pfd = {.fd = ch->fd, .events = POLLIN};
	struct rdma_cm_event *ev = NULL;
	int r;

	for (;;) {
		int64_t left = deadline_ms - now_ms();
		if (left <= 0)
			return -ETIMEDOUT;
		r = poll(&pfd, 1, (int)left);
		if (r < 0 && errno == EINTR)
			continue; /* recompute the remaining time */
		if (r < 0)
			return -errno;
		if (r == 0)
			return -ETIMEDOUT;
		if (rdma_get_cm_event(ch, &ev) != 0)
			return -errno;
		if (ev->event == want) {
			*ev_out = ev;
			return 0;
		}
		rdma_ack_cm_event(ev);
		return -ECONNREFUSED;
	}
}

int rdial_dial(const char *ip, uint16_t port, int timeout_ms,
	       struct rdial_conn **out)
{
	struct rdma_event_channel *ch = NULL;
	struct rdma_cm_id *id = NULL;
	struct rdial_conn *c = NULL;
	struct sockaddr_in dst4;
	struct sockaddr_in6 dst6;
	struct sockaddr *dst;
	struct rdma_cm_event *ev = NULL;
	struct ibv_qp_init_attr qp_init;
	int64_t deadline = now_ms() + timeout_ms;
	int rc;

	*out = NULL;
	memset(&dst4, 0, sizeof(dst4));
	memset(&dst6, 0, sizeof(dst6));

	/* Address family follows the textual form: a colon means IPv6
	 * (the gateway passes bare addresses, never port-suffixed
	 * forms); anything else must parse as IPv4. */
	if (strchr(ip, ':') != NULL) {
		dst6.sin6_family = AF_INET6;
		dst6.sin6_port = htons(port);
		if (inet_pton(AF_INET6, ip, &dst6.sin6_addr) != 1)
			return -EINVAL;
		dst = (struct sockaddr *)&dst6;
	} else {
		dst4.sin_family = AF_INET;
		dst4.sin_port = htons(port);
		if (inet_pton(AF_INET, ip, &dst4.sin_addr) != 1)
			return -EINVAL;
		dst = (struct sockaddr *)&dst4;
	}

	ch = rdma_create_event_channel();
	if (!ch)
		return -errno;
	if (rdma_create_id(ch, &id, NULL, RDMA_PS_TCP) != 0) {
		rc = -errno;
		goto fail;
	}
	if (rdma_resolve_addr(id, NULL, dst, timeout_ms) != 0) {
		rc = -errno;
		goto fail;
	}
	rc = expect_event(ch, RDMA_CM_EVENT_ADDR_RESOLVED, deadline, &ev);
	if (rc != 0)
		goto fail;
	rdma_ack_cm_event(ev);
	ev = NULL;

	if (rdma_resolve_route(id, timeout_ms) != 0) {
		rc = -errno;
		goto fail;
	}
	rc = expect_event(ch, RDMA_CM_EVENT_ROUTE_RESOLVED, deadline, &ev);
	if (rc != 0)
		goto fail;
	rdma_ack_cm_event(ev);
	ev = NULL;

	c = calloc(1, sizeof(*c));
	if (!c) {
		rc = -ENOMEM;
		goto fail;
	}
	c->ch = ch;
	c->id = id;
	/* The oob-only fields must read as "not an oob connection"
	 * everywhere; calloc gave 0, but ctrl_fd uses -1 as its
	 * "no socket" marker. */
	c->ctrl_fd = -1;

	/* The RC QP must exist before rdma_connect: connecting an id
	 * with no QP fails with EINVAL. One shared CQ serves both
	 * directions, so the send completion below polls this queue. */
	memset(&qp_init, 0, sizeof(qp_init));
	qp_init.cap.max_send_wr = 4;
	/* The provider requires a nonzero receive queue; the connection
	 * never posts receives, but a zero depth makes the driver's
	 * create-QP path dereference a NULL resource array. */
	qp_init.cap.max_recv_wr = 1;
	qp_init.cap.max_send_sge = 1;
	qp_init.cap.max_recv_sge = 1;
	qp_init.qp_type = IBV_QPT_RC;
	if (rdma_create_qp(id, NULL, &qp_init) != 0) {
		rc = -errno;
		goto fail_free;
	}
	c->qp = id->qp;
	c->cq = id->send_cq;
	c->pd = id->pd;

	if (rdma_connect(id, NULL) != 0) {
		rc = -errno;
		goto fail_conn;
	}
	rc = expect_event(ch, RDMA_CM_EVENT_ESTABLISHED, deadline, &ev);
	if (rc != 0) {
		if (ev) {
			rdma_ack_cm_event(ev);
			ev = NULL;
		}
		goto fail_conn;
	}
	rdma_ack_cm_event(ev);
	ev = NULL;

	*out = c;
	return 0;

fail_conn:
	rdma_disconnect(id);
	/* Drain the DISCONNECTED or ERROR event so destroying the id
	 * below is not blocked by an unacknowledged CM event. */
	{
		struct rdma_cm_event *dev = NULL;
		expect_event(ch, RDMA_CM_EVENT_DISCONNECTED,
			     now_ms() + timeout_ms, &dev);
		if (dev)
			rdma_ack_cm_event(dev);
	}
fail_free:
	free(c);
fail:
	if (ev)
		rdma_ack_cm_event(ev);
	if (id) {
		if (id->qp)
			rdma_destroy_qp(id);
		rdma_destroy_id(id);
	}
	if (ch)
		rdma_destroy_event_channel(ch);
	return rc;
}

/* --- out-of-band transport (no rdma_cm) ----------------------------
 *
 * On fabrics without kernel CM (the rocm-ernic emulation), the CM
 * REQ never reaches the peer. This path exchanges QP parameters
 * over the same TCP address the token advertises and programs the
 * QP with direct ibv_modify_qp calls, the pattern the emulator's
 * own verification tools use.
 */

#include <netinet/in.h>
#include <unistd.h>

#define RDIAL3_MAX 64 /* "RDIAL3 " + 8 + 1 + 6 + 1 + 32 + "\n" + slack */

/* Connect to ip:port with a nonblocking connect bounded by an
 * absolute deadline. Returns the socket fd or a negative errno. */
static int connect_tcp(const char *ip, uint16_t port, int64_t deadline_ms)
{
	struct sockaddr_in sin = {0};
	struct pollfd pfd;
	int64_t left;
	int fd, r, err;
	socklen_t elen = sizeof(err);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &sin.sin_addr) != 1)
		return -EINVAL;
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0)
		return fd;
	if (errno != EINPROGRESS) {
		err = -errno;
		close(fd);
		return err;
	}
	for (;;) {
		left = deadline_ms - now_ms();
		if (left <= 0) {
			close(fd);
			return -ETIMEDOUT;
		}
		pfd.fd = fd;
		pfd.events = POLLOUT;
		r = poll(&pfd, 1, (int)left);
		if (r < 0 && errno == EINTR)
			continue; /* recompute the remaining time */
		if (r < 0) {
			err = -errno;
			close(fd);
			return err;
		}
		if (r == 0) {
			close(fd);
			return -ETIMEDOUT;
		}
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0) {
			err = -errno;
			close(fd);
			return err;
		}
		if (err != 0) {
			close(fd);
			return -err;
		}
		return fd;
	}
}

/* Write the whole buffer, bounded by the absolute deadline. */
static int send_all(int fd, const void *buf, size_t len, int64_t deadline_ms)
{
	const char *p = buf;
	struct pollfd pfd;
	int64_t left;
	ssize_t n;

	while (len > 0) {
		left = deadline_ms - now_ms();
		if (left <= 0)
			return -ETIMEDOUT;
		pfd.fd = fd;
		pfd.events = POLLOUT;
		n = poll(&pfd, 1, (int)left);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (n == 0)
			return -ETIMEDOUT;
		n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/* Read one byte; returns it as unsigned char, or a negative errno
 * (EOF maps to -ECONNRESET: the peer closed without sending). */
static int recv_byte(int fd, int64_t deadline_ms)
{
	struct pollfd pfd;
	int64_t left;
	ssize_t n;
	unsigned char b;

	for (;;) {
		left = deadline_ms - now_ms();
		if (left <= 0)
			return -ETIMEDOUT;
		pfd.fd = fd;
		pfd.events = POLLIN;
		n = poll(&pfd, 1, (int)left);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (n == 0)
			return -ETIMEDOUT;
		n = read(fd, &b, 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -ECONNRESET;
		return b;
	}
}

/* Read one LF-terminated line into buf (NUL-terminated, LF
 * stripped). Overlong lines are rejected so a malformed peer cannot
 * run the buffer past its end. */
static int recv_line(int fd, char *buf, size_t cap, int64_t deadline_ms)
{
	size_t used = 0;
	int c;

	while ((c = recv_byte(fd, deadline_ms)) >= 0) {
		if (c == '\n') {
			buf[used] = 0;
			return 0;
		}
		if (used + 1 >= cap)
			return -ECONNABORTED;
		if (c != '\r')
			buf[used++] = (char)c;
	}
	return c;
}

/* Parse "RDIAL3 <qpn-hex8> <psn-hex6> <gid-hex32>". The GID is
 * decoded explicitly: sscanf's %x on &gid->raw would decode only
 * the first 4 bytes on some libcs. */
static int parse_rdial3(const char *line, uint32_t *qpn, uint32_t *psn,
			union ibv_gid *gid)
{
	char gidhex[33];
	int i, byte;

	if (sscanf(line, "RDIAL3 %*8x %6x %32[0-9a-f]", psn, gidhex) != 2)
		return -EINVAL;
	/* qpn is parsed separately: sscanf's %x is int-width and the
	 * qpn must be validated against the 24-bit QP number space. */
	{
		unsigned long q = strtoul(line + 7, NULL, 16);

		if (q > 0xFFFFFFu)
			return -EINVAL;
		*qpn = (uint32_t)q;
	}
	if (*psn > 0xFFFFFFu)
		return -EINVAL;
	for (i = 0; i < 16; i++) {
		if (sscanf(gidhex + i * 2, "%2x", &byte) != 1)
			return -EINVAL;
		gid->raw[i] = (uint8_t)byte;
	}
	return 0;
}

/* Create the RC QP and bring it to INIT. The caps mirror the CM
 * path: the provider requires a nonzero receive queue even though
 * the gateway never posts receives. */
static int oob_qp_create(struct ibv_pd *pd, struct ibv_cq *cq,
			 struct ibv_qp **qp)
{
	struct ibv_qp_init_attr ia = {
		.send_cq = cq,
		.recv_cq = cq,
		.cap = {.max_send_wr = 4,
			.max_recv_wr = 1,
			.max_send_sge = 1,
			.max_recv_sge = 1},
		.qp_type = IBV_QPT_RC,
	};
	struct ibv_qp_attr a = {
		.qp_state = IBV_QPS_INIT,
		.pkey_index = 0,
		.port_num = 1,
		.qp_access_flags = IBV_ACCESS_LOCAL_WRITE,
	};

	*qp = ibv_create_qp(pd, &ia);
	if (!*qp)
		return -errno;
	if (ibv_modify_qp(*qp, &a,
			  IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
				  IBV_QP_ACCESS_FLAGS) != 0) {
		int rc = -errno;

		ibv_destroy_qp(*qp);
		*qp = NULL;
		return rc;
	}
	return 0;
}

/* Transition INIT -> RTR -> RTS with the peer's parameters and the
 * attribute set the emulator's data plane was proven with
 * (tests/rdma_verify.c ep_connect). */
static int oob_qp_connect(struct ibv_qp *qp, uint32_t peer_qpn,
			  uint32_t peer_psn, const union ibv_gid *peer_gid,
			  uint32_t my_psn)
{
	struct ibv_qp_attr r = {
		.qp_state = IBV_QPS_RTR,
		.path_mtu = IBV_MTU_1024,
		.dest_qp_num = peer_qpn,
		.rq_psn = peer_psn,
		.max_dest_rd_atomic = 1,
		.min_rnr_timer = 12,
		.ah_attr = {.is_global = 1,
			    .port_num = 1,
			    .grh = {.dgid = *peer_gid,
				    .sgid_index = 1,
				    .hop_limit = 1}},
	};
	struct ibv_qp_attr s = {
		.qp_state = IBV_QPS_RTS,
		.timeout = 14,
		.retry_cnt = 7,
		.rnr_retry = 7,
		.sq_psn = my_psn,
		.max_rd_atomic = 1,
	};

	if (ibv_modify_qp(qp, &r,
			  IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
				  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER) != 0)
		return -errno;
	return ibv_modify_qp(qp, &s,
			     IBV_QP_STATE | IBV_QP_TIMEOUT |
				     IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
				     IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC) ?
		       -errno :
		       0;
}

int rdial_dial_oob(const char *ip, uint16_t port, int timeout_ms,
		   struct rdial_conn **out)
{
	struct rdial_conn *c = NULL;
	struct ibv_device **devlist = NULL;
	struct ibv_context *dev = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	union ibv_gid my_gid, peer_gid;
	char myline[RDIAL3_MAX], peerline[RDIAL3_MAX];
	uint32_t peer_qpn, peer_psn, my_psn;
	int64_t deadline = now_ms() + timeout_ms;
	int ctrl_fd = -1;
	int rc, n;
	static int seeded;

	*out = NULL;

	ctrl_fd = connect_tcp(ip, port, deadline);
	if (ctrl_fd < 0)
		return ctrl_fd;

	/* First device only: the v3 gateway runs one RDMA device, and
	 * the emulator topology advertises exactly one per guest. */
	devlist = ibv_get_device_list(NULL);
	if (!devlist || !devlist[0]) {
		rc = -ENODEV;
		goto fail;
	}
	dev = ibv_open_device(devlist[0]);
	if (!dev) {
		rc = -errno;
		goto fail;
	}
	pd = ibv_alloc_pd(dev);
	if (!pd) {
		rc = -errno;
		goto fail;
	}
	cq = ibv_create_cq(dev, 16, NULL, NULL, 0);
	if (!cq) {
		rc = -errno;
		goto fail;
	}
	rc = oob_qp_create(pd, cq, &qp);
	if (rc != 0)
		goto fail;

	/* The QP exists: its QPN can be advertised. Read the peer's
	 * parameters first so the connect transition uses them. */
	rc = recv_line(ctrl_fd, peerline, sizeof(peerline), deadline);
	if (rc != 0)
		goto fail;
	rc = parse_rdial3(peerline, &peer_qpn, &peer_psn, &peer_gid);
	if (rc != 0)
		goto fail;

	if (!seeded) {
		srand((unsigned)time(NULL));
		seeded = 1;
	}
	my_psn = (uint32_t)(rand() & 0xFFFFFF);
	if (ibv_query_gid(dev, 1, 1, &my_gid) != 0) {
		rc = -errno;
		goto fail;
	}
	rc = oob_qp_connect(qp, peer_qpn, peer_psn, &peer_gid, my_psn);
	if (rc != 0)
		goto fail;

	n = snprintf(myline, sizeof(myline), "RDIAL3 %08x %06x "
		     "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		     qp->qp_num, my_psn,
		     my_gid.raw[0], my_gid.raw[1], my_gid.raw[2],
		     my_gid.raw[3], my_gid.raw[4], my_gid.raw[5],
		     my_gid.raw[6], my_gid.raw[7], my_gid.raw[8],
		     my_gid.raw[9], my_gid.raw[10], my_gid.raw[11],
		     my_gid.raw[12], my_gid.raw[13], my_gid.raw[14],
		     my_gid.raw[15]);
	if (n < 0 || (size_t)n >= sizeof(myline)) {
		rc = -ECONNABORTED;
		goto fail;
	}
	rc = send_all(ctrl_fd, myline, (size_t)n, deadline);
	if (rc != 0)
		goto fail;

	/* The peer's R is its RTS: no RDMA operation is posted before
	 * it arrives, so a slow peer cannot burn the retry budget. */
	n = recv_byte(ctrl_fd, deadline);
	if (n != 'R') {
		rc = n < 0 ? n : -ECONNRESET;
		goto fail;
	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		rc = -ENOMEM;
		goto fail;
	}
	c->ctrl_fd = ctrl_fd;
	c->dev = dev;
	c->pd = pd;
	c->cq = cq;
	c->qp = qp;
	/* ch/id stay NULL: rdial_close branches on this. */

	*out = c;
	return 0;

fail:
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (dev)
		ibv_close_device(dev);
	if (devlist)
		ibv_free_device_list(devlist);
	if (ctrl_fd >= 0)
		close(ctrl_fd);
	return rc;
}

/* Point the connection's MR at staging, re-registering only when
 * the buffer differs from the one already covered. */
static int ensure_mr(struct rdial_conn *c, void *staging, size_t len)
{
	if (c->mr && c->staging != staging) {
		ibv_dereg_mr(c->mr);
		c->mr = NULL;
		c->staging = NULL;
		c->staging_len = 0;
	}
	if (!c->mr) {
		c->mr = ibv_reg_mr(c->pd, staging, len,
				   IBV_ACCESS_LOCAL_WRITE);
		if (!c->mr)
			return -errno;
		c->staging = staging;
		c->staging_len = len;
	}
	return 0;
}

/* Post one SIGNALED RDMA READ or WRITE and wait for its completion.
 * The staging buffer is C-owned and covered by c->mr for the whole
 * call. The single WR of known length lets the caller's count come
 * from the submitted length: providers set wc.byte_len for READ
 * completions but not portably for WRITE. */
static long post_one(struct rdial_conn *c, void *staging, size_t len,
		     uint32_t rkey, uint64_t remote_addr, int is_write,
		     int64_t deadline_ms)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)staging,
		.length = (uint32_t)len,
		.lkey = c->mr->lkey,
	};
	struct ibv_send_wr wr = {
		.wr_id = 1,
		.opcode = is_write ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ,
		.send_flags = IBV_SEND_SIGNALED,
		.sg_list = &sge,
		.num_sge = 1,
		.wr = {.rdma = {.remote_addr = remote_addr, .rkey = rkey}},
	};
	struct ibv_send_wr *bad = NULL;
	struct ibv_wc wc;
	int r;

	if (ibv_post_send(c->qp, &wr, &bad) != 0)
		return -errno;
	for (;;) {
		if (now_ms() >= deadline_ms)
			return -ETIMEDOUT;
		do {
			r = ibv_poll_cq(c->cq, 1, &wc);
		} while (r == 0 && now_ms() < deadline_ms);
		if (r < 0)
			return -EIO;
		if (r == 0)
			return -ETIMEDOUT;
		if (wc.wr_id != 1)
			continue;
		if (wc.status != IBV_WC_SUCCESS)
			return -EIO;
		return (long)len;
	}
}

long rdial_read(struct rdial_conn *c, uint32_t rkey, uint64_t remote_addr,
		uint64_t len, int timeout_ms, void **staging_out)
{
	void *staging;
	long n;

	if (!c || !staging_out || len == 0 || len > UINT32_MAX)
		return -EINVAL;
	/* A timed-out WR may still be writing into the previous
	 * staging buffer; only teardown can release it safely. */
	if (c->broken)
		return -ECANCELED;
	staging = malloc((size_t)len);
	if (!staging)
		return -ENOMEM;
	if (ensure_mr(c, staging, (size_t)len) != 0) {
		free(staging);
		return -errno;
	}
	n = post_one(c, staging, (size_t)len, rkey, remote_addr, 0,
		     now_ms() + timeout_ms);
	if (n < 0) {
		if (n == -ETIMEDOUT) {
			/* The WR may still be writing into staging; the
			 * caller can neither read nor free it. Hand the
			 * allocation to the connection, which releases
			 * it in rdial_close after the QP flush. */
			c->broken = 1;
			c->retain = 1;
		} else {
			free(staging);
		}
		return n;
	}
	*staging_out = staging;
	c->done = 1;
	c->is_read = 1;
	return n;
}

long rdial_write(struct rdial_conn *c, const void *staging, uint32_t rkey,
		 uint64_t remote_addr, uint64_t len, int timeout_ms)
{
	long n;

	if (!c || !staging || len == 0 || len > UINT32_MAX)
		return -EINVAL;
	if (c->broken)
		return -ECANCELED;
	if (ensure_mr(c, (void *)(uintptr_t)staging, (size_t)len) != 0)
		return -errno;
	n = post_one(c, (void *)(uintptr_t)staging, (size_t)len, rkey,
		     remote_addr, 1, now_ms() + timeout_ms);
	/* The staged buffer stays caller-owned; a timed-out WRITE WR
	 * may still be reading it, so the connection is marked broken
	 * rather than reporting the buffer as released. */
	if (n == -ETIMEDOUT)
		c->broken = 1;
	else if (n > 0)
		c->done = 1;
	return n;
}

void *rdial_alloc(uint64_t len)
{
	if (len == 0 || len > UINT32_MAX)
		return NULL;
	return malloc((size_t)len);
}

void rdial_free(void *staging)
{
	free(staging);
}

void rdial_close(struct rdial_conn *c, int timeout_ms)
{
	struct rdma_cm_event *ev = NULL;

	if (!c)
		return;
	if (!c->id && c->ctrl_fd >= 0) {
		/* oob teardown: announce a completed transfer (D) so the
		 * peer can release its region, or send nothing on
		 * failure; the peer reads EOF as the failure signal.
		 * A completed READ additionally waits for the peer's A:
		 * the peer holds its region until the responder-side
		 * read has drained, and the ack is what lets it go. The
		 * wait only bounds teardown; a silent peer cannot fail a
		 * transfer that already completed. */
		if (c->done && !c->broken) {
			send_all(c->ctrl_fd, "D", 1, now_ms() + timeout_ms);
			if (c->is_read)
				recv_byte(c->ctrl_fd, now_ms() + timeout_ms);
		}
		close(c->ctrl_fd);
		/* Destroy the QP before the MR: destroying flushes any
		 * work request still outstanding (a timed-out transfer
		 * on a broken connection), and only once nothing can
		 * reference the registration is it safe to deregister
		 * and let the buffer go. */
		if (c->qp)
			ibv_destroy_qp(c->qp);
		if (c->mr)
			ibv_dereg_mr(c->mr);
		if (c->pd)
			ibv_dealloc_pd(c->pd);
		if (c->cq)
			ibv_destroy_cq(c->cq);
		if (c->dev)
			ibv_close_device(c->dev);
		if (c->retain && c->staging)
			free(c->staging);
		free(c);
		return;
	}
	if (c->id) {
		rdma_disconnect(c->id);
		/* The peer's DISCONNECTED event may or may not arrive in
		 * time; teardown proceeds either way. The QP is
		 * destroyed before the MR is deregistered: destroying
		 * the QP flushes any work request still outstanding
		 * (notably a timed-out transfer on a broken connection),
		 * and only once nothing can reference the registration
		 * is it safe to deregister and let the buffer go. */
		expect_event(c->ch, RDMA_CM_EVENT_DISCONNECTED,
			     now_ms() + timeout_ms, &ev);
		if (ev)
			rdma_ack_cm_event(ev);
		if (c->id->qp)
			rdma_destroy_qp(c->id);
		if (c->mr) {
			ibv_dereg_mr(c->mr);
			c->mr = NULL;
		}
		rdma_destroy_id(c->id);
	}
	if (c->ch)
		rdma_destroy_event_channel(c->ch);
	/* A timed-out READ handed its staging over (retain); the QP
	 * flush above completed the outstanding WR, so the memory is
	 * now unreachable from the device and can be released. */
	if (c->retain && c->staging)
		free(c->staging);
	free(c);
}
