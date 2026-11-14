#include "rdial_wrapper.h"

#include <errno.h>
#include <arpa/inet.h>
#include <poll.h>
#include <rdma/rdma_verbs.h>
#include <stdlib.h>
#include <string.h>

struct rdial_conn {
	struct rdma_event_channel *ch;
	struct rdma_cm_id *id;
	struct ibv_pd *pd;
	struct ibv_mr *mr; /* local staging registration, or NULL */
	void *local;
	size_t local_len;
};

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait for the next CM event on ch and require it to be `want`;
 * anything else (timeouts included) is a failure. The event is
 * returned unacknowledged for the caller to ack. */
static int expect_event(struct rdma_event_channel *ch,
			enum rdma_cm_event_type want, int timeout_ms,
			struct rdma_cm_event **ev_out)
{
	struct pollfd pfd = {.fd = ch->fd, .events = POLLIN};
	struct rdma_cm_event *ev = NULL;
	int64_t deadline = now_ms() + timeout_ms;
	int r;

	for (;;) {
		int64_t left = deadline - now_ms();
		if (left <= 0)
			return -ETIMEDOUT;
		do {
			r = poll(&pfd, 1, (int)left);
		} while (r < 0 && errno == EINTR);
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
	struct sockaddr_in dst;
	struct rdma_cm_event *ev = NULL;
	int rc;

	*out = NULL;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1)
		return -EINVAL;

	ch = rdma_create_event_channel();
	if (!ch)
		return -errno;
	if (rdma_create_id(ch, &id, NULL, RDMA_PS_TCP) != 0) {
		rc = -errno;
		goto fail;
	}
	if (rdma_resolve_addr(id, NULL, (struct sockaddr *)&dst, timeout_ms) != 0) {
		rc = -errno;
		goto fail;
	}
	rc = expect_event(ch, RDMA_CM_EVENT_ADDR_RESOLVED, timeout_ms, &ev);
	if (rc != 0)
		goto fail;
	rdma_ack_cm_event(ev);
	ev = NULL;

	if (rdma_resolve_route(id, timeout_ms) != 0) {
		rc = -errno;
		goto fail;
	}
	rc = expect_event(ch, RDMA_CM_EVENT_ROUTE_RESOLVED, timeout_ms, &ev);
	if (rc != 0)
		goto fail;
	rdma_ack_cm_event(ev);
	ev = NULL;

	/* rdma_connect creates the QP on success (kernel RDMA CM). */
	if (rdma_connect(id, NULL) != 0) {
		rc = -errno;
		goto fail;
	}
	rc = expect_event(ch, RDMA_CM_EVENT_ESTABLISHED, timeout_ms, &ev);
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
	c->pd = id->pd;
	*out = c;
	return 0;

fail:
	if (ev)
		rdma_ack_cm_event(ev);
	if (id)
		rdma_destroy_id(id);
	if (ch)
		rdma_destroy_event_channel(ch);
	return rc;
}

/* Register the staging buffer for the coming local access, dropping
 * any earlier registration. Returns 0 or a negative errno. */
static int ensure_mr(struct rdial_conn *c, void *buf, size_t len)
{
	if (c->mr && (c->local != buf || c->local_len != len)) {
		ibv_dereg_mr(c->mr);
		c->mr = NULL;
	}
	if (!c->mr) {
		c->mr = ibv_reg_mr(c->pd, buf, len, IBV_ACCESS_LOCAL_WRITE);
		if (!c->mr)
			return -errno;
		c->local = buf;
		c->local_len = len;
	}
	return 0;
}

/* Post one WR and wait for its completion, bounded by timeout_ms. */
static long post_one(struct rdial_conn *c, struct ibv_qp *qp, void *local,
		     size_t len, uint32_t rkey, uint64_t remote_addr,
		     int is_write, int timeout_ms)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local,
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
	int64_t deadline = now_ms() + timeout_ms;
	int r;

	if (ibv_post_send(qp, &wr, &bad) != 0)
		return -errno;
	for (;;) {
		int64_t left = deadline - now_ms();
		if (left <= 0)
			return -ETIMEDOUT;
		do {
			r = ibv_poll_cq(c->id->recv_cq, 1, &wc);
		} while (r == 0 && now_ms() < deadline);
		if (r < 0)
			return -EIO;
		if (r == 0)
			return -ETIMEDOUT;
		if (wc.wr_id != 1)
			continue;
		if (wc.status != IBV_WC_SUCCESS)
			return -EIO;
		return (long)wc.byte_len;
	}
}

long rdial_read(struct rdial_conn *c, void *local, uint32_t rkey,
		uint64_t remote_addr, uint64_t len, int timeout_ms)
{
	if (!c || !local || len == 0 || len > UINT32_MAX)
		return -EINVAL;
	if (ensure_mr(c, local, (size_t)len) != 0)
		return -errno;
	return post_one(c, c->id->qp, local, (size_t)len, rkey, remote_addr,
			0, timeout_ms);
}

long rdial_write(struct rdial_conn *c, const void *local, uint32_t rkey,
		 uint64_t remote_addr, uint64_t len, int timeout_ms)
{
	if (!c || !local || len == 0 || len > UINT32_MAX)
		return -EINVAL;
	if (ensure_mr(c, (void *)(uintptr_t)local, (size_t)len) != 0)
		return -errno;
	return post_one(c, c->id->qp, (void *)(uintptr_t)local, (size_t)len,
			rkey, remote_addr, 1, timeout_ms);
}

void rdial_close(struct rdial_conn *c, int timeout_ms)
{
	if (!c)
		return;
	if (c->id) {
		rdma_disconnect(c->id);
		/* The DISCONNECTED event may or may not arrive in time;
		 * either way teardown proceeds when it does or when the
		 * deadline passes. */
		struct rdma_cm_event *ev = NULL;
		if (expect_event(c->ch, RDMA_CM_EVENT_DISCONNECTED, timeout_ms,
				 &ev) == 0 &&
		    ev)
			rdma_ack_cm_event(ev);
		rdma_destroy_id(c->id);
	}
	if (c->ch)
		rdma_destroy_event_channel(c->ch);
	if (c->mr)
		ibv_dereg_mr(c->mr);
	free(c);
}
