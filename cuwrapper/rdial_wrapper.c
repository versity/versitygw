#include "rdial_wrapper.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <rdma/rdma_verbs.h>
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
		if (n == -ETIMEDOUT)
			c->broken = 1;
		else
			free(staging);
		return n;
	}
	*staging_out = staging;
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
	free(c);
}
