/* v3-data-client-oob: minimal hipobj-rc-v3 client for gateway E2E
 * testing over the out-of-band transport.
 *
 * Same S3 behavior as v3-data-client.c (token emission, SigV4, the
 * x-amz-rc-rdma-token header, reply-header checks): only the
 * listener side differs. Instead of an RC-CM listener this variant
 * listens on TCP 18181, exchanges QP parameters line-based with the
 * gateway (RDIAL3 lines plus the R/D/A single bytes), and programs
 * its QP with direct ibv_modify_qp transitions. This is the client
 * half of the gateway's "oob" dialer transport, for fabrics without
 * kernel CM (the rocm-ernic emulation).
 *
 * Protocol summary (gateway is the only RDMA requester):
 *   client -> gateway:  RDIAL3 <qpn-hex8> <psn-hex6> <gid-hex32>\n
 *   gateway -> client:  RDIAL3 <qpn-hex8> <psn-hex6> <gid-hex32>\n
 *   client -> gateway:  R        (client QP is RTS)
 *   ... one RDMA READ (PUT) or WRITE (GET) ...
 *   gateway -> client:  D        (transfer completed; failure sends
 *                                  nothing and closes: EOF = fail)
 *   client -> gateway:  A        (PUT only)
 *
 * Local-only build; links system libibverbs and libcrypto.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <infiniband/verbs.h>

/* --- v3 token encoding (shared with v3-data-client.c) -------------- */
static void ip_to_v4mapped(const char *ip, uint8_t out[16])
{
	memset(out, 0, 16);
	out[10] = 0xff;
	out[11] = 0xff;
	inet_pton(AF_INET, ip, out + 12);
}

static void hex16(uint64_t v, char *out)
{
	sprintf(out, "%016lx", (unsigned long)v);
}
static void hex8(uint32_t v, char *out)
{
	sprintf(out, "%08x", v);
}
static void hex4(uint16_t v, char *out)
{
	sprintf(out, "%04x", v);
}
static void hex32(const uint8_t *b, char *out)
{
	for (int i = 0; i < 16; i++)
		sprintf(out + i * 2, "%02x", b[i]);
}

/* --- SigV4 (libcrypto) --------------------------------------------- */
#include <openssl/hmac.h>
#include <openssl/sha.h>

static void sha256_hex(const void *data, size_t len, char out[65])
{
	unsigned char h[SHA256_DIGEST_LENGTH];
	SHA256(data, len, h);
	for (int i = 0; i < 32; i++)
		sprintf(out + i * 2, "%02x", h[i]);
}

static const char *b64tab =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64(const unsigned char *in, int n, char *out)
{
	int i, o = 0;
	for (i = 0; i + 2 < n; i += 3) {
		out[o++] = b64tab[in[i] >> 2];
		out[o++] = b64tab[((in[i] & 3) << 4) | (in[i+1] >> 4)];
		out[o++] = b64tab[((in[i+1] & 15) << 2) | (in[i+2] >> 6)];
		out[o++] = b64tab[in[i+2] & 63];
	}
	int rem = n - i;
	if (rem == 1) {
		out[o++] = b64tab[in[i] >> 2];
		out[o++] = b64tab[(in[i] & 3) << 4];
		out[o++] = '=';
		out[o++] = '=';
	} else if (rem == 2) {
		out[o++] = b64tab[in[i] >> 2];
		out[o++] = b64tab[((in[i] & 15) << 4)];
		out[o++] = b64tab[((in[i+1] & 15) << 2)];
		out[o++] = '=';
	}
	out[o] = 0;
}

static void hmac(const void *key, int klen, const char *data, size_t dlen,
		 unsigned char out[32])
{
	unsigned int olen = 32;
	HMAC(EVP_sha256(), key, klen, (const unsigned char *)data, dlen, out,
	     &olen);
}

typedef struct {
	const char *host, *ak, *sk, *region, *method, *bucket, *key, *query;
	const char *tokenhdr;
	long body_len;
	const char *payload;
} s3req;

static int http_req(const s3req *r, char *status_out, char *replyhdr_out,
		    int replyhdr_cap, char *body_out, int body_cap,
		    long *body_len_out)
{
	char hosthdr[128], amzdate[32], datestamp[16];
	time_t t = time(NULL);
	struct tm tmv;
	gmtime_r(&t, &tmv);
	strftime(amzdate, sizeof(amzdate), "%Y%m%dT%H%M%SZ", &tmv);
	strftime(datestamp, sizeof(datestamp), "%Y%m%d", &tmv);

	char path[512], canonical_uri[512];
	snprintf(path, sizeof(path), "/%s/%s", r->bucket, r->key);
	strcpy(canonical_uri, path);

	char payload_sha[65];
	sha256_hex(r->payload, r->body_len, payload_sha);

	int has_tok = r->tokenhdr != NULL;
	char hostport[128];
	snprintf(hostport, sizeof(hostport), "%s:9000", r->host);
	snprintf(hosthdr, sizeof(hosthdr), "host:%s\nx-amz-date:%s\n", hostport,
		 amzdate);
	char tokline[512] = "";
	char signed_hdrs[128];
	if (has_tok) {
		snprintf(tokline, sizeof(tokline), "x-amz-rc-rdma-token:%s\n",
			 r->tokenhdr);
		strcpy(signed_hdrs, "host;x-amz-date;x-amz-rc-rdma-token");
	} else {
		strcpy(signed_hdrs, "host;x-amz-date");
	}

	char qs[64] = "";
	if (r->query && r->query[0]) {
		snprintf(qs, sizeof(qs), "?%s", r->query);
	}

	char canonical[4096];
	snprintf(canonical, sizeof(canonical),
		 "%s\n%s\n%s\n%s%s%s\n%s\n%s",
		 r->method, canonical_uri, (qs[0] ? r->query : ""),
		 hosthdr, tokline, "", signed_hdrs, payload_sha);

	char canon_sha[65];
	sha256_hex(canonical, strlen(canonical), canon_sha);

	char scope[128];
	snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", datestamp,
		 r->region);

	char str2sign[4096];
	snprintf(str2sign, sizeof(str2sign),
		 "AWS4-HMAC-SHA256\n%s\n%s\n%s", amzdate, scope, canon_sha);

	unsigned char kdate[32], kregion[32], kservice[32], ksig[32], kfin[32];
	char dbuf[64];
	snprintf(dbuf, sizeof(dbuf), "AWS4%s", r->sk);
	hmac(dbuf, strlen(dbuf), datestamp, strlen(datestamp), kdate);
	hmac(kdate, 32, r->region, strlen(r->region), kregion);
	hmac(kregion, 32, "s3", 1, kservice);
	hmac(kservice, 32, "aws4_request", 12, ksig);
	hmac(ksig, 32, str2sign, strlen(str2sign), kfin);

	char sig_hex[65], auth[1024];
	for (int i = 0; i < 32; i++)
		sprintf(sig_hex + i * 2, "%02x", kfin[i]);
	snprintf(auth, sizeof(auth),
		 "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		 r->ak, scope, signed_hdrs, sig_hex);

	char req[8192];
	int rn = snprintf(req, sizeof(req),
		"%s %s%s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"x-amz-date: %s\r\n"
		"%s%s\r\n"
		"Authorization: %s\r\n"
		"x-amz-content-sha256: %s\r\n"
		"Content-Length: %ld\r\n"
		"Connection: close\r\n\r\n",
		r->method, path, qs, hostport, amzdate,
		has_tok ? "x-amz-rc-rdma-token: " : "",
		has_tok ? r->tokenhdr : "",
		auth, payload_sha, r->body_len);

	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(9000);
	inet_pton(AF_INET, r->host, &sa.sin_addr);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(fd);
		return -2;
	}
	if (write(fd, req, rn) != rn) {
		close(fd);
		return -3;
	}
	if (r->body_len > 0 && r->payload) {
		if (write(fd, r->payload, r->body_len) != r->body_len) {
			close(fd);
			return -4;
		}
	}

	char buf[1024 * 1024];
	long got = 0;
	ssize_t n;
	while ((n = read(fd, buf + got, sizeof(buf) - got)) > 0)
		got += n;
	close(fd);

	buf[got < (long)sizeof(buf) - 1 ? got : (long)sizeof(buf) - 1] = 0;
	if (status_out)
		sscanf(buf, "%*s %ld", (long *)status_out);
	if (replyhdr_out) {
		char *p = strcasestr(buf, "\nx-amz-rc-rdma-reply:");
		if (p) {
			p += strlen("\nx-amz-rc-rdma-reply:");
			while (*p == ' ')
				p++;
			int i = 0;
			while (p[i] && p[i] != '\r' && p[i] != '\n' &&
			       i < replyhdr_cap - 1) {
				replyhdr_out[i] = p[i];
				i++;
			}
			replyhdr_out[i] = 0;
		} else {
			replyhdr_out[0] = 0;
		}
	}
	if (body_out) {
		char *b = strstr(buf, "\r\n\r\n");
		if (b) {
			b += 4;
			int len = got - (b - buf);
			if (len > body_cap - 1)
				len = body_cap - 1;
			memcpy(body_out, b, len);
			body_out[len] = 0;
			if (body_len_out)
				*body_len_out = len;
		}
	}
	return 0;
}

/* --- oob listener side ---------------------------------------------- */
static struct ibv_context *dev;
static struct ibv_pd *pd;
static struct ibv_cq *cq;
static struct ibv_qp *qp;
static struct ibv_mr *mr;
static uint8_t *region;
static int listen_fd = -1;
#define REGION_LEN (1 << 20)
#define GID_INDEX 1

static int send_all_fd(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int recv_byte_fd(int fd)
{
	unsigned char b;
	ssize_t n;

	for (;;) {
		n = read(fd, &b, 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -2; /* EOF: failure signal */
		return b;
	}
}

static int recv_line_fd(int fd, char *buf, size_t cap)
{
	size_t used = 0;
	int c;

	while ((c = recv_byte_fd(fd)) >= 0) {
		if (c == '\n') {
			buf[used] = 0;
			return 0;
		}
		if (used + 1 >= cap)
			return -3;
		if (c != '\r')
			buf[used++] = (char)c;
	}
	return c;
}

static int parse_rdial3(const char *line, uint32_t *qpn, uint32_t *psn,
			union ibv_gid *gid)
{
	char gidhex[33];
	int i, byte;

	if (sscanf(line, "RDIAL3 %*8x %6x %32[0-9a-f]", psn, gidhex) != 2)
		return -1;
	{
		unsigned long q = strtoul(line + 7, NULL, 16);

		if (q > 0xFFFFFFu)
			return -1;
		*qpn = (uint32_t)q;
	}
	if (*psn > 0xFFFFFFu)
		return -1;
	for (i = 0; i < 16; i++) {
		if (sscanf(gidhex + i * 2, "%2x", &byte) != 1)
			return -1;
		gid->raw[i] = (uint8_t)byte;
	}
	return 0;
}

/* INIT -> RTR -> RTS with the peer's parameters. Attribute set
 * matches the gateway's oob dialer and the emulator's proven
 * rdma_verify.c pattern; access flags include the remote ops
 * because this region is the RDMA target. */
static int qp_to_rts(uint32_t peer_qpn, uint32_t peer_psn,
		     const union ibv_gid *peer_gid, uint32_t my_psn)
{
	struct ibv_qp_attr a = {
		.qp_state = IBV_QPS_INIT,
		.pkey_index = 0,
		.port_num = 1,
		.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
				   IBV_ACCESS_REMOTE_READ |
				   IBV_ACCESS_REMOTE_WRITE,
	};
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
				    .sgid_index = GID_INDEX,
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

	if (ibv_modify_qp(qp, &a,
			  IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
				  IBV_QP_ACCESS_FLAGS) != 0)
		return -1;
	if (ibv_modify_qp(qp, &r,
			  IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
				  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER) != 0)
		return -1;
	return ibv_modify_qp(qp, &s,
			     IBV_QP_STATE | IBV_QP_TIMEOUT |
				     IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
				     IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
}

/* Serve one gateway connection: exchange, transitions, then wait
 * for D (success) or EOF (failure). Returns 0 on success. */
static int serve_one(int fd, int is_put)
{
	union ibv_gid my_gid, peer_gid;
	uint32_t peer_qpn, peer_psn, my_psn;
	char myline[64], peerline[64];
	int c, n;

	if (ibv_query_gid(dev, 1, GID_INDEX, &my_gid) != 0)
		return -1;
	my_psn = (uint32_t)(rand() & 0xFFFFFF);

	n = snprintf(myline, sizeof(myline),
		     "RDIAL3 %08x %06x "
		     "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		     qp->qp_num, my_psn,
		     my_gid.raw[0], my_gid.raw[1], my_gid.raw[2],
		     my_gid.raw[3], my_gid.raw[4], my_gid.raw[5],
		     my_gid.raw[6], my_gid.raw[7], my_gid.raw[8],
		     my_gid.raw[9], my_gid.raw[10], my_gid.raw[11],
		     my_gid.raw[12], my_gid.raw[13], my_gid.raw[14],
		     my_gid.raw[15]);
	if (n < 0 || (size_t)n >= sizeof(myline))
		return -1;
	if (send_all_fd(fd, myline, (size_t)n) != 0)
		return -1;
	if (recv_line_fd(fd, peerline, sizeof(peerline)) != 0)
		return -1;
	if (parse_rdial3(peerline, &peer_qpn, &peer_psn, &peer_gid) != 0)
		return -1;
	if (qp_to_rts(peer_qpn, peer_psn, &peer_gid, my_psn) != 0)
		return -1;
	if (send_all_fd(fd, "R", 1) != 0)
		return -1;

	/* The gateway posts the single RDMA operation after our R and
	 * sends D from teardown when it completed. EOF before D is the
	 * defined failure signal: do not touch the region. */
	c = recv_byte_fd(fd);
	if (c != 'D') {
		fprintf(stderr, "transfer failed (ctrl %d)\n", c);
		return -2;
	}
	if (is_put && send_all_fd(fd, "A", 1) != 0)
		return -1;
	return 0;
}

static int oob_setup(const char *ip)
{
	struct ibv_device **devlist;
	struct ibv_qp_init_attr qa = {0};
	struct sockaddr_in sin = {0};
	int one = 1;

	(void)ip;
	devlist = ibv_get_device_list(NULL);
	if (!devlist || !devlist[0]) {
		fprintf(stderr, "no verbs device\n");
		return -1;
	}
	dev = ibv_open_device(devlist[0]);
	if (!dev)
		return -1;
	pd = ibv_alloc_pd(dev);
	if (!pd)
		return -1;
	cq = ibv_create_cq(dev, 16, NULL, NULL, 0);
	if (!cq)
		return -1;
	qa.cap.max_send_wr = 4;
	qa.cap.max_recv_wr = 1;
	qa.cap.max_send_sge = 1;
	qa.cap.max_recv_sge = 1;
	qa.qp_type = IBV_QPT_RC;
	qa.send_cq = cq;
	qa.recv_cq = cq;
	qp = ibv_create_qp(pd, &qa);
	if (!qp)
		return -1;

	region = malloc(REGION_LEN);
	if (!region)
		return -1;
	memset(region, 0, REGION_LEN);
	mr = ibv_reg_mr(pd, region, REGION_LEN,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
	if (!mr)
		return -1;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return -1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(18181);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
		return -1;
	if (listen(listen_fd, 1) != 0)
		return -1;
	srand((unsigned)time(NULL));
	return 0;
}

/* Server thread: the gateway dials only after the S3 request
 * arrives, so the accept/serve loop runs concurrently with the
 * HTTP request the main thread sends. */
static volatile int serve_result;
static volatile int serve_done;

static void *serve_thread(void *arg)
{
	int is_put = *(int *)arg;
	int cfd = accept(listen_fd, NULL, NULL);

	if (cfd < 0) {
		serve_result = -1;
	} else {
		serve_result = serve_one(cfd, is_put);
		close(cfd);
	}
	serve_done = 1;
	return NULL;
}

int main(int argc, char **argv)
{
	const char *ip = argc > 1 ? argv[1] : "192.168.61.50";
	const char *op = argc > 2 ? argv[2] : "put";
	const char *bucket = argc > 3 ? argv[3] : "b1";
	const char *key = argc > 4 ? argv[4] : "k1";
	long len = argc > 5 ? atol(argv[5]) : 4096;
	const char *gw = argc > 6 ? argv[6] : "10.0.2.2";

	signal(SIGPIPE, SIG_IGN);

	if (oob_setup(ip) != 0) {
		fprintf(stderr, "oob_setup failed\n");
		return 2;
	}

	for (long i = 0; i < len && i < REGION_LEN; i++)
		region[i] = (uint8_t)(i * 7 + 3);

	char ipm[33], port[5], rk[9], addr[17], lstr[17];
	uint8_t ipb[16];
	ip_to_v4mapped(ip, ipb);
	hex32(ipb, ipm);
	hex4(18181, port);
	hex8((uint32_t)mr->rkey, rk);
	hex16((uint64_t)(uintptr_t)region, addr);
	hex16((uint64_t)len, lstr);
	char token[128];
	snprintf(token, sizeof(token), "%s:%s:%s:%s:%s", ipm, port, rk, addr,
		 lstr);
	printf("token: %s\n", token);

	int is_put = strcmp(op, "put") == 0;
	pthread_t srv;

	if (!strcmp(op, "idle")) {
		int secs = argc > 5 ? atoi(argv[5]) : 60;
		printf("idle: holding listener+MR for %ds\n", secs);
		sleep(secs);
		return 0;
	}

	/* The gateway dials during http_req, so the listener must be
	 * served by a concurrent thread. */
	if (pthread_create(&srv, NULL, serve_thread, &is_put) != 0) {
		fprintf(stderr, "serve thread failed\n");
		return 2;
	}

	long status = 0;
	char reply[128] = "";
	char body[1024 * 1024];
	long blen = 0;
	int rc;

	if (is_put) {
		s3req r = {.host = gw,
			   .ak = "hipobj-test-key",
			   .sk = "hipobj-test-secret",
			   .region = "us-east-1",
			   .method = "PUT",
			   .bucket = bucket,
			   .key = key,
			   .tokenhdr = token,
			   .body_len = 0,
			   .payload = ""};
		rc = http_req(&r, (char *)&status, reply, sizeof(reply), body,
			      sizeof(body), &blen);
		pthread_join(srv, NULL);
		printf("PUT status=%ld reply=[%s] rc=%d\n", status, reply, rc);
		if (serve_result != 0) {
			fprintf(stderr, "oob transfer failed\n");
			return 3;
		}
		if (status != 200) {
			printf("BODY: %.*s\n", (int)blen, body);
			return 3;
		}
	} else if (strcmp(op, "get") == 0) {
		s3req r = {.host = gw,
			   .ak = "hipobj-test-key",
			   .sk = "hipobj-test-secret",
			   .region = "us-east-1",
			   .method = "GET",
			   .bucket = bucket,
			   .key = key,
			   .tokenhdr = token,
			   .body_len = 0,
			   .payload = ""};
		rc = http_req(&r, (char *)&status, reply, sizeof(reply), body,
			      sizeof(body), &blen);
		pthread_join(srv, NULL);
		printf("GET status=%ld reply=[%s] rc=%d\n", status, reply, rc);
		if (serve_result != 0) {
			fprintf(stderr, "oob transfer failed\n");
			return 3;
		}
		if (status != 200)
			return 3;
		/* verify our region now contains the object bytes */
		int bad = 0;
		for (long i = 0; i < len; i++) {
			uint8_t expect = (uint8_t)(i * 5 + 11);
			if (region[i] != expect) {
				if (bad < 4)
					fprintf(stderr,
						"mismatch at %ld: got %u want %u\n",
						i, region[i], expect);
				bad++;
			}
		}
		printf("GET data check: %s (%d mismatches of %ld)\n",
		       bad ? "FAIL" : "PASS", bad, len);
		return bad ? 4 : 0;
	}
	return 0;
}
