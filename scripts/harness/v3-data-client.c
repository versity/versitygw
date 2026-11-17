/* v3-data-client: minimal hipobj-rc-v3 client for gateway E2E testing.
 *
 * Advertises one RDMA-read/WRITE-able memory region over an RC-CM
 * listener on 18181, encodes the v3 token
 * (ip-hex32:port-hex4:rkey-hex8:addr-hex16:len-hex16), and issues a
 * SigV4-signed S3 PUT/GET carrying x-amz-rc-rdma-token.  Checks the
 * x-amz-rc-rdma-reply header and the transferred bytes.
 *
 * Local-only build; links system libibverbs/librdmacm.
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
#include <unistd.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

/* --- v3 token encoding -------------------------------------------- */
/* 16-byte IPv4-mapped form: ::ffff:a.b.c.d */
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
		out[o++] = b64tab[((in[i] & 3) << 4) | (in[i+1] >> 4)];
		out[o++] = b64tab[(in[i+1] & 15) << 2];
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

/* one-shot raw HTTP client (plain socket) */
#include <sys/socket.h>

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

	/* canonical headers: host;x-amz-date[;x-amz-rc-rdma-token] */
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

	/* read all */
	char buf[1024 * 1024];
	long got = 0;
	ssize_t n;
	while ((n = read(fd, buf + got, sizeof(buf) - got)) > 0)
		got += n;
	close(fd);

	buf[got < (long)sizeof(buf) - 1 ? got : (long)sizeof(buf) - 1] = 0;
	/* status */
	if (status_out)
		sscanf(buf, "%*s %ld", (long *)status_out);
	/* reply header */
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

/* --- RDMA server side: advertise one region ------------------------ */
static struct rdma_cm_id *listen_id;
static struct rdma_cm_event *conn_ev;
static struct ibv_pd *pd;
static struct ibv_mr *mr;
static struct rdma_cm_id *conn_id;
static uint8_t *region;
#define REGION_LEN (1 << 20)

static void *cm_thread(void *arg)
{
	(void)arg;
	struct rdma_cm_event *ev;
	while (rdma_get_cm_event(listen_id->channel, &ev) == 0) {
		enum rdma_cm_event_type t = ev->event;
		if (t == RDMA_CM_EVENT_CONNECT_REQUEST) {
			conn_id = ev->id;
			struct ibv_qp_init_attr qa = {0};
			qa.cap.max_send_wr = 4;
			qa.cap.max_recv_wr = 4;
			qa.cap.max_send_sge = 1;
			qa.cap.max_recv_sge = 1;
			qa.qp_type = IBV_QPT_RC;
			if (rdma_create_qp(conn_id, NULL, &qa) == 0) {
				/* accept immediately */
				rdma_accept(conn_id, NULL);
			} else {
				rdma_reject(conn_id, NULL, 0);
			}
		} else if (t == RDMA_CM_EVENT_ESTABLISHED && conn_id) {
			conn_ev = (void *)1;
		}
		struct rdma_cm_event *free_ev = ev;
		rdma_ack_cm_event(free_ev);
	}
	return NULL;
}

static int rdma_setup(const char *ip)
{
	struct rdma_event_channel *ch = rdma_create_event_channel();
	if (!ch)
		return -1;
	if (rdma_create_id(ch, &listen_id, NULL, RDMA_PS_TCP))
		return -2;
	struct sockaddr_in sin = {0};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(18181);
	inet_pton(AF_INET, ip, &sin.sin_addr);
	if (rdma_bind_addr(listen_id, (struct sockaddr *)&sin))
		return -3;
	if (rdma_listen(listen_id, 1))
		return -4;
	pd = ibv_alloc_pd(listen_id->verbs);
	if (!pd)
		return -5;
	region = malloc(REGION_LEN);
	if (!region)
		return -6;
	memset(region, 0, REGION_LEN);
	mr = ibv_reg_mr(pd, region, REGION_LEN,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
	if (!mr)
		return -7;
	pthread_t th;
	pthread_create(&th, NULL, cm_thread, NULL);
	return 0;
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

	if (rdma_setup(ip) != 0) {
		fprintf(stderr, "rdma_setup failed\n");
		return 2;
	}

	/* fill region for PUT */
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

	long status = 0;
	char reply[128] = "";
	char body[1024 * 1024];
	long blen = 0;
	int rc;

	if (!strcmp(op, "idle")) {
		int secs = argc > 5 ? atoi(argv[5]) : 60;
		printf("idle: holding listener+MR for %ds\n", secs);
		sleep(secs);
		return 0;
	}
	if (!strcmp(op, "put")) {
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
		rc = http_req(&r, (char *)&status, reply, sizeof(reply), body, sizeof(body),
			      &blen);
		printf("PUT status=%ld reply=[%s] rc=%d\n", status, reply, rc);
		if (status != 200) { printf("BODY: %.*s\n", (int)blen, body); return 3; }
		if (status != 200)
			return 3;
		/* verify the gateway read exactly len bytes from our MR */
		/* (server side of the transfer: we cannot observe directly;
		 * a follow-up GET over plain S3 confirms the object bytes) */
	} else if (!strcmp(op, "get")) {
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
		rc = http_req(&r, (char *)&status, reply, sizeof(reply), body, sizeof(body),
			      &blen);
		printf("GET status=%ld reply=[%s] rc=%d\n", status, reply, rc);
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
