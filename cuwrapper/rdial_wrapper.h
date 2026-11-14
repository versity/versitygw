/* rdial: a minimal RDMA CM client for the hipobj-rc-v3 gateway path.
 *
 * The gateway dials the RC-CM listener a hipobj-rc-v3 client
 * advertises in its token, then moves one transfer over the
 * negotiated connection: an RDMA READ from the client's memory
 * region for a PUT, or an RDMA WRITE to it for a GET.
 *
 * Every wait is bounded by a millisecond deadline passed by the
 * caller, so a dead peer cannot pin a gateway handler.
 */
#ifndef HIPV3_RDIAL_H
#define HIPV3_RDIAL_H

#include <stddef.h>
#include <stdint.h>

struct rdial_conn;

/* Connect to ip:port. Returns 0 on success and stores the connection
 * in *out; returns a negative errno on failure. */
int rdial_dial(const char *ip, uint16_t port, int timeout_ms,
               struct rdial_conn **out);

/* RDMA READ len bytes from the client region (rkey, remote_addr)
 * into local. Returns len on success, negative errno on failure. */
long rdial_read(struct rdial_conn *c, void *local, uint32_t rkey,
                uint64_t remote_addr, uint64_t len, int timeout_ms);

/* RDMA WRITE len bytes from local into the client region
 * (rkey, remote_addr). Returns len on success, negative errno on
 * failure. */
long rdial_write(struct rdial_conn *c, const void *local, uint32_t rkey,
                 uint64_t remote_addr, uint64_t len, int timeout_ms);

/* Disconnect and free every resource of c. timeout_ms bounds the
 * wait for the peer's disconnect event before tearing down
 * regardless. Safe to call on a connection in any state. */
void rdial_close(struct rdial_conn *c, int timeout_ms);

#endif /* HIPV3_RDIAL_H */
