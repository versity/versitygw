//go:build !(linux && amd64 && cgo && rdma)

package rcdial

// transportAvailable is false on builds without the rdma transport.
const transportAvailable = false

// newOOBDialer reports the unsupported transport on builds without
// the rdma tag, mirroring the cm path: an oob request on such a
// build surfaces the same 501 as any other transport request.
func newOOBDialer(cfg Config) Dialer { return stubDialer{} }

type stubConn struct{}

var _ connIface = (*stubConn)(nil)

func cgoDial(ip string, port uint16, timeoutMS int) (*stubConn, error) {
	return nil, ErrUnsupportedTransport
}

func (c *stubConn) read(localLen uint64, rkey uint32, remoteAddr uint64, timeoutMS int) ([]byte, func(), error) {
	return nil, nil, ErrUnsupportedTransport
}

func (c *stubConn) write(data []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error) {
	return 0, ErrUnsupportedTransport
}

func (c *stubConn) close(timeoutMS int) {}
