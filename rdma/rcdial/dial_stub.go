//go:build !(linux && amd64 && cgo && rdma)

package rcdial

import "errors"

// ErrUnsupportedTransport is returned by the stub transport on
// configurations without the rdma build tag; the caller turns it into
// the 501 unsupported-transport response.
var ErrUnsupportedTransport = errors.New("rcdial: unsupported transport in this build")

type stubConn struct{}

var _ connIface = (*stubConn)(nil)

func cgoDial(ip string, port uint16, timeoutMS int) (*stubConn, error) {
	return nil, ErrUnsupportedTransport
}

func (c *stubConn) read(local []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error) {
	return 0, ErrUnsupportedTransport
}

func (c *stubConn) write(local []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error) {
	return 0, ErrUnsupportedTransport
}

func (c *stubConn) close(timeoutMS int) {}
