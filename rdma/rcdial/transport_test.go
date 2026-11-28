package rcdial

import "testing"

// The transport selection matrix: every Config.Transport value must
// resolve to a dialer whose support state matches the build. The
// rdma build binds "oob" to the TCP-exchange dialer; the stub build
// reports unsupported for everything.
func TestNewDialerTransportMatrix(t *testing.T) {
	for _, tc := range []struct {
		transport string
		kind      string
	}{
		{"", dialerDefaultKind()},
		{"cm", dialerDefaultKind()},
		{"oob", dialerOOBKind()},
		{"bogus", dialerDefaultKind()},
	} {
		d := NewDialer(Config{Transport: tc.transport})
		if got := dialerKind(d); got != tc.kind {
			t.Errorf("Transport %q: dialer kind = %q, want %q",
				tc.transport, got, tc.kind)
		}
		if d.TransportSupported() != supportedFor(tc.kind) {
			t.Errorf("Transport %q: TransportSupported mismatch for kind %q",
				tc.transport, tc.kind)
		}
	}
}

// A stub build must fail an oob dial with the same error the cm
// path reports, so the adapter's 501 mapping is uniform.
func TestOOBStubDialUnsupported(t *testing.T) {
	if dialerOOBKind() != "stub" {
		t.Skip("rdma build: oob dialer is real")
	}
	d := NewDialer(Config{Transport: "oob"})
	if _, err := d.Dial(Token{}); err != ErrUnsupportedTransport {
		t.Errorf("stub oob Dial error = %v, want ErrUnsupportedTransport", err)
	}
}
