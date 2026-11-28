//go:build !(linux && amd64 && cgo && rdma)

package rcdial

// dialerKind names the dialer a NewDialer call produced; on the
// stub build every transport resolves to the stub dialer.
func dialerKind(d Dialer) string {
	switch d.(type) {
	case stubDialer:
		return "stub"
	default:
		return "stub"
	}
}

func dialerDefaultKind() string { return "stub" }

func dialerOOBKind() string { return "stub" }

func supportedFor(kind string) bool { return kind != "stub" }
