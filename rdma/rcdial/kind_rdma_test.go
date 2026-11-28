//go:build linux && amd64 && cgo && rdma

package rcdial

// dialerKind names the dialer a NewDialer call produced, so the
// transport matrix test can assert the concrete binding of each
// build without importing the cgo types into untagged code.
func dialerKind(d Dialer) string {
	switch d.(type) {
	case cmDialer:
		return "cm"
	case ooDialer:
		return "oob"
	default:
		return "stub"
	}
}

func dialerDefaultKind() string { return "cm" }

func dialerOOBKind() string { return "oob" }

func supportedFor(kind string) bool { return kind != "stub" }
