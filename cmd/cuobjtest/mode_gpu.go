//go:build !cuobjclient_host

package main

func runModeLabel() string {
	return "real-cuda-cuobject-token"
}
