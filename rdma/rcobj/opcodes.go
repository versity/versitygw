package rcobj

import (
	"net/url"
	"strings"
)

// Error codes mirrored from hipobj.h. Defined in a build-tag-free
// file so callers compare OpError codes under the cgo and stub
// builds alike.
const (
	OpSuccess            = 0
	OpInvalidValue       = 1
	OpNotInitialized     = 2
	OpAlreadyInitialized = 3
	OpRdmaError          = 4
	OpS3Error            = 5
	OpBufNotRegistered   = 6
	OpBufAlreadyReg      = 7
	OpNicNotFound        = 8
	OpDmabufNotSupported = 9
	OpSizeTooLarge       = 10
	OpInternalError      = 11
	OpNotSupported       = 12
	OpBusy               = 13
)

// escapeKeyPath percent-escapes each path segment of an object
// key, preserving the slashes that separate them. Object names may
// contain characters the URL grammar treats as syntax (query,
// fragment, percent) so raw concatenation would address a
// different object than the one named.
func escapeKeyPath(key string) string {
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// probeObjectPath builds the escaped path of the admission probe
// object.
func probeObjectPath(bucket, key string) string {
	return "/" + bucket + "/" + escapeKeyPath(key)
}
