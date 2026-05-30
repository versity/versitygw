package v4

import v4Internal "github.com/versity/versitygw/aws/signer/internal/v4"

// IsRequiredSignedHeader reports whether a header must be signed when it is
// present on an incoming request.
func IsRequiredSignedHeader(header string) bool {
	return v4Internal.RequiredSignedHeaders.IsValid(header)
}

// IsIgnoredHeader reports whether a header is normally excluded from signing.
func IsIgnoredHeader(header string) bool {
	return !v4Internal.IgnoredHeaders.IsValid(header)
}
