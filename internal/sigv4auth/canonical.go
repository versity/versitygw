// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigv4auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	amzAlgorithmKey     = "X-Amz-Algorithm"
	amzDateKey          = "X-Amz-Date"
	amzCredentialKey    = "X-Amz-Credential"
	amzSignedHeadersKey = "X-Amz-SignedHeaders"

	authorizationHeader = "Authorization"

	hostHeader          = "host"
	contentLengthHeader = "content-length"
)

// BuildCredentialScope builds the "yyyymmdd/region/service/aws4_request"
// scope string shared by the credential, the string-to-sign, and (as the
// derivation input) DeriveKey.
func BuildCredentialScope(yyyymmdd, region, service string) string {
	return strings.Join([]string{yyyymmdd, region, service, Terminal}, "/")
}

// SigningInput is everything BuildAndSign needs to reproduce a request's
// SigV4 canonical request, string-to-sign, and signature.
type SigningInput struct {
	Method                 string
	Host                   string
	URIPath                string // raw/escaped request path; "" is treated as "/"
	Query                  url.Values
	Header                 http.Header
	ContentLength          int64
	AccessKeyID            string
	CredentialScope        string // BuildCredentialScope(yyyymmdd, region, service)
	SignedHdrs             []string
	PayloadHash            string
	SigningTime            time.Time
	DisableURIPathEscaping bool
	IsPreSign              bool
}

// SignResult carries everything BuildAndSign computed: the canonical
// request and string-to-sign (for a caller to compare against a
// client-presented signature), the signature itself, and — since
// BuildAndSign never mutates its input — every value that needs to land
// back on the wire for an outbound request to actually be signed.
// AmzDate is the formatted X-Amz-Date value used in canonicalization;
// for header auth (!IsPreSign) a caller signing a real outbound request
// must set it as a header itself (req.Header.Set("X-Amz-Date", ...)) —
// unlike a verification caller, which only ever compares Signature and
// never sends the request anywhere. RawQuery is the sorted, re-encoded
// query string in both modes when SigningInput.IsPreSign, it additionally
// carries the appended "&X-Amz-Signature=..." that makes it the final
// presigned query string — for presign, X-Amz-Date already went into
// RawQuery, so AmzDate itself needs no separate application.
// AuthorizationHeader (header-auth's full Authorization value) is only
// populated when !IsPreSign.
type SignResult struct {
	SignedHeaders       http.Header
	CanonicalString     string
	StringToSign        string
	Signature           string
	AmzDate             string
	RawQuery            string
	AuthorizationHeader string
}

// BuildAndSign rebuilds the canonical request for in the same way a SigV4
// client would have, and signs it with derivedKey — the kSigning value
// DeriveKey computes from a secret, or the equivalent value a standalone
// IAM service returns without ever revealing that secret. It never mutates
// in.Query or in.Header: verifying a request's signature must not corrupt
// the real inbound query/headers a caller still needs afterward, and
// signing a real outbound request works just as well by having the caller
// apply SignResult's output themselves. The caller compares Signature
// against the one presented on the original request; a match proves the
// request was signed by whoever holds the secret DeriveKey (or the remote
// IAM service) derived derivedKey from.
func BuildAndSign(derivedKey []byte, in SigningInput) *SignResult {
	query := cloneQuery(in.Query)
	headers := cloneHeader(in.Header)

	amzDate := in.SigningTime.Format(ISO8601Format)
	setRequiredSigningFields(headers, query, in.IsPreSign, amzDate)

	for key := range query {
		sort.Strings(query[key])
	}

	credentialStr := in.AccessKeyID + "/" + in.CredentialScope
	if in.IsPreSign {
		query.Set(amzCredentialKey, credentialStr)
	}

	unsignedHeaders := headers
	if in.IsPreSign {
		var hoisted url.Values
		hoisted, unsignedHeaders = hoistHeadersToQuery(headers)
		for k := range hoisted {
			query[k] = hoisted[k]
		}
	}

	signedHeaders, signedHeadersStr, canonicalHeaderStr := buildCanonicalHeaders(in.Host, in.SignedHdrs, unsignedHeaders, in.ContentLength)

	if in.IsPreSign {
		query.Set(amzSignedHeadersKey, signedHeadersStr)
	}

	var rawQuery strings.Builder
	rawQuery.WriteString(strings.ReplaceAll(query.Encode(), "+", "%20"))

	canonicalURI := in.URIPath
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	if !in.DisableURIPathEscaping {
		canonicalURI = escapePath(canonicalURI, false)
	}

	canonicalString := buildCanonicalString(in.Method, canonicalURI, rawQuery.String(), signedHeadersStr, canonicalHeaderStr, in.PayloadHash)
	strToSign := buildStringToSign(in.SigningTime, in.CredentialScope, canonicalString)
	signature := hex.EncodeToString(hmacSHA256(derivedKey, []byte(strToSign)))

	result := &SignResult{
		SignedHeaders:   signedHeaders,
		CanonicalString: canonicalString,
		StringToSign:    strToSign,
		Signature:       signature,
		AmzDate:         amzDate,
		RawQuery:        rawQuery.String(),
	}

	if in.IsPreSign {
		result.RawQuery += "&X-Amz-Signature=" + signature
	} else {
		result.AuthorizationHeader = buildAuthorizationHeader(credentialStr, signedHeadersStr, signature)
	}

	return result
}

func cloneQuery(q url.Values) url.Values {
	clone := make(url.Values, len(q))
	for k, v := range q {
		clone[k] = append([]string(nil), v...)
	}
	return clone
}

func cloneHeader(h http.Header) http.Header {
	clone := make(http.Header, len(h))
	for k, v := range h {
		clone[k] = append([]string(nil), v...)
	}
	return clone
}

func setRequiredSigningFields(headers http.Header, query url.Values, isPreSign bool, amzDate string) {
	if isPreSign {
		query.Set(amzAlgorithmKey, AlgorithmHMACSHA256)
		query.Set(amzDateKey, amzDate)
		return
	}
	headers[amzDateKey] = append(headers[amzDateKey][:0], amzDate)
}

// hoistHeadersToQuery splits header into the subset eligible for
// query-string hoisting on a presigned request (allowedQueryHoisting) and
// the remainder, which stays as headers.
func hoistHeadersToQuery(header http.Header) (url.Values, http.Header) {
	query := url.Values{}
	unsignedHeaders := http.Header{}
	for k, h := range header {
		if allowedQueryHoisting.IsValid(k) {
			query[k] = h
		} else {
			unsignedHeaders[k] = h
		}
	}
	return query, unsignedHeaders
}

func buildCanonicalHeaders(host string, signedHdrs []string, header http.Header, contentLength int64) (signed http.Header, signedHeadersStr, canonicalHeadersStr string) {
	signed = make(http.Header)

	var headerNames []string
	headerNames = append(headerNames, hostHeader)
	signed[hostHeader] = append(signed[hostHeader], host)

	if slices.Contains(signedHdrs, contentLengthHeader) {
		headerNames = append(headerNames, contentLengthHeader)
		signed[contentLengthHeader] = append(signed[contentLengthHeader], strconv.FormatInt(contentLength, 10))
	}

	for k, v := range header {
		if !shouldSignHeader(k, signedHdrs) {
			continue
		}
		if strings.EqualFold(k, contentLengthHeader) {
			// prevent signing the already-handled content-length header.
			continue
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signed[lowerCaseKey]; ok {
			signed[lowerCaseKey] = append(signed[lowerCaseKey], v...)
			continue
		}

		headerNames = append(headerNames, lowerCaseKey)
		signed[lowerCaseKey] = v
	}
	sort.Strings(headerNames)

	signedHeadersStr = strings.Join(headerNames, ";")

	var canonicalHeaders strings.Builder
	for _, name := range headerNames {
		if name == hostHeader {
			canonicalHeaders.WriteString(hostHeader)
			canonicalHeaders.WriteByte(':')
			canonicalHeaders.WriteString(stripExcessSpaces(host))
		} else {
			canonicalHeaders.WriteString(name)
			canonicalHeaders.WriteByte(':')
			values := signed[name]
			for j, v := range values {
				canonicalHeaders.WriteString(strings.TrimSpace(stripExcessSpaces(v)))
				if j < len(values)-1 {
					canonicalHeaders.WriteByte(',')
				}
			}
		}
		canonicalHeaders.WriteByte('\n')
	}

	return signed, signedHeadersStr, canonicalHeaders.String()
}

// shouldSignHeader reports whether header must be included in the
// canonical headers: never Authorization itself, otherwise exactly the
// headers named in signedHdrs (the client's own SignedHeaders list) when
// non-nil, else falling back to ignoredHeaders' default policy.
func shouldSignHeader(header string, signedHdrs []string) bool {
	if strings.EqualFold(header, authorizationHeader) {
		return false
	}
	if signedHdrs != nil {
		return slices.ContainsFunc(signedHdrs, func(signedHeader string) bool {
			return strings.EqualFold(signedHeader, header)
		})
	}
	return ignoredHeaders.IsValid(header)
}

func buildCanonicalString(method, uri, query, signedHeaders, canonicalHeaders, payloadHash string) string {
	return strings.Join([]string{
		method,
		uri,
		query,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
}

func buildStringToSign(t time.Time, credentialScope, canonicalRequestString string) string {
	hash := sha256.Sum256([]byte(canonicalRequestString))
	return strings.Join([]string{
		AlgorithmHMACSHA256,
		t.Format(ISO8601Format),
		credentialScope,
		hex.EncodeToString(hash[:]),
	}, "\n")
}

func buildAuthorizationHeader(credentialStr, signedHeadersStr, signature string) string {
	return AlgorithmHMACSHA256 + " Credential=" + credentialStr +
		", SignedHeaders=" + signedHeadersStr + ", Signature=" + signature
}

const doubleSpace = "  "

// stripExcessSpaces rewrites str to collapse any run of interior spaces to
// a single space, after trimming leading/trailing spaces.
func stripExcessSpaces(str string) string {
	var j, k, l, m, spaces int
	for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
	}
	for k = 0; k < j && str[k] == ' '; k++ {
	}
	str = str[k : j+1]

	j = strings.Index(str, doubleSpace)
	if j < 0 {
		return str
	}

	buf := []byte(str)
	for k, m, l = j, j, len(buf); k < l; k++ {
		if buf[k] == ' ' {
			if spaces == 0 {
				buf[m] = buf[k]
				m++
			}
			spaces++
		} else {
			spaces = 0
			buf[m] = buf[k]
			m++
		}
	}

	return string(buf[:m])
}

// escapePath URI-encodes path per SigV4's canonical-URI rules: every byte
// except unreserved characters (A-Za-z0-9-._~) is percent-encoded, and '/'
// is additionally preserved unless encodeSep is set (used for the path
// itself, never encodeSep; AWS also reuses this style of encoding for query
// keys/values, always with encodeSep).
func escapePath(path string, encodeSep bool) string {
	var buf strings.Builder
	buf.Grow(len(path))
	for i := 0; i < len(path); i++ {
		c := path[i]
		if isUnreservedByte(c) || (c == '/' && !encodeSep) {
			buf.WriteByte(c)
			continue
		}
		buf.WriteByte('%')
		buf.WriteByte(upperHex[c>>4])
		buf.WriteByte(upperHex[c&0x0f])
	}
	return buf.String()
}

const upperHex = "0123456789ABCDEF"

func isUnreservedByte(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z':
		return true
	case 'a' <= c && c <= 'z':
		return true
	case '0' <= c && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '~':
		return true
	}
	return false
}
