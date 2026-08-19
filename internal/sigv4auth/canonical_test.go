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
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestBuildCanonicalHeaders ports the canonical-header edge cases (leading/
// trailing/interior space stripping, multi-value merging, sort order)
func TestBuildCanonicalHeaders(t *testing.T) {
	req, err := http.NewRequest("POST", "https://mockAPI.mock-region.amazonaws.com", nil)
	if err != nil {
		t.Fatalf("failed to create request, %v", err)
	}

	req.Header.Set("FooInnerSpace", "   inner      space    ")
	req.Header.Set("FooLeadingSpace", "    leading-space")
	req.Header.Add("FooMultipleSpace", "no-space")
	req.Header.Add("FooMultipleSpace", "\ttab-space")
	req.Header.Add("FooMultipleSpace", "trailing-space    ")
	req.Header.Set("FooNoSpace", "no-space")
	req.Header.Set("FooTabSpace", "\ttab-space\t")
	req.Header.Set("FooTrailingSpace", "trailing-space    ")
	req.Header.Set("FooWrappedSpace", "   wrapped-space    ")

	signingTime := time.Date(2021, 10, 20, 12, 42, 0, 0, time.UTC)
	yyyymmdd := signingTime.Format(YYYYMMDD)
	in := SigningInputFromRequest(req)
	in.AccessKeyID = "AKID"
	in.CredentialScope = BuildCredentialScope(yyyymmdd, "mock-region", "mockAPI")
	in.SigningTime = signingTime
	result := BuildAndSign([]byte("dummy-derived-key"), in)

	expectCanonicalString := strings.Join([]string{
		`POST`,
		`/`,
		``,
		`fooinnerspace:inner space`,
		`fooleadingspace:leading-space`,
		`foomultiplespace:no-space,tab-space,trailing-space`,
		`foonospace:no-space`,
		`footabspace:tab-space`,
		`footrailingspace:trailing-space`,
		`foowrappedspace:wrapped-space`,
		`host:mockAPI.mock-region.amazonaws.com`,
		`x-amz-date:20211020T124200Z`,
		``,
		`fooinnerspace;fooleadingspace;foomultiplespace;foonospace;footabspace;footrailingspace;foowrappedspace;host;x-amz-date`,
		``,
	}, "\n")

	if result.CanonicalString != expectCanonicalString {
		t.Errorf("canonical string mismatch:\ngot:\n%s\nwant:\n%s", result.CanonicalString, expectCanonicalString)
	}
}

func TestBuildAndSignOpaqueURLAndQuerySorting(t *testing.T) {
	req, err := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com", nil)
	if err != nil {
		t.Fatalf("failed to create request, %v", err)
	}
	req.URL.Opaque = "//example.org/bucket/key-._~,!@#$%^&*()"
	req.URL.RawQuery = "Foo=z&Foo=o&Foo=m&Foo=a"

	in := SigningInputFromRequest(req)
	if want := "/bucket/key-._~,!@#$%^&*()"; in.URIPath != want {
		t.Errorf("URIPath = %q, want %q (the pre-escaped Opaque path used verbatim, not re-derived from URL.Path)", in.URIPath, want)
	}

	signingTime := time.Unix(0, 0)
	yyyymmdd := signingTime.Format(YYYYMMDD)
	in.AccessKeyID = "AKID"
	in.CredentialScope = BuildCredentialScope(yyyymmdd, "us-east-1", "dynamodb")
	in.SigningTime = signingTime
	result := BuildAndSign([]byte("dummy-derived-key"), in)

	expected := "Foo=a&Foo=m&Foo=o&Foo=z"
	if result.RawQuery != expected {
		t.Errorf("RawQuery = %q, want %q", result.RawQuery, expected)
	}
}

// TestSanitizeHostForHeader confirms a request's explicit Host takes
// precedence over URL.Host and is reflected verbatim in the canonical
// "host" header
func TestSanitizeHostForHeader(t *testing.T) {
	req, err := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com", nil)
	if err != nil {
		t.Fatalf("failed to create request, %v", err)
	}
	req.Host = "myhost"

	in := SigningInputFromRequest(req)
	signingTime := time.Now()
	yyyymmdd := signingTime.Format(YYYYMMDD)
	in.AccessKeyID = "AKID"
	in.CredentialScope = BuildCredentialScope(yyyymmdd, "us-east-1", "dynamodb")
	in.SigningTime = signingTime
	result := BuildAndSign([]byte("dummy-derived-key"), in)

	if !strings.Contains(result.CanonicalString, "host:"+req.Host) {
		t.Errorf("canonical host header invalid:\n%s", result.CanonicalString)
	}
}

// TestBuildAndSignExplicitSignedHeadersIgnoresUnsignedHeaders confirms that,
// with an explicit SignedHdrs list, extra headers present on the request
// but absent from that list never affect the resulting signature.
func TestBuildAndSignExplicitSignedHeadersIgnoresUnsignedHeaders(t *testing.T) {
	build := func(extraHeaders bool) string {
		req, err := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com", nil)
		if err != nil {
			t.Fatalf("failed to create request, %v", err)
		}
		if extraHeaders {
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("X-Unsigned-Header", "ignored")
		}

		signingTime := time.Unix(0, 0)
		yyyymmdd := signingTime.Format(YYYYMMDD)
		derivedKey := DeriveKey("SECRET", yyyymmdd, "us-east-1", "dynamodb")

		in := SigningInputFromRequest(req)
		in.AccessKeyID = "AKID"
		in.CredentialScope = BuildCredentialScope(yyyymmdd, "us-east-1", "dynamodb")
		in.SignedHdrs = []string{"host", "x-amz-date"}
		in.SigningTime = signingTime
		result := BuildAndSign(derivedKey, in)
		return result.Signature
	}

	if got, want := build(false), build(true); got != want {
		t.Errorf("unsigned headers changed the signature: %q != %q", got, want)
	}
}
