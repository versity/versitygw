// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package azure

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/versity/versitygw/s3response"
)

const testServiceURL = "https://devstoreaccount1.blob.core.windows.net/devstoreaccount1"

func testSharedKeyAzure(t *testing.T) *Azure {
	t.Helper()

	// Any valid base64 key will do: the SAS is signed and inspected locally and
	// never sent anywhere, so there is no need for a real account key.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate account key: %v", err)
	}

	cred, err := azblob.NewSharedKeyCredential("devstoreaccount1",
		base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("NewSharedKeyCredential: %v", err)
	}

	return &Azure{
		serviceURL:     testServiceURL,
		sharedkeyCreds: cred,
	}
}

// copySourceURL returns plain errors: the fallback classification is applied
// once, by its caller. Keeping it in a single place is what puts every failure
// to build a source URL on the fallback path, including the ones that only
// surface in production (GetUserDelegationCredential when the gateway identity
// lacks the Storage Blob Delegator role, or against an endpoint with no
// delegation key API).
func TestCopySourceURLErrorsAreNotPreClassified(t *testing.T) {
	az := &Azure{serviceURL: testServiceURL}

	_, err := az.copySourceURL(context.Background(), "src-bucket", "src-object")
	if err == nil {
		t.Fatal("expected an error when no credentials are configured")
	}
	if errors.Is(err, errServerSideCopyFallback) {
		t.Fatal("copySourceURL must not classify its own errors; its caller does")
	}
}

// The other half of that contract: an unsignable copy source has to reach the
// caller classified as "server-side copy unavailable", so that CopyObject falls
// back to download+reupload instead of failing the request.
func TestServerSideCopyObjectNoCredentialsFallsBack(t *testing.T) {
	az := &Azure{serviceURL: testServiceURL}

	_, err := az.serverSideCopyObject(context.Background(),
		s3response.CopyObjectInput{}, "src-bucket", "src-object", nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error when no credentials are configured")
	}
	if !errors.Is(err, errServerSideCopyFallback) {
		t.Fatalf("error must be classified as a fallback, got %v", err)
	}
}

// The MetadataDirective COPY path reads the source properties to filter the
// internal website-redirect key out of the destination metadata, so a caller
// that omits them must be turned away rather than panicking. Falling back keeps
// the copy correct, and skipping the filter instead would silently reintroduce
// the leaked redirect.
func TestServerSideCopyObjectNilSourcePropsFallsBack(t *testing.T) {
	az := testSharedKeyAzure(t)

	_, err := az.serverSideCopyObject(context.Background(),
		s3response.CopyObjectInput{}, "src-bucket", "src-object", nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error when the source properties are missing")
	}
	if !errors.Is(err, errServerSideCopyFallback) {
		t.Fatalf("error must be classified as a fallback, got %v", err)
	}
}

// The copy-source SAS has to be signed, read-only and scoped to the source
// blob. Its service version is pinned by configuration for endpoints that lag
// the SDK, and left at the SDK default otherwise; an override that silently
// stopped being applied would not fail the integration suite, because copies
// would fall back to download+reupload rather than error.
func TestCopySourceURLSharedKeySAS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
	}{
		{name: "sdk default version", version: ""},
		{name: "pinned version", version: "2025-11-05"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			az := testSharedKeyAzure(t)
			az.copySASVersion = tc.version

			got, err := az.copySourceURL(context.Background(), "src-bucket", "src-object")
			if err != nil {
				t.Fatalf("copySourceURL: %v", err)
			}

			base, query, ok := strings.Cut(got, "?")
			if !ok {
				t.Fatalf("expected a query string carrying the SAS, got %v", got)
			}
			if want := az.getBlobURL("src-bucket", "src-object"); base != want {
				t.Fatalf("expected blob URL %v, got %v", want, base)
			}

			vals, err := url.ParseQuery(query)
			if err != nil {
				t.Fatalf("ParseQuery: %v", err)
			}
			if vals.Get("sig") == "" {
				t.Error("expected a signature in the SAS")
			}
			if got := vals.Get("sp"); got != "r" {
				t.Errorf("expected read-only permissions, got %q", got)
			}
			if got := vals.Get("sr"); got != "b" {
				t.Errorf("expected a blob-scoped SAS, got %q", got)
			}

			sv := vals.Get("sv")
			if tc.version == "" {
				if sv == "" {
					t.Error("expected the SDK default service version to be filled in")
				}
				return
			}
			if sv != tc.version {
				t.Errorf("expected service version %q, got %q", tc.version, sv)
			}
		})
	}
}
