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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/versity/versitygw/backend"
)

func TestDecodeAzMarkerToken(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		prefix     string
		delimiter  string
		wantMarker string
		wantKey    string
	}{
		{
			name:       "round trip",
			token:      encodeAzMarkerToken(azMarkerToken{Prefix: "test/", Delimiter: "/", Marker: "2!68!MDAwMDI4", LastKey: "test/a.js"}),
			prefix:     "test/",
			delimiter:  "/",
			wantMarker: "2!68!MDAwMDI4",
			wantKey:    "test/a.js",
		},
		{
			name:    "plain key from an older token or a hand written marker",
			token:   "test/a.js",
			prefix:  "test/",
			wantKey: "test/a.js",
		},
		{
			// the Azure marker belongs to the listing that produced it, so only
			// the key survives a prefix change
			name:    "prefix mismatch drops the azure marker",
			token:   encodeAzMarkerToken(azMarkerToken{Prefix: "test/", Marker: "2!68!MDAwMDI4", LastKey: "test/a.js"}),
			prefix:  "media/",
			wantKey: "test/a.js",
		},
		{
			// the last key was collapsed under the token's delimiter, so a
			// delimiter change drops the azure marker and restarts the listing
			name:      "delimiter mismatch drops the azure marker",
			token:     encodeAzMarkerToken(azMarkerToken{Prefix: "test/", Delimiter: "/", Marker: "2!68!MDAwMDI4", LastKey: "test/a.js"}),
			prefix:    "test/",
			delimiter: "",
			wantKey:   "test/a.js",
		},
		{
			name:    "corrupt token",
			token:   azTokenPrefix + "!!!not base64!!!",
			prefix:  "test/",
			wantKey: azTokenPrefix + "!!!not base64!!!",
		},
		{
			name: "empty token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marker, key := decodeAzMarkerToken(tt.token, tt.prefix, tt.delimiter)
			if marker != tt.wantMarker {
				t.Errorf("azure marker: got %q, want %q", marker, tt.wantMarker)
			}
			if key != tt.wantKey {
				t.Errorf("last key: got %q, want %q", key, tt.wantKey)
			}
		})
	}
}

func TestListBlobsPagination(t *testing.T) {
	keys := make([]string, 0, 2500)
	for i := range 2500 {
		keys = append(keys, fmt.Sprintf("test/asset-%04d.js", i))
	}

	client, srv := fakeAzureContainer(t, keys, 1000)

	var got []string
	var marker, azureMarker string
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("listing did not terminate")
		}

		res, err := (&Azure{}).listBlobs(context.Background(), client, azListingOpts{
			prefix:      "test/",
			marker:      marker,
			azureMarker: azureMarker,
			maxKeys:     1000,
		})
		if err != nil {
			t.Fatalf("list blobs: %v", err)
		}

		for _, o := range res.objects {
			got = append(got, backend.GetStringFromPtr(o.Key))
		}
		if !res.isTruncated {
			break
		}
		if len(res.objects) != 1000 {
			t.Fatalf("truncated page holds %v objects, want 1000", len(res.objects))
		}
		marker, azureMarker = res.lastKey, res.resumeMarker
	}

	if len(got) != len(keys) {
		t.Fatalf("listed %v objects, want %v", len(got), len(keys))
	}
	for i, key := range keys {
		if got[i] != key {
			t.Fatalf("object %v: got %q, want %q", i, got[i], key)
		}
	}

	// resuming from an Azure marker must keep the number of blob listings
	// linear in the number of objects
	if srv.requests > 5 {
		t.Errorf("listing took %v azure requests, want at most 5", srv.requests)
	}
}

func TestListBlobsMarkerAndDelimiter(t *testing.T) {
	keys := []string{
		"test/a/1.js",
		"test/a/2.js",
		"test/b/1.js",
		"test/root.js",
		"test/z/1.js",
	}
	client, _ := fakeAzureContainer(t, keys, 1000)

	res, err := (&Azure{}).listBlobs(context.Background(), client, azListingOpts{
		prefix:    "test/",
		delimiter: "/",
		marker:    "test/a/",
		maxKeys:   1000,
	})
	if err != nil {
		t.Fatalf("list blobs: %v", err)
	}

	var cps []string
	for _, cp := range res.commonPrefixes {
		cps = append(cps, backend.GetStringFromPtr(cp.Prefix))
	}
	if strings.Join(cps, ",") != "test/b/,test/z/" {
		t.Errorf("common prefixes: got %v, want [test/b/ test/z/]", cps)
	}
	if len(res.objects) != 1 || backend.GetStringFromPtr(res.objects[0].Key) != "test/root.js" {
		t.Errorf("objects: got %v, want [test/root.js]", res.objects)
	}
	if res.isTruncated {
		t.Error("listing reported as truncated")
	}
}

func TestListBlobsTruncatedCommonPrefixes(t *testing.T) {
	// common prefixes deliberately span Azure page boundaries so paging must
	// resume from an Azure marker and dedupe prefixes both within a page and
	// across the truncation boundary
	keys := []string{
		"test/a/1.js",
		"test/a/2.js",
		"test/b/1.js",
		"test/c/1.js",
		"test/d/1.js",
	}
	client, _ := fakeAzureContainer(t, keys, 2)

	var got []string
	var marker, azureMarker string
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("listing did not terminate")
		}

		res, err := (&Azure{}).listBlobs(context.Background(), client, azListingOpts{
			prefix:      "test/",
			delimiter:   "/",
			marker:      marker,
			azureMarker: azureMarker,
			maxKeys:     2,
		})
		if err != nil {
			t.Fatalf("list blobs: %v", err)
		}
		if len(res.objects) != 0 {
			t.Fatalf("expected no objects, got %v", res.objects)
		}

		for _, cp := range res.commonPrefixes {
			got = append(got, backend.GetStringFromPtr(cp.Prefix))
		}
		if !res.isTruncated {
			break
		}
		marker, azureMarker = res.lastKey, res.resumeMarker
	}

	want := []string{"test/a/", "test/b/", "test/c/", "test/d/"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("common prefixes: got %v, want %v", got, want)
	}
}

func TestListBlobsSkipsMultipartUploads(t *testing.T) {
	// multipart staging blobs must be filtered out before they count against
	// maxKeys, otherwise the listing would truncate early and hide real objects
	keys := []string{
		string(metaTmpMultipartPrefix) + "/upload-1/part",
		string(metaTmpMultipartPrefix) + "/upload-2/part",
		"a.js",
		"b.js",
	}
	client, _ := fakeAzureContainer(t, keys, 1000)

	res, err := (&Azure{}).listBlobs(context.Background(), client, azListingOpts{
		maxKeys: 2,
	})
	if err != nil {
		t.Fatalf("list blobs: %v", err)
	}

	var got []string
	for _, o := range res.objects {
		got = append(got, backend.GetStringFromPtr(o.Key))
	}
	if strings.Join(got, ",") != "a.js,b.js" {
		t.Errorf("objects: got %v, want [a.js b.js]", got)
	}
	if res.isTruncated {
		t.Error("listing reported as truncated; multipart blobs counted against maxKeys")
	}
}

type fakeAzureServer struct {
	requests int
}

// fakeAzureContainer serves blob listings the way Azure does: paged with opaque
// markers that only it mints, rejecting anything else with the same error real
// Azure returns for an S3 key passed as marker.
func fakeAzureContainer(t *testing.T, keys []string, pageSize int) (*container.Client, *fakeAzureServer) {
	t.Helper()

	state := &fakeAzureServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.requests++

		q := r.URL.Query()
		prefix := q.Get("prefix")

		start := 0
		if marker := q.Get("marker"); marker != "" {
			idx, err := strconv.Atoi(strings.TrimPrefix(marker, "azmarker-"))
			if !strings.HasPrefix(marker, "azmarker-") || err != nil {
				w.Header().Set("x-ms-error-code", "InvalidQueryParameterValue")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			start = idx
		}

		var matched []string
		for _, key := range keys {
			if strings.HasPrefix(key, prefix) {
				matched = append(matched, key)
			}
		}

		end := min(start+pageSize, len(matched))
		var nextMarker string
		if end < len(matched) {
			nextMarker = fmt.Sprintf("azmarker-%d", end)
		}

		var body strings.Builder
		body.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
		for _, key := range matched[start:end] {
			fmt.Fprintf(&body, `<Blob><Name>%s</Name><Properties>`+
				`<Last-Modified>Mon, 02 Jan 2006 15:04:05 GMT</Last-Modified>`+
				`<Etag>0x8DEADBEEF</Etag><Content-Length>7</Content-Length>`+
				`</Properties></Blob>`, key)
		}
		fmt.Fprintf(&body, `</Blobs><NextMarker>%s</NextMarker></EnumerationResults>`, nextMarker)

		w.Header().Set("Content-Type", "application/xml")
		//nolint:errcheck
		w.Write([]byte(body.String()))
	}))
	t.Cleanup(srv.Close)

	client, err := container.NewClientWithNoCredential(srv.URL+"/testbucket", nil)
	if err != nil {
		t.Fatalf("init container client: %v", err)
	}

	return client, state
}
