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

package posix

import (
	"context"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

func TestEncodeWindowsName(t *testing.T) {
	for _, test := range []struct{ key, name string }{
		{"normal.txt", "normal.txt"},
		{"plus+test %#.txt", "plus+test %#.txt"},
		{"question?.txt", "question\uf03f.txt"},
		{"asterisk*.txt", "asterisk\uf02a.txt"},
		{"中文/空 格+%?#.txt", "中文/空 格+%\uf03f#.txt"},
		{`<>:"|?*`, "\uf03c\uf03e\uf03a\uf022\uf07c\uf03f\uf02a"},
		{`back\slash`, "back\uf05cslash"},
		{`..\..\escape`, "..\uf05c..\uf05cescape"},
		{"C:drive", "C\uf03adrive"},
		{"ctrl\x01\x1f\tchar", "ctrl\uf001\uf01f\uf009char"},
		{"del\x7f", "del\x7f"},
		{"trailingdot.", "trailingdot\uf02e"},
		{"trailingspace ", "trailingspace\uf020"},
		{"dots...", "dots..\uf02e"},
		{"...", "..\uf02e"},
		{" ", "\uf020"},
		{" leadingspace", " leadingspace"},
		{"dotdir./spacedir /file", "dotdir\uf02e/spacedir\uf020/file"},
		{"dir/", "dir/"},
		{"/a//b/", "/a//b/"},
		{"./a/../b", "./a/../b"},
		{"CON", "\uf043ON"},
		{"con", "\uf063on"},
		{"nul.txt", "\uf06eul.txt"},
		{"Aux.tar.gz", "\uf041ux.tar.gz"},
		{"prn .txt", "\uf070rn .txt"},
		{"aux/x", "\uf061ux/x"},
		{"x/COM1", "x/\uf043OM1"},
		{"LPT9.log", "\uf04cPT9.log"},
		{"lpt\u00b9", "\uf06cpt\u00b9"},
		{"CONIN$", "\uf043ONIN$"},
		{"conout$.x", "\uf063onout$.x"},
		{"con ", "con\uf020"},
		{"con.", "con\uf02e"},
		{"com0", "com0"},
		{"CONSOLE", "CONSOLE"},
		{"nul?", "nul\uf03f"},
		{"pua\uf03f.txt", "pua\uf000\uf03f.txt"},
		{"\uf000", "\uf000\uf000"},
		{"\uf07f\uf080", "\uf000\uf07f\uf080"},
		{"fullwidth\uff1f", "fullwidth\uff1f"},
		{"emoji😀", "emoji😀"},
	} {
		name := encodeWindowsName(test.key, isDOSDeviceName)
		if name != test.name {
			t.Errorf("encode %+q: got %+q, want %+q", test.key, name, test.name)
		}
		if key := decodeWindowsName(name); key != test.key {
			t.Errorf("decode %+q: got %+q, want %+q", name, key, test.key)
		}
		checkWindowsName(t, name)
	}
}

func TestDecodeWindowsName(t *testing.T) {
	for _, test := range []struct{ name, key string }{
		// names Cygwin and WSL store invalid characters under
		{"a\uf03f\uf02a\uf03a\uf05c", `a?*:\`},
		{"\uf001\uf01f", "\x01\x1f"},
		// names no key is stored under
		{"a\uf000", "a\uf000"},
		{"a\uf041", "aA"},
		{"a\uf02fb", "a/b"},
		{"a\uf080", "a\uf080"},
		{"bad\xffutf8", "bad\xffutf8"},
	} {
		if key := decodeWindowsName(test.name); key != test.key {
			t.Errorf("decode %+q: got %+q, want %+q", test.name, key, test.key)
		}
	}
}

func FuzzWindowsName(f *testing.F) {
	for _, key := range []string{"a?b", "dir./CON", "x\uf000\uf03f", "nul .txt ", "a//b/./c/../"} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if !utf8.ValidString(key) || strings.ContainsRune(key, 0) {
			t.Skip("not an S3 key")
		}
		name := encodeWindowsName(key, isDOSDeviceName)
		if got := decodeWindowsName(name); got != key {
			t.Fatalf("decode(encode(%+q)) = %+q", key, got)
		}
		checkWindowsName(t, name)
	})
}

// TestWindowsNameFS checks that the bucket directory is walked over the keys,
// in the byte order of the keys, and that the entries no key is stored at
// are left out.
func TestWindowsNameFS(t *testing.T) {
	enc := func(key string) string { return encodeWindowsName(key, isDOSDeviceName) }
	fsys := fstest.MapFS{}
	for _, key := range []string{"a", "a?", "aA", "a\uf03f", "a.", "a!/x", "a*/y", "CON/z"} {
		fsys[enc(key)] = &fstest.MapFile{}
	}
	fsys["a\uf041"] = &fstest.MapFile{}    // is "aA" once decoded
	fsys["CON2\uf000"] = &fstest.MapFile{} // is "CON2\uf000\uf000" once encoded
	w := windowsNameFS{fsys: fsys, isReserved: isDOSDeviceName}

	ents, err := fs.ReadDir(w, ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ent := range ents {
		names = append(names, ent.Name())
	}
	want := []string{"CON", "a", "a!", "a*", "a.", "a?", "aA", "a\uf03f"}
	if !slices.Equal(names, want) {
		t.Errorf("read dir: got %+q, want %+q", names, want)
	}

	ents, err = fs.ReadDir(w, "CON")
	if err != nil || len(ents) != 1 || ents[0].Name() != "z" {
		t.Errorf("read dir CON: got %v, %v", ents, err)
	}
	if _, err := fs.Stat(w, "a*/y"); err != nil {
		t.Errorf("stat a*/y: %v", err)
	}
	if _, err := fs.ReadFile(w, "a?"); err != nil {
		t.Errorf("read a?: %v", err)
	}
}

// TestEncodedKeys checks that with encodeKeys every operation finds an object
// at the encoded key, that the keys are returned as they were written, and
// that no name Windows rejects or rewrites is stored. The listings are the
// ones of AWS S3 for the same keys.
func TestEncodedKeys(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		if mode == "xattr" && runtime.GOOS == "windows" {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			root, versionDir := t.TempDir(), t.TempDir()
			storer, opts := mkMeta(t)
			opts.AbsolutePaths = true
			opts.VersioningDir = versionDir
			opts.CopyObjectThreshold = 5 * 1024 * 1024 * 1024
			p, err := New(root, storer, opts)
			if err != nil {
				t.Fatalf("new posix: %v", err)
			}
			defer p.Shutdown()
			p.encodeKeys = true

			ctx := context.Background()
			bucket := "bucket"
			createTestBucket(t, p, bucket)

			keys := []string{
				"question?.txt", "中文/空 格+%?#.txt", `<>:"|`, `back\slash`, `..\..\escape`,
				"C:drive.txt", "ctrl\x01char", "trailingdot.", "trailingspace ",
				"dotdir./spacedir /file", "CON", "nul.txt", "aux/x", "pua\uf03f.txt",
				"sort/a", "sort/a.", "sort/a?", "sort/a?b", "sort/aA", "sort/a\uf03f",
				"sort/a*/y", "sort/a:z", "sort/a!", "dirobj?/",
			}
			// a directory object holds no data
			body := func(key string) string {
				if strings.HasSuffix(key, "/") {
					return ""
				}
				return key
			}
			for _, key := range keys {
				if err := putTestObject(t, p, bucket, key, body(key)); err != nil {
					t.Fatalf("put %+q: %v", key, err)
				}
			}
			for _, key := range keys {
				// the frontend always passes a range
				out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, Range: aws.String("")})
				if err != nil {
					t.Fatalf("get %+q: %v", key, err)
				}
				var data []byte
				if out.Body != nil {
					data, _ = io.ReadAll(out.Body)
					out.Body.Close()
				}
				if string(data) != body(key) {
					t.Errorf("get %+q: got %+q", key, data)
				}
			}

			sorted := slices.Clone(keys)
			slices.Sort(sorted)
			list := func(prefix, delim, startAfter string) ([]string, []string) {
				t.Helper()
				var contents, prefixes []string
				// the frontend always passes a continuation token
				token := aws.String("")
				for {
					out, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket, Prefix: &prefix, Delimiter: &delim,
						StartAfter: &startAfter, ContinuationToken: token, MaxKeys: aws.Int32(2),
					})
					if err != nil {
						t.Fatalf("list: %v", err)
					}
					for _, obj := range out.Contents {
						contents = append(contents, *obj.Key)
					}
					for _, cp := range out.CommonPrefixes {
						prefixes = append(prefixes, *cp.Prefix)
					}
					if !*out.IsTruncated {
						return contents, prefixes
					}
					token = out.NextContinuationToken
				}
			}
			checkList := func(got, want []string) {
				t.Helper()
				if !slices.Equal(got, want) {
					t.Errorf("list: got %+q, want %+q", got, want)
				}
			}
			contents, _ := list("", "", "")
			checkList(contents, sorted)
			contents, _ = list("sort/a?", "", "")
			checkList(contents, []string{"sort/a?", "sort/a?b"})
			contents, prefixes := list("sort/", "/", "")
			checkList(contents, []string{"sort/a", "sort/a!", "sort/a.", "sort/a:z", "sort/a?", "sort/a?b", "sort/aA", "sort/a\uf03f"})
			checkList(prefixes, []string{"sort/a*/"})
			contents, prefixes = list("sort/", "?", "")
			checkList(contents, []string{"sort/a", "sort/a!", "sort/a*/y", "sort/a.", "sort/a:z", "sort/aA", "sort/a\uf03f"})
			checkList(prefixes, []string{"sort/a?"})
			contents, _ = list("sort/", "", "sort/a?")
			checkList(contents, []string{"sort/a?b", "sort/aA", "sort/a\uf03f"})
			v1, err := p.ListObjects(ctx, &s3.ListObjectsInput{
				Bucket: &bucket, Prefix: aws.String("sort/"), Marker: aws.String("sort/a."), MaxKeys: aws.Int32(1000),
			})
			if err != nil {
				t.Fatalf("list v1: %v", err)
			}
			contents = nil
			for _, obj := range v1.Contents {
				contents = append(contents, *obj.Key)
			}
			checkList(contents, []string{"sort/a:z", "sort/a?", "sort/a?b", "sort/aA", "sort/a\uf03f"})

			if err := p.PutObjectTagging(ctx, bucket, "question?.txt", "", map[string]string{"k": "v"}); err != nil {
				t.Fatalf("put tagging: %v", err)
			}
			tags, err := p.GetObjectTagging(ctx, bucket, "question?.txt", "")
			if err != nil || tags["k"] != "v" {
				t.Errorf("get tagging: got %v, %v", tags, err)
			}

			copyKey := "copy*dst?."
			_, err = p.CopyObject(ctx, s3response.CopyObjectInput{
				Bucket: &bucket, Key: &copyKey, CopySource: aws.String(bucket + "/" + "question?.txt"),
				ExpectedBucketOwner: aws.String(""), MetadataDirective: types.MetadataDirectiveCopy,
			})
			if err != nil {
				t.Fatalf("copy: %v", err)
			}
			if data, _ := getTestObject(t, p, bucket, copyKey); string(data) != "question?.txt" {
				t.Errorf("get copy: got %+q", data)
			}

			mpKey := `mp?*:<>|"\.`
			mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &mpKey})
			if err != nil {
				t.Fatalf("create mp: %v", err)
			}
			uploads, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket: &bucket, Prefix: aws.String("mp?"), MaxUploads: aws.Int32(1000),
			})
			if err != nil || len(uploads.Uploads) != 1 || uploads.Uploads[0].Key != mpKey {
				t.Errorf("list mp uploads: got %+v, %v", uploads.Uploads, err)
			}
			part, err := p.UploadPart(ctx, &s3.UploadPartInput{
				Bucket: &bucket, Key: &mpKey, UploadId: &mp.UploadId, PartNumber: aws.Int32(1),
				Body: strings.NewReader("part"), ContentLength: aws.Int64(4),
			})
			if err != nil {
				t.Fatalf("upload part: %v", err)
			}
			done, _, err := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
				Bucket: &bucket, Key: &mpKey, UploadId: &mp.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: []types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag}},
				},
			})
			if err != nil || *done.Key != mpKey {
				t.Fatalf("complete mp: got %v, %v", done.Key, err)
			}
			if data, _ := getTestObject(t, p, bucket, mpKey); string(data) != "part" {
				t.Errorf("get mp object: got %+q", data)
			}

			copyPartKey := "mp2*"
			mp2, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &copyPartKey})
			if err != nil {
				t.Fatalf("create mp: %v", err)
			}
			_, err = p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
				Bucket: &bucket, Key: &copyPartKey, UploadId: &mp2.UploadId, PartNumber: aws.Int32(1),
				CopySource: aws.String(bucket + "/" + "question?.txt"), CopySourceRange: aws.String(""),
			})
			if err != nil {
				t.Fatalf("upload part copy: %v", err)
			}
			err = p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: &copyPartKey, UploadId: &mp2.UploadId})
			if err != nil {
				t.Fatalf("abort mp: %v", err)
			}

			if got := p.NormalizeObjectKey(bucket, `..\..\escape`); got != `..\..\escape` {
				t.Errorf("normalize: got %+q", got)
			}

			if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}
			if err := p.PutObjectLockConfiguration(ctx, bucket, []byte(`{"Enabled":true}`)); err != nil {
				t.Fatalf("put object lock configuration: %v", err)
			}
			lockKey := "nul.txt"
			if err := p.PutObjectLegalHold(ctx, bucket, lockKey, "", true); err != nil {
				t.Fatalf("put legal hold: %v", err)
			}
			head, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &lockKey})
			if err != nil || head.ObjectLockLegalHoldStatus != types.ObjectLockLegalHoldStatusOn {
				t.Errorf("head legal hold: got %+v, %v", head, err)
			}
			retention := []byte(`{"Mode":"GOVERNANCE"}`)
			if err := p.PutObjectRetention(ctx, bucket, lockKey, "", retention); err != nil {
				t.Fatalf("put retention: %v", err)
			}
			if got, err := p.GetObjectRetention(ctx, bucket, lockKey, ""); err != nil || string(got) != string(retention) {
				t.Errorf("get retention: got %s, %v", got, err)
			}

			vKey := "trailingdot."
			if err := putTestObject(t, p, bucket, vKey, "v2"); err != nil {
				t.Fatalf("put version: %v", err)
			}
			if _, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &vKey}); err != nil {
				t.Fatalf("delete: %v", err)
			}
			versions, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
				Bucket: &bucket, Prefix: &vKey, MaxKeys: aws.Int32(1000),
			})
			if err != nil {
				t.Fatalf("list versions: %v", err)
			}
			if len(versions.DeleteMarkers) != 1 || *versions.DeleteMarkers[0].Key != vKey || len(versions.Versions) != 2 {
				t.Fatalf("list versions: got %+v", versions)
			}
			for _, v := range versions.Versions {
				out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &vKey, VersionId: v.VersionId})
				if err != nil {
					t.Fatalf("get version: %v", err)
				}
				data, _ := io.ReadAll(out.Body)
				out.Body.Close()
				if *v.Key != vKey || (string(data) != vKey && string(data) != "v2") {
					t.Errorf("get version %v of %+q: got %+q", *v.VersionId, *v.Key, data)
				}
			}
			_, err = p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &vKey, VersionId: versions.DeleteMarkers[0].VersionId})
			if err != nil {
				t.Fatalf("delete marker: %v", err)
			}
			if data, _ := getTestObject(t, p, bucket, vKey); string(data) != "v2" {
				t.Errorf("get restored version: got %+q", data)
			}

			for _, dir := range []string{root, versionDir, opts.SideCarDir} {
				if dir == "" {
					continue
				}
				err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil || path == dir {
						return err
					}
					checkWindowsName(t, d.Name())
					return nil
				})
				if err != nil {
					t.Fatalf("walk %v: %v", dir, err)
				}
			}

			for _, key := range append(keys, copyKey, mpKey) {
				_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
				if err != nil {
					t.Errorf("delete %+q: %v", key, err)
				}
			}
		})
	}
}

// checkWindowsName fails the test if the path elements of name can't name a
// file on Windows, or on Windows 10 when not run on Windows.
func checkWindowsName(t *testing.T, name string) {
	t.Helper()
	for _, elem := range strings.Split(name, "/") {
		if elem == "" || elem == "." || elem == ".." {
			continue
		}
		if strings.ContainsFunc(elem, isInvalidWindowsChar) ||
			strings.HasSuffix(elem, ".") || strings.HasSuffix(elem, " ") ||
			isReservedName(elem) {
			t.Errorf("%+q isn't a valid Windows file name", elem)
		}
	}
}
