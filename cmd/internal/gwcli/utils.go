// Copyright 2023 Versity Software
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

package gwcli

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3response"
)

// UtilsCommand returns the "utils" subcommand, common to all versitygw
// binaries.
func UtilsCommand() *cli.Command {
	algoValues := types.ChecksumAlgorithmCrc32.Values()
	algos := make([]string, 0, len(algoValues))
	for _, a := range algoValues {
		algos = append(algos, strings.ToLower(string(a)))
	}

	return &cli.Command{
		Name:  "utils",
		Usage: "utility helper CLI tool",
		Subcommands: []*cli.Command{
			{
				Name:    "gen-event-filter-config",
				Aliases: []string{"gefc"},
				Usage:   "Create a new configuration file for bucket event notifications filter.",
				Action:  generateEventFiltersConfig,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "path",
						Usage:   "the path where the config file has to be created",
						Aliases: []string{"p"},
					},
				},
			},
			{
				Name:    "convert-xattr-metadata",
				Aliases: []string{"cxm"},
				Usage:   "Convert legacy X-Amz-Meta.* xattrs into user.metadata JSON and remove legacy keys.",
				Action:  convertXattrMetadata,
			},
			{
				Name:    "convert-posix-dataset",
				Aliases: []string{"cpd"},
				Usage:   "Make a preexisting posix dataset, not created through the gateway, usable by the posix backend.",
				Description: `Walks the posix root directory and stores the metadata the posix backend
expects on buckets and, optionally, on objects.

Every top level directory is treated as a bucket: a private bucket ACL owned by
the --access-key-id account and the BucketOwnerEnforced object ownership are
stored on it. Top level files are ignored.

With --calculate-etag and/or --checksum-algorithm every regular file within a
bucket is read once to compute the MD5 ETag and/or the FULL_OBJECT checksum of
the requested algorithm.

Existing configuration is never overwritten: a bucket attribute, object ETag or
object checksum that is already present is left as is.

Metadata is stored in extended attributes, unless --sidecar-dir is set.

WARNING: for large datasets this command can take a really long time, as it has
to visit every file in the dataset. With --calculate-etag or --checksum-algorithm
every byte of every object is read and hashed. Tune --concurrency and
--read-buffer-size for the host running the conversion.`,
				Action: convertPosixDataset,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "posix-root-dir",
						Usage:    "the posix gateway root directory holding the dataset",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "sidecar-dir",
						Usage: "store metadata in this sidecar directory instead of extended attributes; must be the same directory the gateway is run with",
					},
					&cli.StringFlag{
						Name:        "access-key-id",
						Usage:       "access key id of the account that owns the converted buckets",
						DefaultText: "the root user access key",
					},
					&cli.BoolFlag{
						Name:  "calculate-etag",
						Usage: "calculate and store the MD5 ETag of objects without one (reads every object; can take a long time on large datasets)",
					},
					&cli.StringFlag{
						Name: "checksum-algorithm",
						Usage: fmt.Sprintf("calculate and store the FULL_OBJECT checksum of objects without one, one of: %s (reads every object; can take a long time on large datasets)",
							strings.Join(algos, ", ")),
					},
					&cli.IntFlag{
						Name:        "concurrency",
						Usage:       "maximum number of objects converted concurrently",
						Value:       runtime.NumCPU(),
						DefaultText: "number of CPUs",
					},
					&cli.IntFlag{
						Name:        "read-buffer-size",
						Usage:       "per file read buffer size in bytes used for ETag and checksum calculation; peak buffer memory is concurrency * read-buffer-size",
						Value:       datasetDefaultReadBufferSize,
						DefaultText: "1048576",
					},
				},
			},
		},
	}
}

func generateEventFiltersConfig(ctx *cli.Context) error {
	pathFlag := ctx.String("path")
	path, err := filepath.Abs(filepath.Join(pathFlag, "event_config.json"))
	if err != nil {
		return err
	}

	config := s3event.EventFilter{
		s3event.EventObjectCreated:              true,
		s3event.EventObjectCreatedPut:           true,
		s3event.EventObjectCreatedPost:          true,
		s3event.EventObjectCreatedCopy:          true,
		s3event.EventCompleteMultipartUpload:    true,
		s3event.EventObjectRemoved:              true,
		s3event.EventObjectRemovedDelete:        true,
		s3event.EventObjectRemovedDeleteObjects: true,
		s3event.EventObjectTagging:              true,
		s3event.EventObjectTaggingPut:           true,
		s3event.EventObjectTaggingDelete:        true,
		s3event.EventObjectAclPut:               true,
		s3event.EventObjectRestore:              true,
		s3event.EventObjectRestorePost:          true,
		s3event.EventObjectRestoreCompleted:     true,
	}

	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("parse event config: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(configBytes)
	if err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

const (
	newMetadataAttr = "metadata"   // stored as user.metadata
	oldMetadataHdr  = "X-Amz-Meta" // legacy prefix
)

func convertXattrMetadata(ctx *cli.Context) error {
	root := strings.TrimSpace(ctx.Args().First())
	if root == "" {
		return cli.Exit("missing directory: should be provided as command argument", 2)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve directory: %w", err)
	}

	info, err := os.Stat(absRoot)
	if err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return cli.Exit(fmt.Sprintf("not a directory: %s", absRoot), 2)
	}

	xm := meta.XattrMeta{}
	err = xm.Test(absRoot)
	if err != nil {
		return err
	}

	var (
		scanned   int
		converted int
		skipped   int
		errCount  int
	)

	walkErr := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			errCount++
			// keep going
			return nil
		}

		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			errCount++
			return nil
		}
		if rel == "." {
			// skip root itself
			return nil
		}

		attrs, err := xm.ListAttributes(absRoot, rel)
		if err != nil {
			errCount++
			return nil
		}
		if len(attrs) == 0 {
			// not an s3 object, do not track as skipped
			return nil
		}

		scanned++

		// Collect legacy metadata attributes.
		oldAttrs := make([]string, 0)
		for _, a := range attrs {
			if strings.HasPrefix(a, oldMetadataHdr+".") {
				oldAttrs = append(oldAttrs, a)
			}
		}
		if len(oldAttrs) == 0 {
			skipped++
			return nil
		}

		// Build key/value map from legacy attrs.
		md := make(map[string]string, len(oldAttrs))
		for _, a := range oldAttrs {
			b, err := xm.RetrieveAttribute(nil, absRoot, rel, a)
			if err != nil {
				// If we can't read one key, don't convert this entry.
				errCount++
				return nil
			}
			key := strings.TrimPrefix(a, oldMetadataHdr+".")
			md[key] = string(b)
		}

		// Marshal to JSON and store as user.metadata.
		j, err := json.Marshal(md)
		if err != nil {
			errCount++
			return nil
		}

		if err := xm.StoreAttribute(nil, absRoot, rel, newMetadataAttr, j); err != nil {
			errCount++
			return nil
		}

		// Cleanup old metadata only after successful write of user.metadata.
		for _, a := range oldAttrs {
			if err := xm.DeleteAttribute(absRoot, rel, a); err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
				// Count, but continue cleanup attempts.
				errCount++
			}
		}

		converted++
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk directory: %w", walkErr)
	}

	fmt.Printf(
		"xattr metadata conversion is finished:\n  directory: %s\n  scanned: %d\n  converted: %d\n  skipped: %d\n  errors: %d\n",
		absRoot, scanned, converted, skipped, errCount,
	)

	return nil
}

// Metadata attribute names and reserved directories
const (
	datasetACLKey       = "acl"
	datasetOwnershipKey = "ownership"
	datasetEtagKey      = "etag"
	datasetChecksumsKey = "checksums"
	datasetMetaTmpDir   = ".sgwtmp"
	datasetObjLockDir   = ".vgwlocks"
)

const (
	// datasetLargeFileSize is the object size at and above which a warning
	// is printed before hashing, since reading the file can take a while.
	datasetLargeFileSize = 1 << 30 // 1 GiB
	// datasetDefaultReadBufferSize is the default per-file read buffer size.
	datasetDefaultReadBufferSize = 1 << 20 // 1 MiB
)

// datasetConverter stores the posix backend metadata on a preexisting
// dataset.
type datasetConverter struct {
	root         string
	ms           meta.MetadataStorer
	acl          []byte
	calcEtag     bool
	checksumAlgo types.ChecksumAlgorithm
	bufSize      int
	concurrency  int

	bucketsUpdated atomic.Int64
	bucketsSkipped atomic.Int64
	objectsUpdated atomic.Int64
	objectsSkipped atomic.Int64
	bytesHashed    atomic.Int64
	errors         atomic.Int64
}

func convertPosixDataset(ctx *cli.Context) error {
	root, err := filepath.Abs(ctx.String("posix-root-dir"))
	if err != nil {
		return fmt.Errorf("resolve posix root directory: %w", err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat posix root directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("posix root %q is not a directory", root)
	}

	access := ctx.String("access-key-id")
	if access == "" {
		access = RootUserAccess
	}
	if access == "" {
		return errors.New("bucket owner access key id is not set: provide --access-key-id or the root user access key")
	}

	concurrency := ctx.Int("concurrency")
	if concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive, got %d", concurrency)
	}
	bufSize := ctx.Int("read-buffer-size")
	if bufSize <= 0 {
		return fmt.Errorf("read buffer size must be positive, got %d", bufSize)
	}

	var checksumAlgo types.ChecksumAlgorithm
	if a := ctx.String("checksum-algorithm"); a != "" {
		for _, algo := range types.ChecksumAlgorithmCrc32.Values() {
			if strings.EqualFold(a, string(algo)) {
				checksumAlgo = algo
				break
			}
		}
		if checksumAlgo == "" {
			return fmt.Errorf("invalid checksum algorithm %q", a)
		}
	}

	var ms meta.MetadataStorer
	if sidecarDir := ctx.String("sidecar-dir"); sidecarDir != "" {
		sidecarDir, err = filepath.Abs(sidecarDir)
		if err != nil {
			return fmt.Errorf("resolve sidecar directory: %w", err)
		}
		rel, err := filepath.Rel(root, sidecarDir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("sidecar directory cannot be inside the posix root directory")
		}
		sc, err := meta.NewSideCar(sidecarDir)
		if err != nil {
			return fmt.Errorf("init sidecar metadata: %w", err)
		}
		ms = sc
	} else {
		xm := meta.XattrMeta{}
		if err := xm.Test(root); err != nil {
			return fmt.Errorf("xattr check failed: %w", err)
		}
		ms = xm.WithRootDir(root)
	}

	acl, err := auth.UpdateACL(&auth.PutBucketAclInput{
		ACL: types.BucketCannedACLPrivate,
	}, auth.ACL{Owner: access}, nil)
	if err != nil {
		return fmt.Errorf("build bucket acl: %w", err)
	}

	utils.SetBucketNameValidationStrict(!DisableStrictBucketNames)

	c := &datasetConverter{
		root:         root,
		ms:           ms,
		acl:          acl,
		calcEtag:     ctx.Bool("calculate-etag"),
		checksumAlgo: checksumAlgo,
		bufSize:      bufSize,
		concurrency:  concurrency,
	}

	err = c.run(ctx.Context)

	status := "is finished"
	if errors.Is(err, context.Canceled) {
		status = "was interrupted"
	} else if err != nil {
		status = "failed"
	}
	fmt.Printf("posix dataset conversion %s:\n"+
		"  directory: %s\n"+
		"  buckets updated: %d\n"+
		"  buckets skipped: %d\n"+
		"  objects updated: %d\n"+
		"  objects skipped: %d\n"+
		"  bytes hashed: %d\n"+
		"  errors: %d\n",
		status, root, c.bucketsUpdated.Load(), c.bucketsSkipped.Load(),
		c.objectsUpdated.Load(), c.objectsSkipped.Load(),
		c.bytesHashed.Load(), c.errors.Load())

	if err != nil {
		return err
	}
	if n := c.errors.Load(); n > 0 {
		return cli.Exit(fmt.Sprintf("posix dataset conversion finished with %d errors", n), 1)
	}
	return nil
}

func (c *datasetConverter) run(ctx context.Context) error {
	ents, err := os.ReadDir(c.root)
	if err != nil {
		return fmt.Errorf("read posix root directory: %w", err)
	}

	hashObjects := c.calcEtag || c.checksumAlgo != ""

	// jobs carries object paths relative to the root: <bucket>/<object>.
	jobs := make(chan string, c.concurrency)
	var wg sync.WaitGroup
	if hashObjects {
		for range c.concurrency {
			wg.Go(func() {
				// Each worker owns a single buffer, bounding the read
				// buffer memory to concurrency * read-buffer-size.
				var buf []byte
				for job := range jobs {
					if ctx.Err() != nil {
						// Drain the queue without converting.
						continue
					}
					if buf == nil {
						buf = make([]byte, c.bufSize)
					}
					bucket, object, _ := strings.Cut(job, string(filepath.Separator))
					err := c.convertObject(ctx, bucket, object, buf)
					if errors.Is(err, context.Canceled) {
						continue
					}
					if err != nil {
						c.errorf("object %s: %v", job, err)
					}
				}
			})
		}
	}

	for _, ent := range ents {
		if ctx.Err() != nil {
			break
		}
		// Only real directories are buckets, root level files are ignored.
		if !ent.IsDir() {
			continue
		}
		bucket := ent.Name()
		if bucket == datasetObjLockDir {
			continue
		}
		if !utils.IsValidBucketName(bucket) {
			fmt.Printf("skipping directory %q: invalid bucket name\n", bucket)
			continue
		}

		if err := c.convertBucket(bucket); err != nil {
			c.errorf("bucket %s: %v", bucket, err)
			continue
		}

		if hashObjects {
			fmt.Printf("converting objects of bucket %q\n", bucket)
			c.walkBucket(ctx, bucket, jobs)
		}
	}

	close(jobs)
	wg.Wait()

	return ctx.Err()
}

// convertBucket stores the bucket ACL and object ownership, unless already
// present.
func (c *datasetConverter) convertBucket(bucket string) error {
	updated := false
	for _, attr := range []struct {
		key   string
		value []byte
	}{
		{datasetACLKey, c.acl},
		{datasetOwnershipKey, []byte(types.ObjectOwnershipBucketOwnerEnforced)},
	} {
		exists, err := c.hasAttribute(bucket, "", attr.key)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := c.ms.StoreAttribute(nil, bucket, "", attr.key, attr.value); err != nil {
			return fmt.Errorf("store %s: %w", attr.key, err)
		}
		updated = true
	}

	if updated {
		c.bucketsUpdated.Add(1)
	} else {
		c.bucketsSkipped.Add(1)
	}
	return nil
}

// walkBucket queues every regular file in the bucket for conversion.
func (c *datasetConverter) walkBucket(ctx context.Context, bucket string, jobs chan<- string) {
	bucketPath := filepath.Join(c.root, bucket)
	err := filepath.WalkDir(bucketPath, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			c.errorf("walk %s: %v", path, err)
			return nil
		}
		if d.IsDir() {
			if d.Name() == datasetMetaTmpDir && filepath.Dir(path) == bucketPath {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks, sockets, devices, etc. are not objects.
		if !d.Type().IsRegular() {
			return nil
		}

		object, err := filepath.Rel(c.root, path)
		if err != nil {
			c.errorf("walk %s: %v", path, err)
			return nil
		}

		select {
		case jobs <- object:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		c.errorf("walk bucket %s: %v", bucket, err)
	}
}

// convertObject calculates and stores the missing ETag and checksum of an
// object, reading the file once for both.
func (c *datasetConverter) convertObject(ctx context.Context, bucket, object string, buf []byte) error {
	needEtag := false
	if c.calcEtag {
		exists, err := c.hasAttribute(bucket, object, datasetEtagKey)
		if err != nil {
			return err
		}
		needEtag = !exists
	}
	needChecksum := false
	if c.checksumAlgo != "" {
		exists, err := c.hasAttribute(bucket, object, datasetChecksumsKey)
		if err != nil {
			return err
		}
		needChecksum = !exists
	}
	if !needEtag && !needChecksum {
		c.objectsSkipped.Add(1)
		return nil
	}

	f, err := os.Open(filepath.Join(c.root, bucket, object))
	if err != nil {
		return err
	}
	defer f.Close()

	before, err := f.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		c.objectsSkipped.Add(1)
		return nil
	}
	if before.Size() >= datasetLargeFileSize {
		fmt.Printf("warning: object %s/%s is %d bytes, calculating its ETag/checksum may take a while\n",
			bucket, object, before.Size())
	}

	var md5Hash, checksumHash hash.Hash
	var dst []io.Writer
	if needEtag {
		md5Hash = md5.New()
		dst = append(dst, md5Hash)
	}
	if needChecksum {
		checksumHash, err = utils.NewHash(utils.HashType(strings.ToLower(string(c.checksumAlgo))))
		if err != nil {
			return err
		}
		dst = append(dst, checksumHash)
	}

	n, err := io.CopyBuffer(io.MultiWriter(dst...), ctxReader{ctx: ctx, r: f}, buf)
	if errors.Is(err, context.Canceled) {
		return err
	}
	if err != nil {
		return fmt.Errorf("read object data: %w", err)
	}
	c.bytesHashed.Add(n)

	after, err := f.Stat()
	if err != nil {
		return err
	}
	if n != after.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("object was modified during conversion, skipping")
	}

	// The open file is only used by xattr storage, which does not need
	// it to be writable.
	if needChecksum {
		sum := utils.Base64SumString(checksumHash.Sum(nil))
		checksum := s3response.Checksum{
			Algorithm: c.checksumAlgo,
			Type:      types.ChecksumTypeFullObject,
		}
		checksum.SetSum(c.checksumAlgo, &sum)
		value, err := json.Marshal(checksum)
		if err != nil {
			return fmt.Errorf("marshal checksum: %w", err)
		}
		if err := c.ms.StoreAttribute(f, bucket, object, datasetChecksumsKey, value); err != nil {
			return fmt.Errorf("store checksum: %w", err)
		}
	}
	if needEtag {
		etag := backend.GenerateEtag(md5Hash)
		if err := c.ms.StoreAttribute(f, bucket, object, datasetEtagKey, []byte(etag)); err != nil {
			return fmt.Errorf("store etag: %w", err)
		}
	}

	c.objectsUpdated.Add(1)
	return nil
}

func (c *datasetConverter) hasAttribute(bucket, object, attr string) (bool, error) {
	_, err := c.ms.RetrieveAttribute(nil, bucket, object, attr)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get %s: %w", attr, err)
	}
	return true, nil
}

// ctxReader stops reading once ctx is canceled, so an interrupt does not
// wait for a large file to be fully hashed. Wrapping the file also hides
// *os.File's WriterTo, so io.CopyBuffer streams through the given buffer.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr ctxReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}

func (c *datasetConverter) errorf(format string, args ...any) {
	c.errors.Add(1)
	// Metadata storers report some failures (e.g. no space left on device)
	// as S3 API errors, whose Error() is an XML document; print the
	// description instead.
	for i, arg := range args {
		err, ok := arg.(error)
		if !ok {
			continue
		}
		if s3Err, ok := errors.AsType[s3err.S3Error](err); ok {
			args[i] = strings.Replace(err.Error(), s3Err.Error(), s3Err.BaseError().Description, 1)
		}
	}
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
}
