//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3lib "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/rdma/rcobj"
)

// runV2Mode drives the hipobj-rc-v2 flow through the rcobj Go
// wrapper on libhipobj: admission probe, plain PUT/GET, Range GET,
// and the multipart flow, then REST fallback verification on an
// old gateway.
func runV2Mode(size int) error {
	host, port, err := v2EndpointParts(*endpoint)
	if err != nil {
		return err
	}
	_ = host
	_ = port

	probeKey := *key + "-probe"
	if err := v2EnsureProbeObject(host, port, probeKey); err != nil {
		return fmt.Errorf("probe object: %w", err)
	}

	// v2 client: libhipobj owns the RDMA data plane; the control
	// callbacks live inside the wrapper.
	cl, err := rcobj.Init(rcobj.Config{
		ControlEndpoint:     "http://" + host + ":" + fmt.Sprint(port),
		NicHint:             os.Getenv("VGWRDMA_RDMA_GID_HINT"),
		ConnectDeadlineMs:   10000,
		TransferDeadlineMs:  60000,
		CancelCleanupBudget: 1000,
		Credentials: rcobj.Credentials{
			AccessKey: *access,
			SecretKey: *secret,
			Region:    *region,
		},
		Region:      *region,
		ProbeBucket: *bucket,
		ProbeKey:    probeKey,
	})
	if err != nil {
		return fmt.Errorf("rcobj init: %w", err)
	}
	defer cl.Shutdown()

	// Host memory is registered through the library's host-MR
	// path; the v2 entry points require a registered buffer.
	// The transfer payload lives in device memory: v2 transfers
	// require a device-backed MR, so the staging bytes are
	// generated on the host and copied up through the HIP runtime.
	hostPayload := make([]byte, size)
	if _, err := readRandom(hostPayload); err != nil {
		return fmt.Errorf("fill PUT buffer: %w", err)
	}
	putBufGlobal = hostPayload
	putAlloc, err := rcobj.VallocDev(size)
	if err != nil {
		return fmt.Errorf("alloc PUT device buffer: %w", err)
	}
	if err := rcobj.CopyDevHostToDev(putAlloc, hostPayload); err != nil {
		_ = rcobj.FreeDev(putAlloc)
		return fmt.Errorf("stage PUT payload: %w", err)
	}
	if err := cl.RegisterBuffer(putAlloc, uint64(size)); err != nil {
		_ = rcobj.FreeDev(putAlloc)
		return fmt.Errorf("register: %w", err)
	}
	// releasePut frees the buffer only after a successful
	// deregistration; a pinned registration keeps the allocation
	// alive and reports the failure.
	releasePut := func() error {
		if err := cl.DeregisterBuffer(putAlloc); err != nil {
			return fmt.Errorf("deregister PUT buffer: %w (buffer kept)", err)
		}
		if err := rcobj.FreeDev(putAlloc); err != nil {
			return fmt.Errorf("free PUT device buffer: %w", err)
		}
		return nil
	}

	results := []v2Result{}
	restBase := newS3Client(*endpoint, *access, *secret, *region)

	// 1. Plain PUT
	r := v2Result{step: "PUT"}
	r.dur, r.bytes, r.err = v2DoTransfer(cl, opPut,
		putAlloc, 0, uint64(size), "", *key, func() error {
			return restPutObj(restBase, *key, hostPayload)
		})
	results = append(results, r)

	// 2. Plain GET (full): device buffer, staged down for compare.
	getAlloc, gerr := rcobj.VallocDev(size)
	if gerr != nil {
		return fmt.Errorf("alloc GET device buffer: %w", gerr)
	}
	if err := cl.RegisterBuffer(getAlloc, uint64(size)); err != nil {
		_ = rcobj.FreeDev(getAlloc)
		return fmt.Errorf("register GET buffer: %w", err)
	}
	releaseGet := func() error {
		if err := cl.DeregisterBuffer(getAlloc); err != nil {
			return fmt.Errorf("deregister GET buffer: %w (buffer kept)", err)
		}
		if err := rcobj.FreeDev(getAlloc); err != nil {
			return fmt.Errorf("free GET device buffer: %w", err)
		}
		return nil
	}

	if r.err == nil {
		r = v2Result{step: "GET"}
		r.dur, r.bytes, r.err = v2DoTransfer(cl, opGet,
			getAlloc, 0, uint64(size), "", *key, func() error {
				return restGetObj(restBase, *key, putBufGlobal)
			})
		if r.err == nil {
			got := make([]byte, size)
			if cerr := rcobj.CopyDevDevToHost(got, getAlloc); cerr != nil {
				r.err = fmt.Errorf("stage down GET result: %w", cerr)
			} else {
				r.byteMatch = string(putBufGlobal) == string(got)
				if !r.byteMatch {
					r.firstDiff = -1
					for i := 0; i < len(putBufGlobal); i++ {
						if putBufGlobal[i] != got[i] {
							r.firstDiff = i
							r.gotByte = got[i]
							r.wantByte = putBufGlobal[i]
							break
						}
					}
					r.err = fmt.Errorf("GET bytes mismatch")
				}
			}
		}
		results = append(results, r)
	}

	// 3. Range GET at a non-zero offset
	rangeOffset := uint64(size / 4)
	rangeSize := uint64(size / 2)
	if r.err == nil && rangeOffset > 0 && rangeSize > 0 {
		rgAlloc, rgerr := rcobj.VallocDev(int(rangeSize))
		if rgerr != nil {
			return fmt.Errorf("alloc Range device buffer: %w", rgerr)
		}
		if err := cl.RegisterBuffer(rgAlloc, rangeSize); err != nil {
			_ = rcobj.FreeDev(rgAlloc)
			return fmt.Errorf("register Range buffer: %w", err)
		}
		r = v2Result{step: fmt.Sprintf("GET+Range@%d", rangeOffset)}
		r.dur, r.bytes, r.err = v2DoTransfer(cl, opGet,
			rgAlloc, rangeOffset, rangeSize, "", *key, func() error {
				return restGetRange(restBase, *key,
					rangeOffset, rangeSize, putBufGlobal[rangeOffset:rangeOffset+rangeSize])
			})
		if r.err == nil {
			got := make([]byte, rangeSize)
			if cerr := rcobj.CopyDevDevToHost(got, rgAlloc); cerr != nil {
				r.err = fmt.Errorf("stage down Range result: %w", cerr)
			} else {
				want := putBufGlobal[rangeOffset : rangeOffset+rangeSize]
				r.byteMatch = string(want) == string(got)
				if !r.byteMatch {
					r.firstDiff = -1
					for i := 0; i < len(want); i++ {
						if want[i] != got[i] {
							r.firstDiff = i
							r.gotByte = got[i]
							r.wantByte = want[i]
							break
						}
					}
					r.err = fmt.Errorf("Range GET bytes mismatch")
				}
			}
		}
		results = append(results, r)
		// The buffer may only be freed once the registration is
		// gone: a failed deregistration can leave the memory pinned
		// for DMA, so that failure is reported and the allocation
		// is preserved.
		if derr := cl.DeregisterBuffer(rgAlloc); derr != nil {
			return fmt.Errorf("deregister Range buffer: %w (buffer kept)", derr)
		}
		if ferr := rcobj.FreeDev(rgAlloc); ferr != nil {
			return fmt.Errorf("free Range device buffer: %w", ferr)
		}
	}

	ok := true
	for _, res := range results {
		status := "OK"
		if res.err != nil {
			status = "FAIL: " + res.err.Error()
			ok = false
		}
		match := ""
		if res.step != "PUT" {
			if res.byteMatch {
				match = " bytes=match"
			} else {
				match = " bytes=MISMATCH"
				if res.firstDiff >= 0 {
					match += fmt.Sprintf(" at off=%d (got %02x want %02x)",
						res.firstDiff, res.gotByte, res.wantByte)
				}
			}
		}
		fmt.Printf("  %-18s %10s %8d B  %s%s\n", res.step,
			res.dur.Round(time.Millisecond), res.bytes, status, match)
	}

	// 4. Multipart: REST create -> v2 UploadPart x2 -> REST
	// complete -> full GET verifies the assembled bytes.
	mpOK, mpErr := v2Multipart(cl, size)
	fmt.Printf("  %-18s %10s %8d B  %s\n", "multipart",
		"", size, ternStr(mpErr == nil && mpOK, "OK", "FAIL: "+errStr(mpErr)))
	if mpErr != nil || !mpOK {
		ok = false
	}

	if !ok {
		if err := releasePut(); err != nil {
			fmt.Printf("  cleanup: %v\n", err)
		}
		if err := releaseGet(); err != nil {
			fmt.Printf("  cleanup: %v\n", err)
		}
		return fmt.Errorf("v2 mode had failures")
	}
	var cleanupErr error
	if err := releasePut(); err != nil {
		cleanupErr = err
	}
	if err := releaseGet(); err != nil {
		cleanupErr = err
	}
	if cleanupErr != nil {
		return fmt.Errorf("v2 mode cleanup: %w", cleanupErr)
	}
	fmt.Printf("\nv2 mode: all steps green\n")
	return nil
}

const (
	opGet = 0
	opPut = 1
)

// v2DoTransfer runs one v2 transfer through the rcobj wrapper. The
// query string carries the part context for multipart uploads.
// key names the object this transfer addresses; the multipart flow
// passes its own key so parts land on the upload's object.
func v2DoTransfer(cl *rcobj.Client, op int,
	buf unsafe.Pointer, offset, size uint64, query, key string,
	rest func() error) (time.Duration, int, error) {

	start := time.Now()
	name := opName(op)
	var err error
	if op == opPut {
		err = cl.Put(*bucket, key, buf, size, offset, query)
	} else {
		err = cl.Get(*bucket, key, buf, size, offset, query)
	}
	dur := time.Since(start)
	if err != nil {
		if rcobj.NotSupported(err) && rest != nil {
			// The endpoint declined v2: run the same operation over
			// REST so an old gateway stays readable.
			if rerr := rest(); rerr != nil {
				return dur, 0, fmt.Errorf("%s rest fallback: %w", name, rerr)
			}
			return dur, int(size), nil
		}
		return dur, 0, fmt.Errorf("%s: %w", name, err)
	}
	return dur, int(size), nil
}

func opName(op int) string {
	if op == opGet {
		return "GET"
	}
	return "PUT"
}

func ternStr(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}

func errStr(e error) string {
	if e == nil {
		return "<nil>"
	}
	return e.Error()
}

// v2Multipart covers the 8.3 flow: REST CreateMultipartUpload,
// two v2 UploadPart transfers, REST CompleteMultipartUpload, then
// a full v2 GET verifying the assembled bytes.
func v2Multipart(cl *rcobj.Client, size int) (bool, error) {
	base := newS3Client(*endpoint, *access, *secret, *region)
	mpKey := *key + "-mp"
	create, err := base.CreateMultipartUpload(context.Background(),
		&s3lib.CreateMultipartUploadInput{
			Bucket: aws.String(*bucket),
			Key:    aws.String(mpKey),
		})
	if err != nil {
		return false, fmt.Errorf("create mpu: %w", err)
	}
	uploadID := *create.UploadId
	mpDone := false
	defer func() {
		if !mpDone {
			_, _ = base.AbortMultipartUpload(context.Background(),
				&s3lib.AbortMultipartUploadInput{
					Bucket:   aws.String(*bucket),
					Key:      aws.String(mpKey),
					UploadId: aws.String(uploadID),
				})
		}
	}()

	partSize := (size + 1) / 2
	// S3 requires every part except the last to be at least 5 MiB,
	// so part 1 is padded with a fixed payload when the test size
	// is smaller. part 2 carries the remainder so the assembled
	// object is exactly the uploaded payload.
	const minPart = 5 << 20
	part1Len := partSize
	if part1Len < minPart {
		part1Len = minPart
	}
	part2Len := size - partSize
	partLens := []int{part1Len, part2Len}
	pad := make([]byte, part1Len-partSize)
	parts := make([]types.CompletedPart, 0, 2)
	for part := 1; part <= 2; part++ {
		plen := partLens[part-1]
		alloc, aerr := rcobj.VallocDev(plen)
		if aerr != nil {
			return false, fmt.Errorf("alloc part %d: %w", part, aerr)
		}
		buf := make([]byte, plen)
		off := (part - 1) * partSize
		end := off + partSize
		if part == 2 {
			end = size
		}
		if end > len(putBufGlobal) {
			end = len(putBufGlobal)
		}
		copy(buf, putBufGlobal[off:end])
		if plen > end-off {
			copy(buf[end-off:], pad)
		}
		if cerr := rcobj.CopyDevHostToDev(alloc, buf); cerr != nil {
			_ = rcobj.FreeDev(alloc)
			return false, fmt.Errorf("stage part %d: %w", part, cerr)
		}
		if err := cl.RegisterBuffer(alloc, uint64(plen)); err != nil {
			_ = rcobj.FreeDev(alloc)
			return false, fmt.Errorf("register part %d: %w", part, err)
		}
		query := fmt.Sprintf("partNumber=%d&uploadId=%s", part, uploadID)
		_, _, terr := v2DoTransfer(cl, opPut,
			alloc, 0, uint64(plen), query, mpKey, func() error {
				return restUploadPart(base, mpKey, uploadID, part, buf)
			})
		if terr == nil {
			// The server's authoritative ETag for this part: fetched
			// through the parts listing rather than fabricated, so
			// CompleteMultipartUpload carries real values.
			etag, gerr := restPartETag(base, mpKey, uploadID, part)
			if gerr != nil {
				terr = fmt.Errorf("part %d etag: %w", part, gerr)
			} else {
				parts = append(parts, types.CompletedPart{
					ETag:       aws.String(etag),
					PartNumber: aws.Int32(int32(part)),
				})
			}
		}
		// The buffer may only be released once the registration is
		// gone: a failed deregistration can leave the memory pinned
		// for DMA, so the allocation is preserved on that failure.
		if derr := cl.DeregisterBuffer(alloc); derr != nil {
			return false, fmt.Errorf("deregister part %d: %w (buffer kept)", part, derr)
		}
		if ferr := rcobj.FreeDev(alloc); ferr != nil {
			return false, fmt.Errorf("free part %d device buffer: %w", part, ferr)
		}
		if terr != nil {
			return false, fmt.Errorf("part %d: %w", part, terr)
		}
	}
	_, err = base.CompleteMultipartUpload(context.Background(),
		&s3lib.CompleteMultipartUploadInput{
			Bucket:   aws.String(*bucket),
			Key:      aws.String(mpKey),
			UploadId: aws.String(uploadID),
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: parts,
			},
		})
	if err != nil {
		return false, fmt.Errorf("complete mpu: %w", err)
	}
	mpDone = true

	// Full GET verifies the assembled bytes: the expected content
	// is the exact concatenation of both uploaded parts (part 1
	// payload plus any padding plus part 2 payload).
	verifyLen := part1Len + part2Len
	verifyAlloc, vaerr := rcobj.VallocDev(verifyLen)
	if vaerr != nil {
		return false, fmt.Errorf("alloc verify device buffer: %w", vaerr)
	}
	if err := cl.RegisterBuffer(verifyAlloc, uint64(verifyLen)); err != nil {
		_ = rcobj.FreeDev(verifyAlloc)
		return false, fmt.Errorf("register verify buffer: %w", err)
	}
	_, _, gerr := v2DoTransfer(cl, opGet, verifyAlloc, 0, uint64(verifyLen), "", mpKey,
		func() error { return restGetObj(base, mpKey, putBufGlobal) })
	if gerr != nil {
		_ = cl.DeregisterBuffer(verifyAlloc)
		_ = rcobj.FreeDev(verifyAlloc)
		return false, fmt.Errorf("verify get: %w", gerr)
	}
	// Stage the result down and compare while the allocation is
	// alive: the expected content is the exact concatenation of both
	// uploaded parts. The buffer is freed only after the
	// deregistration succeeded, so a pinned registration never
	// leaves DMA referencing released memory.
	vbuf := make([]byte, verifyLen)
	if cerr := rcobj.CopyDevDevToHost(vbuf, verifyAlloc); cerr != nil {
		_ = cl.DeregisterBuffer(verifyAlloc)
		_ = rcobj.FreeDev(verifyAlloc)
		return false, fmt.Errorf("stage down verify result: %w", cerr)
	}
	want := make([]byte, 0, verifyLen)
	want = append(want, putBufGlobal[:partSize]...)
	if len(pad) > 0 {
		want = append(want, pad...)
	}
	want = append(want, putBufGlobal[partSize:size]...)
	match := bytes.Equal(vbuf, want)
	if derr := cl.DeregisterBuffer(verifyAlloc); derr != nil {
		return false, fmt.Errorf("deregister verify buffer: %w (buffer kept)", derr)
	}
	if ferr := rcobj.FreeDev(verifyAlloc); ferr != nil {
		return false, fmt.Errorf("free verify device buffer: %w", ferr)
	}
	if !match {
		return false, fmt.Errorf("multipart verify: bytes mismatch")
	}
	return true, nil
}

// restUploadPart is the REST fallback for one part upload.
func restUploadPart(base *s3lib.Client, key, uploadID string,
	part int, buf []byte) error {
	_, err := base.UploadPart(context.Background(), &s3lib.UploadPartInput{
		Bucket:     aws.String(*bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(int32(part)),
		Body:       bytes.NewReader(buf),
	})
	return err
}

// restPartETag fetches the server's ETag for an uploaded part.
func restPartETag(base *s3lib.Client, key, uploadID string,
	part int) (string, error) {
	out, err := base.ListParts(context.Background(), &s3lib.ListPartsInput{
		Bucket:   aws.String(*bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
	if err != nil {
		return "", err
	}
	for _, p := range out.Parts {
		if int(*p.PartNumber) == part {
			if p.ETag == nil {
				return "", fmt.Errorf("part %d has no etag", part)
			}
			return *p.ETag, nil
		}
	}
	return "", fmt.Errorf("part %d not listed", part)
}

// restPutObj is the REST fallback for a plain PUT.
func restPutObj(base *s3lib.Client, key string, src []byte) error {
	_, err := base.PutObject(context.Background(), &s3lib.PutObjectInput{
		Bucket: aws.String(*bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(src),
	})
	return err
}

// restGetRange is the REST fallback for a ranged GET.
func restGetRange(base *s3lib.Client, key string,
	offset, size uint64, dst []byte) error {
	out, err := base.GetObject(context.Background(), &s3lib.GetObjectInput{
		Bucket: aws.String(*bucket),
		Key:    aws.String(key),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", offset, offset+size-1)),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	_, err = io.ReadFull(out.Body, dst)
	return err
}

// restGetObj is the REST fallback for the verification GET.
func restGetObj(base *s3lib.Client, key string, dst []byte) error {
	out, err := base.GetObject(context.Background(), &s3lib.GetObjectInput{
		Bucket: aws.String(*bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	_, err = io.ReadFull(out.Body, dst)
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// putBufGlobal holds the host-side PUT payload. The transfer
// buffer itself lives in device memory; this copy is the staging
// source (H2D before the PUT) and the comparison reference for
// the GET, Range, and multipart verification steps.
var putBufGlobal []byte

// readRandom fills b with crypto-random bytes.
func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}

// v2Result records one v2 step's outcome for the summary table.
type v2Result struct {
	step      string
	dur       time.Duration
	bytes     int
	err       error
	byteMatch bool
	firstDiff int
	gotByte   byte
	wantByte  byte
}

// v2EndpointParts splits an endpoint URL into host and port.
func v2EndpointParts(endpoint string) (host string, port uint32, err error) {
	ep := endpoint
	if !strings.Contains(ep, "://") {
		ep = "http://" + ep
	}
	u, perr := url.Parse(ep)
	if perr != nil || u.Host == "" {
		return "", 0, fmt.Errorf("invalid endpoint %q", endpoint)
	}
	h := u.Hostname()
	p := u.Port()
	if p == "" {
		p = "80"
	}
	pn, cerr := strconv.Atoi(p)
	if cerr != nil || pn <= 0 || pn > 65535 {
		return "", 0, fmt.Errorf("invalid endpoint port in %q", endpoint)
	}
	return h, uint32(pn), nil
}

// v2EnsureProbeObject creates the readable object the admission
// probe needs, through plain S3.
func v2EnsureProbeObject(host string, port uint32, key string) error {
	base := newS3Client(*endpoint, *access, *secret, *region)
	if err := ensureBucket(base, *bucket); err != nil {
		return err
	}
	var cl int64 = 5
	_, err := base.PutObject(context.Background(), &s3lib.PutObjectInput{
		Bucket:        aws.String(*bucket),
		Key:           aws.String(key),
		ContentLength: &cl,
		Body:          strings.NewReader("probe"),
	})
	return err
}
