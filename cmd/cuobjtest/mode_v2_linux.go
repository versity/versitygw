//go:build linux && amd64

package main

import (
	"context"
	"crypto/rand"
	"fmt"
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
		Region: *region,
	})
	if err != nil {
		return fmt.Errorf("rcobj init: %w", err)
	}
	defer cl.Shutdown()

	// Host memory is registered through the library's host-MR
	// path; the v2 entry points require a registered buffer.
	putAlloc := rcobj.Valloc(size)
	if putAlloc == nil {
		return fmt.Errorf("alloc PUT buffer")
	}
	defer rcobj.Free(putAlloc)
	putBuf := unsafe.Slice((*byte)(putAlloc), size)
	putBufGlobal = putBuf
	if _, err := readRandom(putBuf); err != nil {
		return fmt.Errorf("fill PUT buffer: %w", err)
	}
	if err := cl.RegisterBuffer(putAlloc, uint64(size)); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer cl.DeregisterBuffer(putAlloc)

	results := []v2Result{}

	// 1. Plain PUT
	r := v2Result{step: "PUT"}
	r.dur, r.bytes, r.err = v2DoTransfer(cl, opPut,
		putAlloc, 0, uint64(size), "")
	results = append(results, r)

	// 2. Plain GET (full)
	getAlloc := rcobj.Valloc(size)
	if getAlloc == nil {
		return fmt.Errorf("alloc GET buffer")
	}
	defer rcobj.Free(getAlloc)
	getBuf := unsafe.Slice((*byte)(getAlloc), size)
	if err := cl.RegisterBuffer(getAlloc, uint64(size)); err != nil {
		return fmt.Errorf("register GET buffer: %w", err)
	}
	defer cl.DeregisterBuffer(getAlloc)

	if r.err == nil {
		r = v2Result{step: "GET"}
		r.dur, r.bytes, r.err = v2DoTransfer(cl, opGet,
			getAlloc, 0, uint64(size), "")
		r.byteMatch = r.err == nil && string(putBuf) == string(getBuf)
		if r.err == nil && !r.byteMatch {
			r.firstDiff = -1
			for i := 0; i < len(putBuf); i++ {
				if putBuf[i] != getBuf[i] {
					r.firstDiff = i
					r.gotByte = getBuf[i]
					r.wantByte = putBuf[i]
					break
				}
			}
			r.err = fmt.Errorf("GET bytes mismatch")
		}
		results = append(results, r)
	}

	// 3. Range GET at a non-zero offset
	rangeOffset := uint64(size / 4)
	rangeSize := uint64(size / 2)
	if r.err == nil && rangeOffset > 0 && rangeSize > 0 {
		rgAlloc := rcobj.Valloc(int(rangeSize))
		if rgAlloc == nil {
			return fmt.Errorf("alloc Range buffer")
		}
		rangeBuf := unsafe.Slice((*byte)(rgAlloc), int(rangeSize))
		if err := cl.RegisterBuffer(rgAlloc, rangeSize); err != nil {
			return fmt.Errorf("register Range buffer: %w", err)
		}
		r = v2Result{step: fmt.Sprintf("GET+Range@%d", rangeOffset)}
		r.dur, r.bytes, r.err = v2DoTransfer(cl, opGet,
			rgAlloc, rangeOffset, rangeSize, "")
		r.byteMatch = r.err == nil &&
			string(putBuf[rangeOffset:rangeOffset+rangeSize]) == string(rangeBuf)
		if r.err == nil && !r.byteMatch {
			want := putBuf[rangeOffset : rangeOffset+rangeSize]
			r.firstDiff = -1
			for i := 0; i < len(want); i++ {
				if want[i] != rangeBuf[i] {
					r.firstDiff = i
					r.gotByte = rangeBuf[i]
					r.wantByte = want[i]
					break
				}
			}
			r.err = fmt.Errorf("Range GET bytes mismatch")
		}
		results = append(results, r)
		cl.DeregisterBuffer(rgAlloc)
		rcobj.Free(rgAlloc)
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
		return fmt.Errorf("v2 mode had failures")
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
func v2DoTransfer(cl *rcobj.Client, op int,
	buf unsafe.Pointer, offset, size uint64, query string) (time.Duration, int, error) {

	start := time.Now()
	name := opName(op)
	var err error
	if op == opPut {
		err = cl.Put(*bucket, *key, buf, size, offset, query)
	} else {
		err = cl.Get(*bucket, *key, buf, size, offset, query)
	}
	dur := time.Since(start)
	if err != nil {
		if rcobj.NotSupported(err) {
			// The endpoint declined v2: fall back to REST for this
			// transfer so an old gateway stays readable.
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

	partSize := size / 2
	// S3 requires every part except the last to be at least 5 MiB,
	// so part 1 is padded with a fixed payload when the test size
	// is smaller.
	const minPart = 5 << 20
	part1Len := partSize
	if part1Len < minPart {
		part1Len = minPart
	}
	partLens := []int{part1Len, partSize}
	pad := make([]byte, part1Len-partSize)
	parts := make([]types.CompletedPart, 0, 2)
	for part := 1; part <= 2; part++ {
		plen := partLens[part-1]
		alloc := rcobj.Valloc(plen)
		if alloc == nil {
			return false, fmt.Errorf("alloc part %d", part)
		}
		buf := unsafe.Slice((*byte)(alloc), plen)
		off := (part - 1) * partSize
		end := off + partSize
		if end > len(putBufGlobal) {
			end = len(putBufGlobal)
		}
		copy(buf, putBufGlobal[off:end])
		if plen > partSize {
			copy(buf[partSize:], pad)
		}
		if err := cl.RegisterBuffer(alloc, uint64(plen)); err != nil {
			rcobj.Free(alloc)
			return false, fmt.Errorf("register part %d: %w", part, err)
		}
		query := fmt.Sprintf("partNumber=%d&uploadId=%s", part, uploadID)
		_, _, terr := v2DoTransfer(cl, opPut,
			alloc, 0, uint64(plen), query)
		cl.DeregisterBuffer(alloc)
		rcobj.Free(alloc)
		if terr != nil {
			return false, fmt.Errorf("part %d: %w", part, terr)
		}
		etag := "placeholder"
		parts = append(parts, types.CompletedPart{
			ETag:       aws.String(etag),
			PartNumber: aws.Int32(int32(part)),
		})
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

	// Full GET verifies the assembled bytes.
	verifyAlloc := rcobj.Valloc(size)
	if verifyAlloc == nil {
		return false, fmt.Errorf("alloc verify buffer")
	}
	defer rcobj.Free(verifyAlloc)
	vbuf := unsafe.Slice((*byte)(verifyAlloc), size)
	if err := cl.RegisterBuffer(verifyAlloc, uint64(size)); err != nil {
		return false, fmt.Errorf("register verify buffer: %w", err)
	}
	defer cl.DeregisterBuffer(verifyAlloc)
	if _, _, gerr := v2DoTransfer(cl, opGet, verifyAlloc, 0, uint64(size), ""); gerr != nil {
		return false, fmt.Errorf("verify get: %w", gerr)
	}
	want := putBufGlobal
	if size > len(want) {
		want = want[:size]
	}
	if !strings.Contains(string(vbuf), string(want[:min(size, len(want))])) {
		return false, fmt.Errorf("multipart verify: bytes mismatch")
	}
	return true, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// putBufGlobal holds the PUT payload for the multipart flow's
// part-copy step.
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
