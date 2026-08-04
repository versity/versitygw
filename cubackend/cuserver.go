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

//go:build linux && amd64 && cgo

package cubackend

// Package backend implements the cuObject-accelerated storage backend.
// CuServer embeds the versitygw backend and overrides PutObject and
// GetObject to use RDMA transfers when the request contains a cuObject
// RDMA descriptor. All other S3 operations delegate directly to backend.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/cumiddleware"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/rdma"
	"github.com/versity/versitygw/rdma/bufferpool"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// CuServer is a versitygw Backend that embeds another backend and overrides
// PutObject/GetObject for RDMA-accelerated transfers via cuObjServer.
// All other S3 operations (list, head, delete, multipart, etc.) pass
// through to the embedded backend unchanged.
type CuServer struct {
	backend.Backend
	rdmaSrv *rdma.Server
	pool    *bufferpool.Pool
}

// New creates a CuServer backend. It creates a cuObjServer instance,
// starts the RDMA session, and pre-allocates a pool of RDMA-registered
// host buffers.
func New(opts CuServerOpts, be backend.Backend) (*CuServer, error) {
	rdmaSrv, err := rdma.NewServer(opts.RDMAIP, opts.RDMAPort, opts.RDMATunables)
	if err != nil {
		be.Shutdown()
		return nil, fmt.Errorf("cuserver: rdma server: %w", err)
	}

	// StartSession is a no-op when the library manages session start
	// internally (e.g. libcuobjserver v1.2.0 calls startRDMASession from
	// the cuObjServer constructor). It is kept here for forward compatibility
	// with library versions that require an explicit call.
	if err := rdmaSrv.StartSession(); err != nil {
		rdmaSrv.Close()
		be.Shutdown()
		return nil, fmt.Errorf("cuserver: rdma session: %w", err)
	}

	bufSize := opts.PoolBufSize
	if bufSize <= 0 {
		bufSize = rdma.MaxTransferSize
	}
	bufCount := opts.PoolBufCount
	if bufCount <= 0 {
		bufCount = 4
	}

	pool, err := bufferpool.NewPool(rdmaSrv, bufSize, bufCount)
	if err != nil {
		rdmaSrv.Close()
		be.Shutdown()
		return nil, fmt.Errorf("cuserver: buffer pool: %w", err)
	}

	return &CuServer{
		Backend: be,
		rdmaSrv: rdmaSrv,
		pool:    pool,
	}, nil
}

// String returns a human-readable identifier for the backend.
func (*CuServer) String() string {
	return "cuObject Server"
}

// Shutdown closes the buffer pool and RDMA server, then shuts down the
// embedded backend.
func (cs *CuServer) Shutdown() {
	cs.pool.Close()
	cs.rdmaSrv.Close()
	cs.Backend.Shutdown()
}

// PutObject handles S3 PUT requests. If the request context contains a
// cuObject RDMA descriptor, data is transferred via RDMA READ from the
// client's GPU memory into a local buffer, then written to the backend
// Without an RDMA descriptor, delegates directly to backend.
func (cs *CuServer) PutObject(ctx context.Context, po s3response.PutObjectInput) (s3response.PutObjectOutput, error) {
	descr, ok := cumiddleware.GetRDMADescriptor(ctx)
	if !ok {
		debuglogger.Logf("doing normal put")
		// Normal S3 path — no RDMA descriptor present
		return cs.Backend.PutObject(ctx, po)
	}

	debuglogger.Logf("doing RDMA put")
	// RDMA-accelerated path
	size, ok := cumiddleware.GetRDMASize(ctx)
	if !ok || size <= 0 {
		// Size comes from the legacy 3-header scheme or, for the combined
		// token scheme, the standard Content-Length header — neither was usable.
		return s3response.PutObjectOutput{}, fmt.Errorf("cuserver: RDMA PUT requires a positive size via the %s header or a standard Content-Length header", cumiddleware.HeaderRDMASize)
	}
	if size > int64(rdma.MaxTransferSize) {
		return s3response.PutObjectOutput{}, fmt.Errorf("cuserver: object size %d exceeds RDMA max %d", size, rdma.MaxTransferSize)
	}

	remoteStart := cumiddleware.GetRDMARemoteStart(ctx)
	debuglogger.Logf("RDMA PUT params: key=%q size=%d remoteStart=0x%x descr=%s", keyFromPtr(po.Key), size, remoteStart, descr)

	channelID, err := cs.rdmaSrv.AllocateChannel()
	if err != nil {
		return s3response.PutObjectOutput{}, fmt.Errorf("cuserver: alloc channel: %w", err)
	}
	defer cs.rdmaSrv.FreeChannel(channelID)

	buf, _, err := cs.pool.Acquire(ctx)
	if err != nil {
		return s3response.PutObjectOutput{}, fmt.Errorf("cuserver: acquire buffer: %w", err)
	}
	defer cs.pool.Release(buf)

	key := keyFromPtr(po.Key)

	// Stream RDMA chunks into a pipe so backend can begin writing before
	// the full transfer is complete.
	pr, pw := io.Pipe()
	po.Body = pr
	po.ContentLength = &size
	producerErrCh := make(chan error, 1)
	go func() {
		defer close(producerErrCh)

		local := buf.Slice()
		remaining := size
		offset := int64(0)

		for remaining > 0 {
			chunk := rdmaPutChunkSize(len(local), remaining)
			if chunk <= 0 {
				wrapped := fmt.Errorf("cuserver: invalid RDMA PUT buffer size %d", len(local))
				_ = pw.CloseWithError(wrapped)
				producerErrCh <- wrapped
				return
			}

			// RDMA READ current chunk from client into the start of local buffer.
			n, e := cs.rdmaSrv.HandlePut(key, buf, remoteStart+uint64(offset), chunk, descr, channelID)
			if e == nil && n != chunk {
				e = fmt.Errorf("short RDMA transfer: got %d bytes, want %d", n, chunk)
			}
			if e != nil {
				wrapped := fmt.Errorf("cuserver: RDMA PUT %q chunk offset=%d size=%d: %w", key, offset, chunk, e)
				_ = pw.CloseWithError(wrapped)
				producerErrCh <- wrapped
				return
			}

			if _, e := pw.Write(local[:int(chunk)]); e != nil {
				producerErrCh <- e
				return
			}

			offset += chunk
			remaining -= chunk
		}

		if e := pw.Close(); e != nil {
			producerErrCh <- e
			return
		}
		producerErrCh <- nil
	}()

	out, err := cs.Backend.PutObject(ctx, po)
	if err != nil {
		_ = pr.Close()
		if prodErr := <-producerErrCh; prodErr != nil {
			return s3response.PutObjectOutput{}, fmt.Errorf("cuserver: PUT %q failed (backend: %v; rdma/pipe: %w)", key, err, prodErr)
		}
		return s3response.PutObjectOutput{}, err
	}

	if prodErr := <-producerErrCh; prodErr != nil {
		return s3response.PutObjectOutput{}, prodErr
	}

	cumiddleware.SetRDMAReplyHeader(ctx, http.StatusOK, size)
	return out, nil
}

// UploadPart handles S3 multipart upload part requests. RDMA offload is not
// supported here: object data would travel out-of-band via RDMA, but the
// embedded backend's UploadPart still expects the part in the HTTP body.
// Decline the descriptor so the client retries over the normal HTTP path
// instead of silently uploading a wrong/empty part.
func (cs *CuServer) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	if _, ok := cumiddleware.GetRDMADescriptor(ctx); ok {
		return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
	}
	return cs.Backend.UploadPart(ctx, input)
}

// GetObject handles S3 GET requests. If the request context contains a
// cuObject RDMA descriptor, the object is read from the backend
// into an RDMA buffer, then transferred via RDMA WRITE to the client's
// GPU memory. The HTTP response contains metadata only (no body).
// Without an RDMA descriptor, delegates directly to backend.
func (cs *CuServer) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	descr, ok := cumiddleware.GetRDMADescriptor(ctx)
	if !ok {
		debuglogger.Logf("doing normal get")
		// Normal S3 path
		return cs.Backend.GetObject(ctx, input)
	}

	debuglogger.Logf("doing RDMA get")

	// First, get the object from backend (opens the file, returns metadata + Body)
	res, err := cs.Backend.GetObject(ctx, input)
	if err != nil {
		return nil, err
	}

	// Determine the actual content size
	var size int64
	if res.ContentLength != nil {
		size = *res.ContentLength
	}
	if size <= 0 {
		// No content to transfer — return metadata only
		return res, nil
	}
	if size > int64(rdma.MaxTransferSize) {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, fmt.Errorf("cuserver: object size %d exceeds RDMA max %d", size, rdma.MaxTransferSize)
	}
	if capSize, ok := cumiddleware.GetRDMASize(ctx); ok {
		if capSize <= 0 {
			if res.Body != nil {
				res.Body.Close()
			}
			return nil, fmt.Errorf("cuserver: RDMA GET requires a positive client capacity")
		}
		if size > capSize {
			if res.Body != nil {
				res.Body.Close()
			}
			return nil, fmt.Errorf("cuserver: object/range size %d exceeds RDMA client capacity %d", size, capSize)
		}
	}

	remoteStart := cumiddleware.GetRDMARemoteStart(ctx)

	channelID, err := cs.rdmaSrv.AllocateChannel()
	if err != nil {
		res.Body.Close()
		return nil, fmt.Errorf("cuserver: alloc channel: %w", err)
	}
	defer cs.rdmaSrv.FreeChannel(channelID)

	buf, slice, err := cs.pool.Acquire(ctx)
	if err != nil {
		res.Body.Close()
		return nil, fmt.Errorf("cuserver: acquire buffer: %w", err)
	}
	defer cs.pool.Release(buf)
	defer res.Body.Close()

	if len(slice) == 0 {
		return nil, fmt.Errorf("cuserver: invalid RDMA GET buffer size %d", len(slice))
	}

	key := keyFromPtr(input.Key)
	debuglogger.Logf("RDMA GET params: key=%q size=%d remoteStart=0x%x descr=%s", key, size, remoteStart, descr)

	remaining := size
	offset := int64(0)
	for remaining > 0 {
		chunk := rdmaPutChunkSize(len(slice), remaining)
		if chunk <= 0 {
			return nil, fmt.Errorf("cuserver: invalid RDMA GET buffer size %d", len(slice))
		}

		if _, err = io.ReadFull(res.Body, slice[:int(chunk)]); err != nil {
			return nil, fmt.Errorf("cuserver: read object %q chunk offset=%d size=%d into RDMA buffer: %w", key, offset, chunk, err)
		}

		n, err := cs.rdmaSrv.HandleGet(key, buf, remoteStart+uint64(offset), chunk, descr, channelID)
		if err == nil && n != chunk {
			err = fmt.Errorf("short RDMA transfer: got %d bytes, want %d", n, chunk)
		}
		if err != nil {
			return nil, fmt.Errorf("cuserver: RDMA GET %q chunk offset=%d size=%d: %w", key, offset, chunk, err)
		}

		offset += chunk
		remaining -= chunk
	}

	// Return metadata only — the data was already sent via RDMA.
	// Set Body to empty and clear ContentLength so the HTTP response
	// carries only headers.
	res.Body = io.NopCloser(bytes.NewReader(nil))
	zero := int64(0)
	res.ContentLength = &zero

	cumiddleware.SetRDMAReplyHeader(ctx, http.StatusOK, size)
	return res, nil
}

func keyFromPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Ensure CuServer satisfies the Backend interface at compile time.
var _ backend.Backend = (*CuServer)(nil)

func rdmaPutChunkSize(bufSize int, remaining int64) int64 {
	if bufSize <= 0 || remaining <= 0 {
		return 0
	}

	chunkSize := int64(bufSize)
	if remaining < chunkSize {
		return remaining
	}

	return chunkSize
}
