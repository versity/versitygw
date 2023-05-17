package posix

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3err"
)

type Posix struct {
	backend.BackendUnsupported
}

var _ backend.Backend = &Posix{}

const metaTmpDir = ".sgwtmp"

func (p *Posix) ListBuckets() (*s3.ListBucketsOutput, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("readdir buckets: %w", err)
	}

	var buckets []types.Bucket
	for _, entry := range entries {
		if !entry.IsDir() {
			// buckets must be a directory
			continue
		}

		fi, err := entry.Info()
		if err != nil {
			// skip entries returning errors
			continue
		}

		buckets = append(buckets, types.Bucket{
			Name:         backend.GetStringPtr(entry.Name()),
			CreationDate: backend.GetTimePtr(fi.ModTime()),
		})
	}

	sort.Sort(backend.ByBucketName(buckets))

	return &s3.ListBucketsOutput{
		Buckets: buckets,
	}, nil
}

func (p *Posix) HeadBucket(bucket string) (*s3.HeadBucketOutput, error) {
	_, err := os.Lstat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	return &s3.HeadBucketOutput{}, nil
}

func (p *Posix) PutBucket(bucket string) error {
	err := os.Mkdir(bucket, 0777)
	if err != nil && os.IsExist(err) {
		return s3err.GetAPIError(s3err.ErrBucketAlreadyExists)
	}
	if err != nil {
		return fmt.Errorf("mkdir bucket: %w", err)
	}

	return nil
}

func (p *Posix) DeleteBucket(bucket string) error {
	names, err := os.ReadDir(bucket)
	if err != nil && os.IsNotExist(err) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("readdir bucket: %w", err)
	}

	if len(names) == 1 && names[0].Name() == metaTmpDir {
		// if .sgwtmp is only item in directory
		// then clean this up before trying to remove the bucket
		err = os.RemoveAll(filepath.Join(bucket, metaTmpDir))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove temp dir: %w", err)
		}
	}

	err = os.Remove(bucket)
	if err != nil && err.(*os.PathError).Err == syscall.ENOTEMPTY {
		return s3err.GetAPIError(s3err.ErrBucketNotEmpty)
	}
	if err != nil {
		return fmt.Errorf("remove bucket: %w", err)
	}

	return nil
}
