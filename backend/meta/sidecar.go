package meta

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SideCar is a metadata storer that uses sidecar files to store metadata.
type SideCar struct{}

const (
	sidecardir  = ".vgw_meta"
	sidecarmeta = ".meta"
)

// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
func (s SideCar) RetrieveAttribute(bucket, object, attribute string) ([]byte, error) {
	metadir := filepath.Join(sidecardir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(sidecardir, bucket, sidecarmeta)
	}
	attr := filepath.Join(metadir, attribute)

	value, err := os.ReadFile(attr)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSuchKey
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read attribute: %v", err)
	}

	return value, nil
}

// StoreAttribute stores the value of a specific attribute for an object or a bucket.
func (s SideCar) StoreAttribute(bucket, object, attribute string, value []byte) error {
	metadir := filepath.Join(sidecardir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(sidecardir, bucket, sidecarmeta)
	}
	err := os.MkdirAll(metadir, 0777)
	if err != nil {
		return fmt.Errorf("failed to create metadata directory: %v", err)
	}

	attr := filepath.Join(metadir, attribute)
	err = os.WriteFile(attr, value, 0666)
	if err != nil {
		return fmt.Errorf("failed to write attribute: %v", err)
	}

	return nil
}

// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
func (s SideCar) DeleteAttribute(bucket, object, attribute string) error {
	metadir := filepath.Join(sidecardir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(sidecardir, bucket, sidecarmeta)
	}
	attr := filepath.Join(metadir, attribute)

	err := os.Remove(attr)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoSuchKey
	}
	if err != nil {
		return fmt.Errorf("failed to remove attribute: %v", err)
	}

	return nil
}

// ListAttributes lists all attributes for an object or a bucket.
func (s SideCar) ListAttributes(bucket, object string) ([]string, error) {
	metadir := filepath.Join(sidecardir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(sidecardir, bucket, sidecarmeta)
	}

	ents, err := os.ReadDir(metadir)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list attributes: %v", err)
	}

	var attrs []string
	for _, ent := range ents {
		attrs = append(attrs, ent.Name())
	}

	return attrs, nil
}

// DeleteAttributes removes all attributes for an object or a bucket.
func (s SideCar) DeleteAttributes(bucket, object string) error {
	metadir := filepath.Join(sidecardir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(sidecardir, bucket, sidecarmeta)
	}

	err := os.RemoveAll(metadir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove attributes: %v", err)
	}
	return nil
}
