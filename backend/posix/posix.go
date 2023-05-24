package posix

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/pkg/xattr"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3err"
)

type Posix struct {
	backend.BackendUnsupported
}

var _ backend.Backend = &Posix{}

const (
	metaTmpDir          = ".sgwtmp"
	metaTmpMultipartDir = metaTmpDir + "/multipart"
	onameAttr           = "user.objname"
	tagHdr              = "X-Amz-Tagging"
	dirObjKey           = "user.dirisobject"
)

var (
	newObjUID = 0
	newObjGID = 0
)

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

func (p *Posix) CreateMultipartUpload(mpu *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	bucket := *mpu.Bucket
	object := *mpu.Key

	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	// generate random uuid for upload id
	uploadID := uuid.New().String()
	// hash object name for multipart container
	objNameSum := sha256.Sum256([]byte(*mpu.Key))
	// multiple uploads for same object name allowed,
	// they will all go into the same hashed name directory
	objdir := filepath.Join(bucket, metaTmpMultipartDir,
		fmt.Sprintf("%x", objNameSum))
	// the unique upload id is a directory for all of the parts
	// associated with this specific multipart upload
	err = os.MkdirAll(filepath.Join(objdir, uploadID), 0755)
	if err != nil {
		return nil, fmt.Errorf("create upload temp dir: %w", err)
	}

	// set an xattr with the original object name so that we can
	// map the hashed name back to the original object name
	err = xattr.Set(objdir, onameAttr, []byte(object))
	if err != nil {
		// if we fail, cleanup the container directories
		// but ignore errors because there might still be
		// other uploads for the same object name outstanding
		os.RemoveAll(filepath.Join(objdir, uploadID))
		os.Remove(objdir)
		return nil, fmt.Errorf("set name attr for upload: %w", err)
	}

	// set user attrs
	for k, v := range mpu.Metadata {
		xattr.Set(filepath.Join(objdir, uploadID), "user."+k, []byte(v))
	}

	return &s3.CreateMultipartUploadOutput{
		Bucket:   &bucket,
		Key:      &object,
		UploadId: &uploadID,
	}, nil
}

func (p *Posix) CompleteMultipartUpload(bucket, object, uploadID string, parts []types.Part) (*s3.CompleteMultipartUploadOutput, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	sum, err := p.checkUploadIDExists(bucket, object, uploadID)
	if err != nil {
		return nil, err
	}

	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	// check all parts ok
	last := len(parts) - 1
	partsize := int64(0)
	for i, p := range parts {
		fi, err := os.Lstat(filepath.Join(objdir, uploadID, fmt.Sprintf("%v", p.PartNumber)))
		if err != nil {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}

		if i == 0 {
			partsize = fi.Size()
		}
		// all parts except the last need to be the same size
		if i < last && partsize != fi.Size() {
			return nil, s3err.GetAPIError(s3err.ErrInvalidPart)
		}
	}

	f, err := openTmpFile(".")
	if err != nil {
		return nil, fmt.Errorf("open temp file: %w", err)
	}
	defer f.Close()

	for _, p := range parts {
		pf, err := os.Open(filepath.Join(objdir, uploadID, fmt.Sprintf("%v", p.PartNumber)))
		if err != nil {
			return nil, fmt.Errorf("open part %v: %v", p.PartNumber, err)
		}
		_, err = io.Copy(f, pf)
		pf.Close()
		if err != nil {
			return nil, fmt.Errorf("copy part %v: %v", p.PartNumber, err)
		}
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	loadUserMetaData(upiddir, userMetaData)

	objname := filepath.Join(bucket, object)
	dir := filepath.Dir(objname)
	if dir != "" {
		if err = mkdirAll(dir, os.FileMode(0755), bucket, object); err != nil {
			if err != nil && os.IsExist(err) {
				return nil, s3err.GetAPIError(s3err.ErrObjectParentIsFile)
			}
			if err != nil {
				return nil, fmt.Errorf("make object parent directories: %w", err)
			}
		}
	}
	err = linkTmpFile(f, objname)
	if err != nil {
		return nil, fmt.Errorf("link object in namespace: %w", err)
	}

	for k, v := range userMetaData {
		err = xattr.Set(objname, "user."+k, []byte(v))
		if err != nil {
			// cleanup object if returning error
			os.Remove(objname)
			return nil, fmt.Errorf("set user attr %q: %w", k, err)
		}
	}

	// Calculate s3 compatible md5sum for complete multipart.
	s3MD5 := getMultipartMD5(parts)

	err = xattr.Set(objname, "user.etag", []byte(s3MD5))
	if err != nil {
		// cleanup object if returning error
		os.Remove(objname)
		return nil, fmt.Errorf("set etag attr: %w", err)
	}

	if newObjUID != 0 || newObjGID != 0 {
		err = os.Chown(objname, newObjUID, newObjGID)
		if err != nil {
			// cleanup object if returning error
			os.Remove(objname)
			return nil, fmt.Errorf("set object uid/gid: %w", err)
		}
	}

	// cleanup tmp dirs
	os.RemoveAll(upiddir)
	// use Remove for objdir in case there are still other uploads
	// for same object name outstanding
	os.Remove(objdir)

	return &s3.CompleteMultipartUploadOutput{
		Bucket: &bucket,
		ETag:   &s3MD5,
		Key:    &object,
	}, nil
}

func (p *Posix) checkUploadIDExists(bucket, object, uploadID string) ([32]byte, error) {
	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	_, err := os.Stat(filepath.Join(objdir, uploadID))
	if err != nil && os.IsNotExist(err) {
		return [32]byte{}, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("stat upload: %w", err)
	}
	return sum, nil
}

func loadUserMetaData(path string, m map[string]string) (tag, contentType, contentEncoding string) {
	ents, err := xattr.List(path)
	if err != nil || len(ents) == 0 {
		return
	}
	for _, e := range ents {
		if !isValidMeta(e) {
			continue
		}
		b, err := xattr.Get(path, e)
		if err == syscall.ENODATA {
			m[strings.TrimPrefix(e, "user.")] = ""
			continue
		}
		if err != nil {
			continue
		}
		m[strings.TrimPrefix(e, "user.")] = string(b)
	}

	b, err := xattr.Get(path, "user."+tagHdr)
	tag = string(b)
	if err != nil {
		tag = ""
	}
	if tag != "" {
		m[tagHdr] = tag
	}

	b, err = xattr.Get(path, "user.content-type")
	contentType = string(b)
	if err != nil {
		contentType = ""
	}
	if contentType != "" {
		m["content-type"] = contentType
	}

	b, err = xattr.Get(path, "user.content-encoding")
	contentEncoding = string(b)
	if err != nil {
		contentEncoding = ""
	}
	if contentEncoding != "" {
		m["content-encoding"] = contentEncoding
	}

	return
}

func isValidMeta(val string) bool {
	if strings.HasPrefix(val, "user.X-Amz-Meta") {
		return true
	}
	if strings.EqualFold(val, "user.Expires") {
		return true
	}
	return false
}

// mkdirAll is similar to os.MkdirAll but it will also set uid/gid when
// making new directories
func mkdirAll(path string, perm os.FileMode, bucket, object string) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = mkdirAll(path[:j-1], perm, bucket, object)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = os.Mkdir(path, perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}
	if newObjUID != 0 || newObjGID != 0 {
		err = os.Chown(path, newObjUID, newObjGID)
		if err != nil {
			return fmt.Errorf("set parent ownership: %w", err)
		}
	}
	return nil
}

func getMultipartMD5(parts []types.Part) string {
	var partsEtagBytes []byte
	for _, part := range parts {
		partsEtagBytes = append(partsEtagBytes, getEtagBytes(*part.ETag)...)
	}
	s3MD5 := fmt.Sprintf("%s-%d", md5String(partsEtagBytes), len(parts))
	return s3MD5
}

func getEtagBytes(etag string) []byte {
	decode, err := hex.DecodeString(strings.ReplaceAll(etag, string('"'), ""))
	if err != nil {
		return []byte(etag)
	}
	return decode
}

func md5String(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

func (p *Posix) AbortMultipartUpload(mpu *s3.AbortMultipartUploadInput) error {
	bucket := *mpu.Bucket
	object := *mpu.Key
	uploadID := *mpu.UploadId

	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	_, err = os.Stat(filepath.Join(objdir, uploadID))
	if err != nil {
		return s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}

	err = os.RemoveAll(filepath.Join(objdir, uploadID))
	if err != nil {
		return fmt.Errorf("remove multipart upload container: %w", err)
	}
	os.Remove(objdir)

	return nil
}

func (p *Posix) ListMultipartUploads(mpu *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	bucket := *mpu.Bucket

	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	// ignore readdir error and use the empty list returned
	objs, _ := os.ReadDir(filepath.Join(bucket, metaTmpMultipartDir))

	var uploads []types.MultipartUpload

	keyMarker := *mpu.KeyMarker
	uploadIDMarker := *mpu.UploadIdMarker
	var pastMarker bool
	if keyMarker == "" && uploadIDMarker == "" {
		pastMarker = true
	}

	for i, obj := range objs {
		if !obj.IsDir() {
			continue
		}

		b, err := xattr.Get(filepath.Join(bucket, metaTmpMultipartDir, obj.Name()), onameAttr)
		if err != nil {
			continue
		}
		objectName := string(b)
		if !strings.HasPrefix(objectName, *mpu.Prefix) {
			continue
		}

		upids, err := os.ReadDir(filepath.Join(bucket, metaTmpMultipartDir, obj.Name()))
		if err != nil {
			continue
		}

		for j, upid := range upids {
			if !upid.IsDir() {
				continue
			}

			if objectName == keyMarker || upid.Name() == uploadIDMarker {
				pastMarker = true
				continue
			}
			if keyMarker != "" && uploadIDMarker != "" && !pastMarker {
				continue
			}

			userMetaData := make(map[string]string)
			upiddir := filepath.Join(bucket, metaTmpMultipartDir, obj.Name(), upid.Name())
			loadUserMetaData(upiddir, userMetaData)

			uploadID := upid.Name()
			uploads = append(uploads, types.MultipartUpload{
				Key:      &objectName,
				UploadId: &uploadID,
			})
			if len(uploads) == int(mpu.MaxUploads) {
				return &s3.ListMultipartUploadsOutput{
					Bucket:             &bucket,
					Delimiter:          mpu.Delimiter,
					IsTruncated:        i != len(objs) || j != len(upids),
					KeyMarker:          &keyMarker,
					MaxUploads:         mpu.MaxUploads,
					NextKeyMarker:      &objectName,
					NextUploadIdMarker: &uploadID,
					Prefix:             mpu.Prefix,
					UploadIdMarker:     mpu.UploadIdMarker,
					Uploads:            uploads,
				}, nil
			}
		}
	}

	return &s3.ListMultipartUploadsOutput{
		Bucket:         &bucket,
		Delimiter:      mpu.Delimiter,
		KeyMarker:      &keyMarker,
		MaxUploads:     mpu.MaxUploads,
		Prefix:         mpu.Prefix,
		UploadIdMarker: mpu.UploadIdMarker,
		Uploads:        uploads,
	}, nil
}

func (p *Posix) ListObjectParts(bucket, object, uploadID string, partNumberMarker int, maxParts int) (*s3.ListPartsOutput, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	sum, err := p.checkUploadIDExists(bucket, object, uploadID)
	if err != nil {
		return nil, err
	}

	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))

	ents, err := os.ReadDir(filepath.Join(objdir, uploadID))
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchUpload)
	}
	if err != nil {
		return nil, fmt.Errorf("readdir upload: %w", err)
	}

	var parts []types.Part
	for _, e := range ents {
		pn, _ := strconv.Atoi(e.Name())
		if pn <= partNumberMarker {
			continue
		}

		partPath := filepath.Join(objdir, uploadID, e.Name())
		b, err := xattr.Get(partPath, "user.etag")
		etag := string(b)
		if err != nil {
			etag = ""
		}

		fi, err := os.Lstat(partPath)
		if err != nil {
			continue
		}

		parts = append(parts, types.Part{
			PartNumber:   int32(pn),
			ETag:         &etag,
			LastModified: backend.GetTimePtr(fi.ModTime()),
			Size:         fi.Size(),
		})
	}

	sort.Slice(parts,
		func(i int, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })

	oldLen := len(parts)
	if len(parts) > maxParts {
		parts = parts[:maxParts]
	}
	newLen := len(parts)

	nextpart := int32(0)
	if len(parts) != 0 {
		nextpart = parts[len(parts)-1].PartNumber
	}

	userMetaData := make(map[string]string)
	upiddir := filepath.Join(objdir, uploadID)
	loadUserMetaData(upiddir, userMetaData)

	return &s3.ListPartsOutput{
		Bucket:               &bucket,
		IsTruncated:          oldLen != newLen,
		Key:                  &object,
		MaxParts:             int32(maxParts),
		NextPartNumberMarker: backend.GetStringPtr(fmt.Sprintf("%v", nextpart)),
		PartNumberMarker:     backend.GetStringPtr(fmt.Sprintf("%v", partNumberMarker)),
		Parts:                parts,
		UploadId:             &uploadID,
	}, nil
}

// TODO: copy part
// func (p *Posix) CopyPart(srcBucket, srcObject, DstBucket, uploadID, rangeHeader string, part int) (*types.CopyPartResult, error) {
// }

func (p *Posix) PutObjectPart(bucket, object, uploadID string, part int, length int64, r io.Reader) (string, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return "", fmt.Errorf("stat bucket: %w", err)
	}

	f, err := openTmpFile(".")
	if err != nil {
		return "", fmt.Errorf("open temp file: %w", err)
	}
	defer f.Close()

	hash := md5.New()
	tr := io.TeeReader(r, hash)
	_, err = io.Copy(f, tr)
	if err != nil {
		return "", fmt.Errorf("write part data: %w", err)
	}

	sum := sha256.Sum256([]byte(object))
	objdir := filepath.Join(bucket, metaTmpMultipartDir, fmt.Sprintf("%x", sum))
	partPath := filepath.Join(objdir, uploadID, fmt.Sprintf("%v", part))

	err = linkTmpFile(f, partPath)
	if err != nil {
		return "", fmt.Errorf("link object in namespace: %w", err)
	}

	dataSum := hash.Sum(nil)
	etag := hex.EncodeToString(dataSum[:])
	xattr.Set(partPath, "user.etag", []byte(etag))

	return etag, nil
}

func (p *Posix) PutObject(po *s3.PutObjectInput) (string, error) {
	_, err := os.Stat(*po.Bucket)
	if err != nil && os.IsNotExist(err) {
		return "", s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return "", fmt.Errorf("stat bucket: %w", err)
	}

	name := filepath.Join(*po.Bucket, *po.Key)

	etag := ""

	if strings.HasSuffix(*po.Key, "/") {
		// object is directory
		err = mkdirAll(name, os.FileMode(0755), *po.Bucket, *po.Key)
		if err != nil {
			return "", err
		}

		// TODO: set user attrs
		//for k, v := range metadata {
		//	xattr.Set(name, "user."+k, []byte(v))
		//}

		// set our tag that this dir was specifically put
		xattr.Set(name, dirObjKey, nil)
	} else {
		// object is file
		f, err := openTmpFile(".")
		if err != nil {
			return "", fmt.Errorf("open temp file: %w", err)
		}
		defer f.Close()

		// TODO: fallocate based on content length

		hash := md5.New()
		rdr := io.TeeReader(po.Body, hash)
		_, err = io.Copy(f, rdr)
		if err != nil {
			f.Close()
			return "", fmt.Errorf("write object data: %w", err)
		}
		dir := filepath.Dir(name)
		if dir != "" {
			err = mkdirAll(dir, os.FileMode(0755), *po.Bucket, *po.Key)
			if err != nil {
				f.Close()
				return "", fmt.Errorf("make object parent directories: %w", err)
			}
		}

		err = linkTmpFile(f, name)
		if err != nil {
			return "", fmt.Errorf("link object in namespace: %w", err)
		}

		// TODO: set user attrs
		//for k, v := range metadata {
		//	xattr.Set(name, "user."+k, []byte(v))
		//}

		dataSum := hash.Sum(nil)
		etag := hex.EncodeToString(dataSum[:])
		xattr.Set(name, "user.etag", []byte(etag))

		if newObjUID != 0 || newObjGID != 0 {
			err = os.Chown(name, newObjUID, newObjGID)
			if err != nil {
				return "", fmt.Errorf("set object uid/gid: %v", err)
			}
		}
	}

	return etag, nil
}

func (p *Posix) DeleteObject(bucket, object string) error {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}

	os.Remove(filepath.Join(bucket, object))
	if err != nil && os.IsNotExist(err) {
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return fmt.Errorf("delete object: %w", err)
	}

	return p.removeParents(bucket, object)
}

func (p *Posix) removeParents(bucket, object string) error {
	// this will remove all parent directories that were not
	// specifically uploaded with a put object. we detect
	// this with a special xattr to indicate these. stop
	// at either the bucket or the first parent we encounter
	// with the xattr, whichever comes first.
	objPath := filepath.Join(bucket, object)

	for {
		parent := filepath.Dir(objPath)

		if filepath.Base(parent) == bucket {
			break
		}

		_, err := xattr.Get(parent, dirObjKey)
		if err == nil {
			break
		}

		err = os.Remove(parent)
		if err != nil {
			break
		}

		objPath = parent
	}
	return nil
}

func (p *Posix) DeleteObjects(bucket string, objects *s3.DeleteObjectsInput) error {
	// delete object already checks bucket
	for _, obj := range objects.Delete.Objects {
		err := p.DeleteObject(bucket, *obj.Key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Posix) GetObject(bucket, object, acceptRange string, startOffset, length int64, writer io.Writer) (*s3.GetObjectOutput, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	objPath := filepath.Join(bucket, object)
	fi, err := os.Stat(objPath)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}

	if startOffset+length > fi.Size() {
		// TODO: is ErrInvalidRequest correct here?
		return nil, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	f, err := os.Open(objPath)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("open object: %w", err)
	}
	defer f.Close()

	rdr := io.NewSectionReader(f, startOffset, length)
	_, err = io.Copy(writer, rdr)
	if err != nil {
		return nil, fmt.Errorf("copy data: %w", err)
	}

	userMetaData := make(map[string]string)

	_, contentType, contentEncoding := loadUserMetaData(objPath, userMetaData)

	// TODO: fill range request header?
	// TODO: parse tags for tag count?
	return &s3.GetObjectOutput{
		AcceptRanges:    &acceptRange,
		ContentLength:   length,
		ContentEncoding: &contentEncoding,
		ContentType:     &contentType,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
	}, nil
}

func (p *Posix) HeadObject(bucket, object string, etag string) (*s3.HeadObjectOutput, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	objPath := filepath.Join(bucket, object)
	fi, err := os.Stat(objPath)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}

	userMetaData := make(map[string]string)
	_, contentType, contentEncoding := loadUserMetaData(filepath.Join(bucket, objPath), userMetaData)

	// TODO: fill accept ranges request header?
	// TODO: do we need to get etag from xattr?
	return &s3.HeadObjectOutput{
		ContentLength:   fi.Size(),
		ContentType:     &contentType,
		ContentEncoding: &contentEncoding,
		ETag:            &etag,
		LastModified:    backend.GetTimePtr(fi.ModTime()),
		Metadata:        userMetaData,
	}, nil
}

func (p *Posix) CopyObject(srcBucket, srcObject, DstBucket, dstObject string) (*s3.CopyObjectOutput, error) {
	_, err := os.Stat(srcBucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	_, err = os.Stat(DstBucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	objPath := filepath.Join(srcBucket, srcObject)
	f, err := os.Open(objPath)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchKey)
	}
	if err != nil {
		return nil, fmt.Errorf("stat object: %w", err)
	}
	defer f.Close()

	etag, err := p.PutObject(&s3.PutObjectInput{Bucket: &DstBucket, Key: &dstObject, Body: f})
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(filepath.Join(DstBucket, dstObject))
	if err != nil {
		return nil, fmt.Errorf("stat dst object: %w", err)
	}

	return &s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{
			ETag:         &etag,
			LastModified: backend.GetTimePtr(fi.ModTime()),
		},
	}, nil
}

func (p *Posix) ListObjects(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsOutput, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(fileSystem, prefix, delim, marker, maxkeys)
	if err != nil {
		return nil, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return &s3.ListObjectsOutput{
		CommonPrefixes: results.CommonPrefixes,
		Contents:       results.Objects,
		Delimiter:      &delim,
		IsTruncated:    results.Truncated,
		Marker:         &marker,
		MaxKeys:        int32(maxkeys),
		Name:           &bucket,
		NextMarker:     &results.NextMarker,
		Prefix:         &prefix,
	}, nil
}
func (p *Posix) ListObjectsV2(bucket, prefix, marker, delim string, maxkeys int) (*s3.ListObjectsV2Output, error) {
	_, err := os.Stat(bucket)
	if err != nil && os.IsNotExist(err) {
		return nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return nil, fmt.Errorf("stat bucket: %w", err)
	}

	fileSystem := os.DirFS(bucket)
	results, err := backend.Walk(fileSystem, prefix, delim, marker, maxkeys)
	if err != nil {
		return nil, fmt.Errorf("walk %v: %w", bucket, err)
	}

	return &s3.ListObjectsV2Output{
		CommonPrefixes:        results.CommonPrefixes,
		Contents:              results.Objects,
		Delimiter:             &delim,
		IsTruncated:           results.Truncated,
		ContinuationToken:     &marker,
		MaxKeys:               int32(maxkeys),
		Name:                  &bucket,
		NextContinuationToken: &results.NextMarker,
		Prefix:                &prefix,
	}, nil
}
