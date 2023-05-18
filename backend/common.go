package backend

import "github.com/aws/aws-sdk-go-v2/service/s3/types"

func IsValidBucketName(name string) bool { return true }

type ByBucketName []types.Bucket

func (d ByBucketName) Len() int           { return len(d) }
func (d ByBucketName) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d ByBucketName) Less(i, j int) bool { return *d[i].Name < *d[j].Name }
