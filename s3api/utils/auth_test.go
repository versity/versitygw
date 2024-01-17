package utils

import (
	"testing"
)

func TestAuthParse(t *testing.T) {
	vectors := []struct {
		name    string // name of test string
		authstr string // Authorization string
		algo    string
		sig     string
	}{{
		name:    "restic",
		authstr: "AWS4-HMAC-SHA256 Credential=user/20240116/us-east-1/s3/aws4_request,SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length,Signature=d5199fc7f3aa35dd3d400427be2ae4c98bfad390785280cbb9eea015b51e12ac",
		algo:    "AWS4-HMAC-SHA256",
		sig:     "d5199fc7f3aa35dd3d400427be2ae4c98bfad390785280cbb9eea015b51e12ac",
	},
		{
			name:    "aws eaxample",
			authstr: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
			algo:    "AWS4-HMAC-SHA256",
			sig:     "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
		}}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			data, err := ParseAuthorization(v.authstr)
			if err != nil {
				t.Fatal(err)
			}
			if data.Algorithm != v.algo {
				t.Errorf("algo got %v, expected %v", data.Algorithm, v.algo)
			}
			if data.Signature != v.sig {
				t.Errorf("signature got %v, expected %v", data.Signature, v.sig)
			}
		})
	}
}
