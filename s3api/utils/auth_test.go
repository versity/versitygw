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

package utils

import (
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttputil"
	v4 "github.com/versity/versitygw/aws/signer/v4"
)

func TestAuthParse(t *testing.T) {
	vectors := []struct {
		name    string // name of test string
		authstr string // Authorization string
		algo    string
		sig     string
	}{
		{
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
		},
		{
			name:    "s3browser",
			authstr: "AWS4-HMAC-SHA256 Credential=access_key/20240206/us-east-1/s3/aws4_request,SignedHeaders=host;user-agent;x-amz-content-sha256;x-amz-date, Signature=37a35d96998d786113ad420c57c22c5433f6aca74f88f26566caa047fc3601c6",
			algo:    "AWS4-HMAC-SHA256",
			sig:     "37a35d96998d786113ad420c57c22c5433f6aca74f88f26566caa047fc3601c6",
		},
	}

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

// 2024/02/06 21:03:28 Request headers:
// 2024/02/06 21:03:28 Host: 172.21.0.160:11000
// 2024/02/06 21:03:28 User-Agent: S3 Browser/11.5.7 (https://s3browser.com)
// 2024/02/06 21:03:28 Authorization: AWS4-HMAC-SHA256 Credential=access_key/20240206/us-east-1/s3/aws4_request,SignedHeaders=host;user-agent;x-amz-content-sha256;x-amz-date, Signature=37a35d96998d786113ad420c57c22c5433f6aca74f88f26566caa047fc3601c6
// 2024/02/06 21:03:28 X-Amz-Content-Sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
// 2024/02/06 21:03:28 X-Amz-Date: 20240206T210328Z
func Test_Client_UserAgent(t *testing.T) {
	signedHdrs := []string{"host", "user-agent", "x-amz-content-sha256", "x-amz-date"}
	access := "access_key"
	secret := "secret_key"
	region := "us-east-1"
	host := "172.21.0.160:11000"
	agent := "S3 Browser/11.5.7 (https://s3browser.com)"
	expectedSig := "37a35d96998d786113ad420c57c22c5433f6aca74f88f26566caa047fc3601c6"
	dateStr := "20240206T210328Z"

	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	tdate, err := time.Parse(iso8601Format, dateStr)
	if err != nil {
		t.Fatal(err)
	}

	app.Get("/", func(c *fiber.Ctx) error {
		req, err := createHttpRequestFromCtx(c, signedHdrs, int64(c.Request().Header.ContentLength()))
		if err != nil {
			t.Fatal(err)
		}

		req.Host = host
		req.Header.Set("X-Amz-Content-Sha256", zeroLenSig)

		signer := v4.NewSigner()

		signErr := signer.SignHTTP(req.Context(),
			aws.Credentials{
				AccessKeyID:     access,
				SecretAccessKey: secret,
			},
			req, zeroLenSig, service, region, tdate, signedHdrs,
			func(options *v4.SignerOptions) {
				options.DisableURIPathEscaping = true
			})
		if signErr != nil {
			t.Fatalf("sign generated http request: %v", err)
		}

		genAuth, err := ParseAuthorization(req.Header.Get("Authorization"))
		if err != nil {
			return err
		}

		if genAuth.Signature != expectedSig {
			t.Errorf("SIG: %v\nexpected: %v\n", genAuth.Signature, expectedSig)
		}

		return c.Send(c.Request().Header.UserAgent())
	})

	ln := fasthttputil.NewInmemoryListener()
	go func() {
		err := app.Listener(ln)
		if err != nil {
			panic(err)
		}
	}()

	c := fiber.AcquireClient()
	c.UserAgent = agent
	a := c.Get("http://example.com")
	a.HostClient.Dial = func(_ string) (net.Conn, error) { return ln.Dial() }
	a.String()
	fiber.ReleaseClient(c)
}
