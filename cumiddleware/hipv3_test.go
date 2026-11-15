package cumiddleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// newV3App builds a fiber app with the v3 middleware and a probe
// handler that reports whether the descriptor was stored.
func newV3App() (*fiber.App, *bool) {
	stored := new(bool)
	app := fiber.New()
	app.Use(RDMAv3Middleware(""))
	app.Get("/bucket/*", func(c fiber.Ctx) error {
		_, ok := GetV3Descriptor(c.RequestCtx())
		*stored = ok
		return c.SendString("get")
	})
	app.Put("/bucket/*", func(c fiber.Ctx) error {
		_, ok := GetV3Descriptor(c.RequestCtx())
		*stored = ok
		return c.SendString("put")
	})
	return app, stored
}

const v3GoodToken = "00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:0000000000100000"
const v3BadToken = "not-a-token"

func TestV3MiddlewareNoHeaderPasses(t *testing.T) {
	app, stored := newV3App()
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if *stored {
		t.Error("descriptor stored without header")
	}
}

func TestV3MiddlewareStoresValidToken(t *testing.T) {
	app, stored := newV3App()
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	req.Header.Set(HeaderRDMAv3Token, v3GoodToken)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !*stored {
		t.Error("descriptor not stored for valid token")
	}
}

func TestV3MiddlewareVersionedGetStays(t *testing.T) {
	app, stored := newV3App()
	req := httptest.NewRequest(http.MethodGet, "/bucket/key?versionId=abc", nil)
	req.Header.Set(HeaderRDMAv3Token, v3GoodToken)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !*stored {
		t.Error("versioned GET dropped off the v3 path")
	}
}

func TestV3MiddlewareUploadPartStays(t *testing.T) {
	app, stored := newV3App()
	req := httptest.NewRequest(http.MethodPut, "/bucket/key?uploadId=u&partNumber=1", nil)
	req.Header.Set(HeaderRDMAv3Token, v3GoodToken)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !*stored {
		t.Error("UploadPart dropped off the v3 path")
	}
}

func TestV3MiddlewareOtherOperationBypasses(t *testing.T) {
	for _, q := range []string{"?acl", "?tagging", "?uploads"} {
		app, stored := newV3App()
		req := httptest.NewRequest(http.MethodGet, "/bucket/key"+q, nil)
		req.Header.Set(HeaderRDMAv3Token, v3GoodToken)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if *stored {
			t.Errorf("query %q stayed on the v3 path", q)
		}
	}
}

func TestV3MiddlewareMalformedTokenIs400(t *testing.T) {
	app, _ := newV3App()
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	req.Header.Set(HeaderRDMAv3Token, v3BadToken)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestV3MiddlewareUnsupportedMethodBypasses(t *testing.T) {
	app := fiber.New()
	app.Use(RDMAv3Middleware(""))
	app.Post("/bucket/*", func(c fiber.Ctx) error { return c.SendString("post") })
	app.Delete("/bucket/*", func(c fiber.Ctx) error { return c.SendString("delete") })
	for _, m := range []string{http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequest(m, "/bucket/key", nil)
		req.Header.Set(HeaderRDMAv3Token, v3GoodToken)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s status = %d", m, resp.StatusCode)
		}
	}
}

// A virtual-hosted request reaches the middleware before the
// router's host-style parser rewrites its path, so the object
// predicate must recognize the bucket in the Host header: with the
// domain configured, /key on bucket.<domain> is an object and the
// token is enforced; without the domain configured it is not.
func TestV3MiddlewareVirtualHostedObject(t *testing.T) {
	stored := new(bool)
	app := fiber.New()
	app.Use(RDMAv3Middleware("s3.example.com"))
	app.Get("/*", func(c fiber.Ctx) error {
		_, ok := GetV3Descriptor(c.RequestCtx())
		*stored = ok
		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, "http://mybucket.s3.example.com/key", nil)
	req.Header.Set(HeaderRDMAv3Token, v3GoodToken)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !*stored {
		t.Error("virtual-hosted object request bypassed the v3 descriptor")
	}

	// Bucket-on-host with a malformed token is still a terminal 400.
	stored2 := new(bool)
	app2 := fiber.New()
	app2.Use(RDMAv3Middleware("s3.example.com"))
	app2.Get("/*", func(c fiber.Ctx) error {
		_, ok := GetV3Descriptor(c.RequestCtx())
		*stored2 = ok
		return c.SendString("ok")
	})
	req2 := httptest.NewRequest(http.MethodGet, "http://mybucket.s3.example.com/key", nil)
	req2.Header.Set(HeaderRDMAv3Token, v3BadToken)
	resp2, err := app2.Test(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("virtual-hosted malformed token status = %d, want 400", resp2.StatusCode)
	}

	// Service host without the virtual domain: /key is not an
	// object, the token is ignored.
	stored3 := new(bool)
	app3 := fiber.New()
	app3.Use(RDMAv3Middleware(""))
	app3.Get("/*", func(c fiber.Ctx) error {
		_, ok := GetV3Descriptor(c.RequestCtx())
		*stored3 = ok
		return c.SendString("ok")
	})
	req3 := httptest.NewRequest(http.MethodGet, "http://mybucket.s3.example.com/key", nil)
	req3.Header.Set(HeaderRDMAv3Token, v3GoodToken)
	resp3, err := app3.Test(req3)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp3.Body)
	resp3.Body.Close()
	if *stored3 {
		t.Error("virtual-hosted request stored a descriptor with no virtual domain configured")
	}
}
