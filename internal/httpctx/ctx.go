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

package httpctx

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

// Ctx is the request context of the gateway servers, created by
// fiber.NewWithCustomCtx(NewCtx). Fiber normalizes every path it routes as
// RFC 3986 Section 6.2.2 describes: it decodes the escapes of unreserved
// characters and removes the "." and ".." segments, and DefaultCtx.Path
// returns that normalized path, an override included. An S3 path names a
// bucket and an object key, and S3 takes the key as it is: "a/../b",
// "x/." and "a%41" are keys of their own. Ctx keeps a path set by Path as
// it is and has fiber route routePath of it instead.
type Ctx struct {
	*fiber.DefaultCtx
	path    string
	hasPath bool
}

// NewCtx returns a new Ctx of app.
func NewCtx(app *fiber.App) fiber.CustomCtx {
	return &Ctx{DefaultCtx: fiber.NewDefaultCtx(app)}
}

// Reset prepares c for the request of fctx.
func (c *Ctx) Reset(fctx *fasthttp.RequestCtx) {
	c.DefaultCtx.Reset(fctx)
	c.path, c.hasPath = "", false
}

// Path returns the path set by the last override, or fiber's normalized
// path before one. An override is set as the request URI path, like fiber
// sets it, and fiber routes routePath of it.
func (c *Ctx) Path(override ...string) string {
	if len(override) != 0 {
		c.path, c.hasPath = override[0], true
		c.DefaultCtx.Path(routePath(c.path))
		if uri := c.Request().URI(); string(uri.PathOriginal()) != c.path {
			uri.SetPath(c.path)
		}
	}
	if c.hasPath {
		return c.path
	}
	return c.DefaultCtx.Path()
}

// routePath returns path with the bytes fiber's normalization changes
// replaced: every '%' and the dots of a "." or ".." segment are '_'. Fiber
// matches a route on the routed path but takes the route parameters from
// Path at the offsets of the match, so the two have the same length and
// the parameters hold the bytes of path.
func routePath(path string) string {
	if !strings.Contains(path, "%") && !strings.Contains(path, "/.") {
		return path
	}

	b := []byte(path)
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] != '/' {
			if b[j] == '%' {
				b[j] = '_'
			}
			j++
		}
		if seg := path[i:j]; seg == "." || seg == ".." {
			for k := i; k < j; k++ {
				b[k] = '_'
			}
		}
		i = j + 1
	}
	return string(b)
}
