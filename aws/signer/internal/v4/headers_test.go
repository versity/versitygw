package v4

import "testing"

func TestAllowedQueryHoisting(t *testing.T) {
	cases := map[string]struct {
		Header      string
		ExpectHoist bool
	}{
		"object-lock": {
			Header:      "X-Amz-Object-Lock-Mode",
			ExpectHoist: false,
		},
		"s3 metadata": {
			Header:      "X-Amz-Meta-SomeName",
			ExpectHoist: false,
		},
		"another header": {
			Header:      "X-Amz-SomeOtherHeader",
			ExpectHoist: false,
		},
		"lowercase amz header": {
			Header:      "x-amz-someotherheader",
			ExpectHoist: false,
		},
		"mixed case amz header": {
			Header:      "x-AmZ-someotherheader",
			ExpectHoist: false,
		},
		"non-amz content header": {
			Header:      "Content-Type",
			ExpectHoist: false,
		},
		"non X-AMZ header": {
			Header:      "X-SomeOtherHeader",
			ExpectHoist: false,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if e, a := c.ExpectHoist, AllowedQueryHoisting.IsValid(c.Header); e != a {
				t.Errorf("expect hoist %v, was %v", e, a)
			}
		})
	}
}

func TestRequiredSignedHeaders(t *testing.T) {
	cases := map[string]struct {
		Header         string
		ExpectRequired bool
	}{
		"known content header": {
			Header:         "Content-Type",
			ExpectRequired: false,
		},
		"known content header lowercase": {
			Header:         "content-type",
			ExpectRequired: false,
		},
		"known conditional header": {
			Header:         "If-Match",
			ExpectRequired: false,
		},
		"range header": {
			Header:         "Range",
			ExpectRequired: false,
		},
		"content md5 header": {
			Header:         "Content-Md5",
			ExpectRequired: false,
		},
		"arbitrary amz header": {
			Header:         "X-Amz-SomeOtherHeader",
			ExpectRequired: true,
		},
		"arbitrary amz header lowercase": {
			Header:         "x-amz-someotherheader",
			ExpectRequired: true,
		},
		"object-lock amz header": {
			Header:         "X-Amz-Object-Lock-Mode",
			ExpectRequired: true,
		},
		"metadata amz header": {
			Header:         "X-Amz-Meta-SomeName",
			ExpectRequired: true,
		},
		"non-amz custom header": {
			Header:         "X-SomeOtherHeader",
			ExpectRequired: false,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if e, a := c.ExpectRequired, RequiredSignedHeaders.IsValid(c.Header); e != a {
				t.Errorf("expect required %v, was %v", e, a)
			}
		})
	}
}

func TestIgnoredHeaders(t *testing.T) {
	cases := map[string]struct {
		Header        string
		ExpectIgnored bool
	}{
		"expect": {
			Header:        "Expect",
			ExpectIgnored: true,
		},
		"user-agent": {
			Header:        "User-Agent",
			ExpectIgnored: true,
		},
		"transfer-encoding": {
			Header:        "Transfer-Encoding",
			ExpectIgnored: true,
		},
		"authorization": {
			Header:        "Authorization",
			ExpectIgnored: true,
		},
		"authorization lowercase": {
			Header:        "authorization",
			ExpectIgnored: true,
		},
		"trace id lowercase": {
			Header:        "x-amzn-trace-id",
			ExpectIgnored: true,
		},
		"X-AMZ header": {
			Header:        "X-Amz-Content-Sha256",
			ExpectIgnored: false,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if e, a := c.ExpectIgnored, IgnoredHeaders.IsValid(c.Header); e == a {
				t.Errorf("expect ignored %v, was %v", e, a)
			}
		})
	}
}
