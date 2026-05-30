package v4

// IgnoredHeaders is a list of headers that are ignored during signing
var IgnoredHeaders = Rules{
	ExcludeList{
		MapRule{
			"Authorization":     struct{}{},
			"User-Agent":        struct{}{},
			"X-Amzn-Trace-Id":   struct{}{},
			"Expect":            struct{}{},
			"Transfer-Encoding": struct{}{},
		},
	},
}

// RequiredSignedHeaders are request headers that must be part of SignedHeaders
// whenever they are present on the request.
var RequiredSignedHeaders = Rules{
	AllowList{
		MapRule{
			"Host": struct{}{},
		},
	},
	Patterns{"X-Amz-"},
}

// AllowedQueryHoisting is a allowed list for Build query headers. The boolean value
// represents whether or not it is a pattern.
var AllowedQueryHoisting = InclusiveRules{
	ExcludeList{RequiredSignedHeaders},
	Patterns{"X-Amz-"},
}
