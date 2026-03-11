package command

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type queryPair struct {
	key   string
	value string
}

// awsQueryEscape applies the AWS SigV4 percent-encoding rules.
// - Spaces must be encoded as %20 (not '+')
// - '~' must not be escaped
func awsQueryEscape(s string) string {
	esc := url.QueryEscape(s)
	esc = strings.ReplaceAll(esc, "+", "%20")
	esc = strings.ReplaceAll(esc, "%7E", "~")
	return esc
}

// canonicalizeQuery converts a raw query string into an AWS SigV4 canonical query string.
// It percent-encodes keys/values, sorts them, and joins as k=v pairs.
func canonicalizeQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	// Treat bare subresource values like "cors" as "cors=".
	if !strings.Contains(raw, "=") && !strings.HasSuffix(raw, "=") {
		raw += "="
	}

	vals, err := url.ParseQuery(raw)
	if err != nil {
		return "", fmt.Errorf("error parsing query: %w", err)
	}

	pairs := getQueryPairs(vals)
	sort.Slice(pairs, func(i, j int) bool {
		escapedKeyI, escapedKeyJ := awsQueryEscape(pairs[i].key), awsQueryEscape(pairs[j].key)
		if escapedKeyI != escapedKeyJ {
			return escapedKeyI < escapedKeyJ
		}
		escapedValueI, escapedValueJ := awsQueryEscape(pairs[i].value), awsQueryEscape(pairs[j].value)
		return escapedValueI < escapedValueJ
	})

	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(awsQueryEscape(p.key))
		b.WriteByte('=')
		b.WriteString(awsQueryEscape(p.value))
	}
	return b.String(), nil
}

func getQueryPairs(values url.Values) []queryPair {
	pairs := make([]queryPair, 0, len(values))
	for queryKey, queryValues := range values {
		if len(queryValues) == 0 {
			pairs = append(pairs, queryPair{key: queryKey, value: ""})
			continue
		}
		for _, v := range queryValues {
			pairs = append(pairs, queryPair{key: queryKey, value: v})
		}
	}
	return pairs
}
