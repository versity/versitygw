package posix

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend/meta"
)

func TestListBucketsAndOwnersBucketLinks(t *testing.T) {
	a := assert.New(t)
	type link struct {
		from string
		to   string
	}
	testCases := []struct {
		name  string
		dirs  []string
		links []link
	}{
		{"empty", []string{}, nil},
		{"single", []string{"abucket"}, nil},
		{"basic three", []string{"ccc", "bbb", "aaa"}, nil},
		{"case sensitive", []string{"Ccc", "bBb", "aaA"}, nil},
		{"link single", []string{"frombucket"}, []link{{"frombucket", "tobucket"}}},
	}

	ctx := context.Background()
	var err error

	for _, tc := range testCases {
		gwDir := t.TempDir()

		var expected []string

		t.Logf("%s: working in gw dir [%s]", tc.name, gwDir)
		os.Chdir(gwDir)
		for _, dir := range tc.dirs {
			err = os.Mkdir(dir, 0755)
			if err != nil {
				t.Fatalf("Failed to setup test: Mkdir err %s", err)
			}
			expected = append(expected, dir)
		}
		for _, link := range tc.links {
			err = os.Symlink(link.from, link.to)
			if err != nil {
				t.Fatalf("Failed to setup test: Link err %s", err)
			}
			expected = append(expected, link.to)
		}

		meta := meta.XattrMeta{}
		var opts PosixOpts

		opts.BucketLinks = true

		p, err := New(gwDir, meta, opts)
		if err != nil {
			t.Errorf("Can't create posix backend")
		}
		resp, err := p.ListBucketsAndOwners(ctx)
		if err != nil {
			t.Fatalf("ListBucketsAndOwners failed: %s", err)
		}
		var got []string
		for _, bucket := range resp {
			got = append(got, bucket.Name)
		}
		sort.Strings(got)
		sort.Strings(expected)
		a.Equal(got, expected)
	}
}
