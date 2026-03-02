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

// # Walk benchmarks
//
// ## Quick start – run all small benchmarks
//
//	go test -bench='^BenchmarkWalk[^LH]' -benchtime=6x -count=6 ./backend/
//
// ## Run by tier
//
// Small  (5 k files):
//
//	go test -bench='^BenchmarkWalk[^LH]' -benchtime=6x -count=6 ./backend/
//
// Large (100 k files):
//
//	go test -bench='^BenchmarkWalkLarge' -benchtime=3x ./backend/
//
// Huge (500 k files):
//
//	go test -bench='^BenchmarkWalkHuge' -benchtime=3x ./backend/
//
// Note: Large and Huge benchmarks create fixture files under /tmp on first run.
// The fixtures are reused on subsequent runs as long as
// /tmp/versitygw_walk_bench/large is present. Remove that directory to force a
// full rebuild:
//
//	rm -rf /tmp/versitygw_walk_bench/large
//
// ## Comparing against main using benchstat
//
// Install benchstat if needed:
//
//	go install golang.org/x/perf/cmd/benchstat@latest
//
// 1. Record results on the current branch:
//
//	go test -bench='^BenchmarkWalk[^LH]' -benchtime=3x -count=6 ./backend/ > /tmp/new.txt
//
// 2. Create a worktree for main and record results there:
//
//	git worktree add /tmp/versitygw_main main
//	cp backend/walk_bench_test.go /tmp/versitygw_main/backend/
//	(cd /tmp/versitygw_main && go test -bench='^BenchmarkWalk[^LH]' -benchtime=3x -count=6 ./backend/ > /tmp/old.txt)
//	git worktree remove --force /tmp/versitygw_main
//
// 3. Compare:
//
//	benchstat /tmp/old.txt /tmp/new.txt
//
// Use -count=6 (minimum) for statistically meaningful p-values.
// Use -benchtime=3x (at least 3 iterations per count) to reduce per-run noise.
// For Large/Huge tiers use -benchtime=3x -count=1 (each op already takes seconds).
package backend_test

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

// benchRoot is the /tmp directory shared across all benchmarks in the run.
// It is created once by setupBenchDir and once (lazily) by setupLargeBenchDir.
const benchRoot = "/tmp/versitygw_walk_bench"

// Tier sizes:
//
//	Small   –   5000 files per tree
//	Large   – 100000 files per tree
//	Huge    – 500000 files flat only
var (
	benchSetupOnce      sync.Once
	benchLargeSetupOnce sync.Once
)

// parallelMkfile creates a batch of file paths in parallel using a worker
// pool sized to GOMAXPROCS, so setup time scales with CPU count.
func parallelMkfile(b *testing.B, paths []string) {
	b.Helper()
	workers := runtime.GOMAXPROCS(0)
	ch := make(chan string, workers*4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range ch {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				f, err := os.Create(path)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				_ = f.Close()
			}
		}()
	}
	for _, p := range paths {
		ch <- p
	}
	close(ch)
	wg.Wait()
	if firstErr != nil {
		b.Fatalf("bench setup: %v", firstErr)
	}
}

// Structure summary (files under benchRoot):
//
//	small/flat/       – 5000 files directly in the directory
//	small/deep/       – 100 top-level dirs × 50 files each = 5000 files (2 levels)
//	small/wide/       – 200 top-level dirs, 5 subdirs × 5 files = 5000 files (3 levels)
//	small/mixed/      – 10 prefix dirs × 100 files = 1000 files
//
//	large/flat/       – 100000 files flat
//	large/deep/       – 1000 dirs × 100 files = 100000 files
//	large/wide/       – 500 dirs × 10 subdirs × 20 files = 100000 files
//	large/mixed/      – 100 prefix dirs × 1 000 files = 100000 files
//	large/flat_huge/  – 500000 files flat
func setupBenchDir(b *testing.B) {
	b.Helper()
	benchSetupOnce.Do(func() {
		// Reuse fixtures from a previous run if they exist.
		sentinel := filepath.Join(benchRoot, "small", "flat", "file04999.txt")
		if _, err := os.Stat(sentinel); err == nil {
			return
		}
		_ = os.RemoveAll(filepath.Join(benchRoot, "small"))

		var paths []string

		// small/flat/ – 5000 files
		for i := range 5000 {
			paths = append(paths, filepath.Join(benchRoot, "small", "flat", fmt.Sprintf("file%05d.txt", i)))
		}

		// small/deep/ – 100 dirs × 50 files
		for i := range 100 {
			for j := range 50 {
				paths = append(paths, filepath.Join(benchRoot, "small", "deep",
					fmt.Sprintf("dir%03d", i),
					fmt.Sprintf("file%03d.txt", j)))
			}
		}

		// small/wide/ – 200 dirs × 5 subdirs × 5 files
		for i := range 200 {
			for j := range 5 {
				for k := range 5 {
					paths = append(paths, filepath.Join(benchRoot, "small", "wide",
						fmt.Sprintf("dir%03d", i),
						fmt.Sprintf("sub%02d", j),
						fmt.Sprintf("file%02d.txt", k)))
				}
			}
		}

		// small/mixed/ – 10 prefix dirs × 100 files
		for i := range 10 {
			for j := range 100 {
				paths = append(paths, filepath.Join(benchRoot, "small", "mixed",
					fmt.Sprintf("prefix%02d", i),
					fmt.Sprintf("file%04d.txt", j)))
			}
		}

		parallelMkfile(b, paths)
	})
}

func setupLargeBenchDir(b *testing.B) {
	b.Helper()
	setupBenchDir(b) // ensure small/ exists too
	benchLargeSetupOnce.Do(func() {
		// Reuse fixtures from a previous run if they exist.
		sentinel := filepath.Join(benchRoot, "large", "flat_huge", "file0499999.txt")
		if _, err := os.Stat(sentinel); err == nil {
			return
		}
		_ = os.RemoveAll(filepath.Join(benchRoot, "large"))
		var paths []string

		// large/flat/ – 100000 files flat
		for i := range 100_000 {
			paths = append(paths, filepath.Join(benchRoot, "large", "flat", fmt.Sprintf("file%06d.txt", i)))
		}

		// large/deep/ – 1000 dirs × 100 files = 100000 files
		for i := range 1000 {
			for j := range 100 {
				paths = append(paths, filepath.Join(benchRoot, "large", "deep",
					fmt.Sprintf("dir%04d", i),
					fmt.Sprintf("file%03d.txt", j)))
			}
		}

		// large/wide/ – 500 dirs × 10 subdirs × 20 files = 100000 files
		for i := range 500 {
			for j := range 10 {
				for k := range 20 {
					paths = append(paths, filepath.Join(benchRoot, "large", "wide",
						fmt.Sprintf("dir%03d", i),
						fmt.Sprintf("sub%02d", j),
						fmt.Sprintf("file%02d.txt", k)))
				}
			}
		}

		// large/mixed/ – 100 prefix dirs × 1000 files = 100000 files
		for i := range 100 {
			for j := range 1000 {
				paths = append(paths, filepath.Join(benchRoot, "large", "mixed",
					fmt.Sprintf("prefix%03d", i),
					fmt.Sprintf("file%05d.txt", j)))
			}
		}

		// large/flat_huge/ – 500000 files flat
		for i := range 500_000 {
			paths = append(paths, filepath.Join(benchRoot, "large", "flat_huge", fmt.Sprintf("file%07d.txt", i)))
		}

		b.Log("creating large bench fixtures (this runs once per /tmp clean)...")
		parallelMkfile(b, paths)
	})
}

// benchGetObj is a lightweight GetObjFunc that mimics what the POSIX backend
// does: stat the entry and populate the minimum Object fields, returning
// ErrSkipObj for bare directories (no stored etag = no explicit S3 PUT).
func benchGetObj(path string, d fs.DirEntry) (s3response.Object, error) {
	if d.IsDir() {
		return s3response.Object{}, backend.ErrSkipObj
	}
	fi, err := d.Info()
	if err != nil {
		return s3response.Object{}, err
	}
	sz := fi.Size()
	mt := fi.ModTime()
	etag := path // cheap stand-in; avoids md5 cost skewing the walk measurement
	return s3response.Object{
		Key:          &path,
		Size:         &sz,
		LastModified: &mt,
		ETag:         &etag,
	}, nil
}

// runWalk is a convenience wrapper so each benchmark loop is one line.
func runWalk(b *testing.B, fsys fs.FS, prefix, delim, marker string, max int32) {
	b.Helper()
	_, err := backend.Walk(context.Background(), fsys, prefix, delim, marker, max, benchGetObj, nil)
	if err != nil {
		b.Fatalf("Walk: %v", err)
	}
}

// ── Small (5 k files) ─────────────────────────────────────────────────────────

// BenchmarkWalkFlat lists all 5000 files in a single flat directory.
func BenchmarkWalkFlat(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "flat"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 10000)
	}
}

// BenchmarkWalkFlatDelim lists with a "/" delimiter (all files collapse into
// the root; tests the common-prefix fast-path for a flat bucket).
func BenchmarkWalkFlatDelim(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "flat"))
	for b.Loop() {
		runWalk(b, fsys, "", "/", "", 10000)
	}
}

// BenchmarkWalkFlatPaged benchmarks paginated listing (1000 objects per page,
// walking through 5 pages of the flat directory).
func BenchmarkWalkFlatPaged(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "flat"))
	for b.Loop() {
		marker := ""
		for {
			res, err := backend.Walk(context.Background(),
				fsys, "", "", marker, 1000, benchGetObj, nil)
			if err != nil {
				b.Fatalf("Walk: %v", err)
			}
			if !res.Truncated {
				break
			}
			marker = res.NextMarker
		}
	}
}

// BenchmarkWalkDeep lists all files recursively through 2 levels of dirs.
func BenchmarkWalkDeep(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "deep"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 10000)
	}
}

// BenchmarkWalkDeepDelim lists with "/" delimiter, returning 100 common
// prefixes instead of descending into every directory.
func BenchmarkWalkDeepDelim(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "deep"))
	for b.Loop() {
		runWalk(b, fsys, "", "/", "", 10000)
	}
}

// BenchmarkWalkWide lists all 5000 files across a wide tree (3 levels).
func BenchmarkWalkWide(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "wide"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 10000)
	}
}

// BenchmarkWalkWideDelim collapses the wide tree to the top-level dirs.
func BenchmarkWalkWideDelim(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "wide"))
	for b.Loop() {
		runWalk(b, fsys, "", "/", "", 10000)
	}
}

// BenchmarkWalkWithPrefix exercises the prefix-optimisation.
func BenchmarkWalkWithPrefix(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small"))
	for b.Loop() {
		runWalk(b, fsys, "mixed/prefix05/", "", "", 1000)
	}
}

// BenchmarkWalkWithPrefixDelim lists with a prefix and delimiter.
func BenchmarkWalkWithPrefixDelim(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small"))
	for b.Loop() {
		runWalk(b, fsys, "mixed/", "/", "", 1000)
	}
}

// BenchmarkWalkWithMarker benchmarks resuming a listing mid-way through the
// mixed/ prefix (simulates the second page of a paginated request).
func BenchmarkWalkWithMarker(b *testing.B) {
	setupBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "small"))
	marker := "mixed/prefix05/file0050.txt"
	for b.Loop() {
		runWalk(b, fsys, "mixed/", "", marker, 1000)
	}
}

// ── Large (100 k files) ──────────────────────────────────────────
// Run with: go test -bench=WalkLarge -benchtime=10s ./backend/

// BenchmarkWalkLargeFlat lists 100000 files in a flat directory.
func BenchmarkWalkLargeFlat(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "flat"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 200000)
	}
}

// BenchmarkWalkLargeFlatDelim collapses 100000 flat files under a "/" delimiter.
func BenchmarkWalkLargeFlatDelim(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "flat"))
	for b.Loop() {
		runWalk(b, fsys, "", "/", "", 200000)
	}
}

// BenchmarkWalkLargeFlatPaged pages through 100000 flat files, 1000 per page.
func BenchmarkWalkLargeFlatPaged(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "flat"))
	for b.Loop() {
		marker := ""
		for {
			res, err := backend.Walk(context.Background(),
				fsys, "", "", marker, 1000, benchGetObj, nil)
			if err != nil {
				b.Fatalf("Walk: %v", err)
			}
			if !res.Truncated {
				break
			}
			marker = res.NextMarker
		}
	}
}

// BenchmarkWalkLargeDeep fully recurses through 1000 dirs × 100 files.
func BenchmarkWalkLargeDeep(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "deep"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 200000)
	}
}

// BenchmarkWalkLargeDeepDelim lists 1000 common-prefixes without recursing.
func BenchmarkWalkLargeDeepDelim(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "deep"))
	for b.Loop() {
		runWalk(b, fsys, "", "/", "", 200000)
	}
}

// BenchmarkWalkLargeWide fully recurses a 3-level wide tree (100000 files).
func BenchmarkWalkLargeWide(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "wide"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 200000)
	}
}

// BenchmarkWalkLargeWideDelim collapses the wide tree to its 500 top-level dirs.
func BenchmarkWalkLargeWideDelim(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "wide"))
	for b.Loop() {
		runWalk(b, fsys, "", "/", "", 200000)
	}
}

// BenchmarkWalkLargeWithPrefix jumps directly into a subdirectory via prefix.
func BenchmarkWalkLargeWithPrefix(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large"))
	for b.Loop() {
		runWalk(b, fsys, "mixed/prefix050/", "", "", 5000)
	}
}

// BenchmarkWalkLargeWithMarker resumes a listing mid-way through a 100000-file tree.
func BenchmarkWalkLargeWithMarker(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large"))
	marker := "mixed/prefix050/file00500.txt"
	for b.Loop() {
		runWalk(b, fsys, "mixed/", "", marker, 5000)
	}
}

// ── Huge (500 k files) ────────────────────────────────────────────
// Run with: go test -bench=WalkHuge -benchtime=3x ./backend/
// (use -benchtime=Nx to limit iterations given each op is >1 s)

// BenchmarkWalkHugeFlat fully lists 500000 files in a single directory.
func BenchmarkWalkHugeFlat(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "flat_huge"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 1_000_000)
	}
}

// BenchmarkWalkHugeFlatMarker resumes a listing mid-way through 500000 flat
// files returning the next 1000.
func BenchmarkWalkHugeFlatMarker(b *testing.B) {
	setupLargeBenchDir(b)
	fsys := os.DirFS(filepath.Join(benchRoot, "large", "flat_huge"))
	// Marker sits at roughly the 50% point of the flat listing.
	marker := fmt.Sprintf("file%07d.txt", 250_000)
	for b.Loop() {
		runWalk(b, fsys, "", "", marker, 1000)
	}
}

// ── Timing sanity check ───────────────────────────────────────────────────────

// BenchmarkWalkSetupTime measures just the one-time setup cost.
func BenchmarkWalkSetupTime(b *testing.B) {
	start := time.Now()
	setupBenchDir(b)
	b.ReportMetric(float64(time.Since(start).Milliseconds()), "setup_ms")
	fsys := os.DirFS(filepath.Join(benchRoot, "small", "flat"))
	for b.Loop() {
		runWalk(b, fsys, "", "", "", 1)
	}
}
