package integration

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

const (
	// parallelLimit defines the maximum number of concurrent goroutines
	// that can execute tests in parallel.
	parallelLimit int64 = 100
)

// TestState manages the execution of integration tests with optional
// parallelism and synchronization control.
type TestState struct {
	mainCh    chan IntTest        // Channel for queuing test functions to run (used in parallel mode)
	syncTests []IntTest           // Slice of test functions that must run synchronously after parallel ones
	conf      *S3Conf             // Shared S3 configuration for all tests
	sem       *semaphore.Weighted // Semaphore limiting the number of concurrent parallel tests
	wg        *sync.WaitGroup     // WaitGroup tracking running test goroutines
	ctx       context.Context     // Context for cancellation and graceful shutdown
	parallel  bool                // Whether tests should run in parallel or sequentially
}

// NewTestState initializes a new TestState instance. If parallel execution is enabled,
// it starts a background goroutine to process queued tests.
func NewTestState(ctx context.Context, conf *S3Conf, parallel bool) *TestState {
	ts := &TestState{
		mainCh:   make(chan IntTest, parallelLimit),
		conf:     conf,
		ctx:      ctx,
		sem:      semaphore.NewWeighted(parallelLimit),
		wg:       &sync.WaitGroup{},
		parallel: parallel,
	}

	// Start background test processor (only used in parallel mode)
	go ts.process()

	return ts
}

// Run executes a test function. In parallel mode, it enqueues the function
// for concurrent execution; otherwise, it runs the test immediately.
func (ct *TestState) Run(f IntTest) {
	select {
	case <-ct.ctx.Done():
		// Stop if context is canceled
		return
	default:
		if ct.parallel {
			// Queue test for background processing
			ct.mainCh <- f
			return
		}

		// Run test synchronously
		f(ct.conf)
	}
}

// Sync adds a test function to be executed synchronously after all parallel
// tests have completed. It will not execute immediately.
func (ct *TestState) Sync(f IntTest) {
	select {
	case <-ct.ctx.Done():
		// Stop if context is canceled
		return
	default:
		ct.syncTests = append(ct.syncTests, f)
	}
}

// process continuously reads from the test queue and executes each test
// in a controlled concurrent manner using a semaphore.
func (ct *TestState) process() {
	for fn := range ct.mainCh {
		select {
		case <-ct.ctx.Done():
			// Skip processing if context is canceled
			continue
		default:
			// Acquire semaphore to limit parallelism
			if err := ct.sem.Acquire(ct.ctx, 1); err != nil {
				continue
			}
			ct.wg.Add(1)
			go func() {
				// Run test and release semaphore once done
				fn(ct.conf)
				ct.sem.Release(1)
				ct.wg.Done()
			}()
		}
	}
}

// Wait blocks until all queued parallel tests complete, then runs all
// synchronous tests. It also ensures proper cleanup of the test channel.
func (ct *TestState) Wait() {
	// Wait for all parallel tests to finish
	ct.wg.Wait()
	close(ct.mainCh)

	// Run all synchronous tests sequentially
	for _, fn := range ct.syncTests {
		select {
		case <-ct.ctx.Done():
			// Stop if context is canceled before completion
			return
		default:
			fn(ct.conf)
		}
	}
}
