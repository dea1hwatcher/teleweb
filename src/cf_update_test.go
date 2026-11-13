package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCFDomainsUpdater_SuccessImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	mockRefresh := func(ctx context.Context) error {
		attempts.Add(1)
		return nil
	}

	done := make(chan struct{})
	go func() {
		// 10ms initial delay, 10ms retry delay, 100ms max retry, 30ms steady interval
		runCFDomainsUpdater(ctx, mockRefresh, 10*time.Millisecond, 10*time.Millisecond, 100*time.Millisecond, 30*time.Millisecond)
		close(done)
	}()

	time.Sleep(25 * time.Millisecond)
	if attempts.Load() != 1 {
		t.Fatalf("expected 1 attempt after initial delay, got %d", attempts.Load())
	}

	time.Sleep(40 * time.Millisecond)
	if attempts.Load() < 2 {
		t.Fatalf("expected >= 2 attempts after steady tick, got %d", attempts.Load())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("updater did not stop upon context cancellation")
	}
}

func TestCFDomainsUpdater_EarlyBootRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	mockRefresh := func(ctx context.Context) error {
		if attempts.Add(1) < 3 {
			return errors.New("simulated network not ready")
		}
		return nil
	}

	done := make(chan struct{})
	go func() {
		// Use tiny intervals for fast, deterministic unit testing
		initialDelay := 5 * time.Millisecond
		initialRetry := 10 * time.Millisecond
		maxRetry := 200 * time.Millisecond
		steadyInterval := 500 * time.Millisecond

		// Test logic: run with short context
		runCFDomainsUpdater(ctx, mockRefresh, initialDelay, initialRetry, maxRetry, steadyInterval)
		close(done)
	}()

	// Wait enough for initial + 2 retries
	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("updater did not stop upon context cancellation")
	}

	if count := attempts.Load(); count < 3 {
		t.Fatalf("expected at least 3 attempts to succeed after retries, got %d", count)
	}
}
