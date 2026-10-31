package main

import (
	"testing"
	"time"
)

// TSPI_providerShutdown runs its teardown through runBounded because TapiSrv
// is blocked inside that call, holding the lock that serialises the provider,
// with every TAPI application on the machine queued behind it. A teardown that
// cannot finish must degrade into a warning, never into a hang.
func TestRunBoundedGivesUpOnAStuckTeardown(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	if runBounded(50*time.Millisecond, func() { <-release }) {
		t.Fatal("runBounded reported success for a teardown that never finished")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("runBounded waited %v, far past its deadline", waited)
	}
}

func TestRunBoundedWaitsForATeardownThatFinishes(t *testing.T) {
	finished := false
	ok := runBounded(10*time.Second, func() {
		time.Sleep(10 * time.Millisecond)
		finished = true
	})
	if !ok {
		t.Fatal("runBounded timed out on a teardown that finishes promptly")
	}
	// Safe to read: runBounded only returns true after fn's goroutine closed
	// the channel it selects on.
	if !finished {
		t.Error("runBounded returned before the teardown completed")
	}
}

// Once TapiSrv has asked for shutdown, calling back into it is what deadlocks
// the Telephony service, so every callback site checks this first.
func TestCallbacksAreRefusedOnceClosing(t *testing.T) {
	p := &providerState{}
	if !p.callbacksAllowed() {
		t.Fatal("callbacks refused before shutdown was requested")
	}
	p.closing.Store(true)
	if p.callbacksAllowed() {
		t.Error("callbacks still permitted after shutdown was requested")
	}
}
