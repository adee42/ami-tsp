package ami

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/adee42/ami-tsp/internal/config"
)

// TestReachable covers the precondition that guards the startup probe. It must
// say yes to a listening port and no to a dead one, and it must never leave a
// connection behind — TapiSrv is blocked while this runs.
func TestReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	// Accept and discard, so a successful dial has something to talk to.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	live := config.AMI{Host: host, Port: port}
	if !Reachable(live, 2*time.Second) {
		t.Error("a listening port was reported unreachable")
	}

	// The same address with the listener gone: refused, and quickly.
	_ = ln.Close()
	started := time.Now()
	if Reachable(live, 2*time.Second) {
		t.Error("a closed port was reported reachable")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("a refused connection took %s; it should fail immediately", elapsed)
	}
}

// TestReachableRespectsTimeout: an unroutable address must give up inside the
// budget rather than hang the caller.
func TestReachableRespectsTimeout(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) and is not routed, so the dial
	// hangs rather than being refused — the case the timeout exists for.
	blackhole := config.AMI{Host: "203.0.113.1", Port: 5038}

	started := time.Now()
	if Reachable(blackhole, 500*time.Millisecond) {
		t.Error("an unroutable address was reported reachable")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("dial to a blackhole took %s, ignoring the 500ms timeout", elapsed)
	}
}
