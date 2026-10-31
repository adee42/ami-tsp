package main

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/pbx"
)

// The shim ignores callbacks with a null procedure, so these run the real
// bookkeeping without a TapiSrv to talk to.

func testProvider() *providerState {
	return &providerState{
		callsByKey:   map[string]*callDev{},
		callsByToken: map[unsafe.Pointer]*callDev{},
	}
}

func outboundCall(p *providerState, key string) *callDev {
	c := &callDev{line: &lineDev{}, key: key, state: callStateFor(pbx.StateUnknown), awaiting: true}
	p.callsByKey[key] = c
	return c
}

// TestCallMessagesWaitForMakeCallCompletion: TSPI forbids call messages
// before the lineMakeCall request completes, and the PBX's events easily
// overtake the Originate response. They are held, then released in order.
func TestCallMessagesWaitForMakeCallCompletion(t *testing.T) {
	p := testProvider()
	c := outboundCall(p, "tag")

	p.fireCallState(c, callStateFor(pbx.StateDialing), 0)
	p.fireCallState(c, callStateFor(pbx.StateConnected), 0)
	if len(c.deferred) != 2 {
		t.Fatalf("%d messages held before completion, want 2", len(c.deferred))
	}

	p.finishMakeCall(c, 0, nil)
	if c.awaiting || len(c.deferred) != 0 {
		t.Errorf("after completion: awaiting=%v, %d messages still held", c.awaiting, len(c.deferred))
	}
	// The completion must not replace what the PBX reported with DIALING.
	if c.state != callStateFor(pbx.StateConnected) {
		t.Errorf("state after completion = 0x%x, want connected", c.state)
	}
}

// TestFailedMakeCallDropsHeldMessages: TAPI destroys a call whose request
// failed, so nothing held for it may be sent.
func TestFailedMakeCallDropsHeldMessages(t *testing.T) {
	p := testProvider()
	c := outboundCall(p, "tag")
	p.fireCallState(c, callStateFor(pbx.StateDialing), 0)

	p.finishMakeCall(c, 0, errors.New("Extension does not exist"))
	if !c.ended || len(c.deferred) != 0 {
		t.Errorf("after failure: ended=%v, %d messages held", c.ended, len(c.deferred))
	}
	if _, ok := p.callsByKey["tag"]; ok {
		t.Error("failed call still receives PBX events")
	}
}

// TestNothingFollowsIdle: a state reported after IDLE (the late DIALING of a
// call that had already ended was one) leaves a dead call on screen.
func TestNothingFollowsIdle(t *testing.T) {
	p := testProvider()
	c := &callDev{line: &lineDev{}, state: callStateFor(pbx.StateIdle)}
	p.fireCallState(c, callStateFor(pbx.StateDialing), 0)
	if c.state != callStateFor(pbx.StateIdle) {
		t.Errorf("state changed to 0x%x after IDLE", c.state)
	}
}

// TestPre12CallIsRebound: without ChannelId the call arrives under its own
// Uniqueid and names our tag in OriginateTag. It must reach the call
// lineMakeCall created, not become a second, unsolicited one.
func TestPre12CallIsRebound(t *testing.T) {
	p := testProvider()
	c := outboundCall(p, "tag")

	got := p.callForLocked(&pbx.Snapshot{Key: "1700000000.42", OriginateTag: "tag"})
	if got != c {
		t.Fatal("call not found by its originate tag")
	}
	if c.key != "1700000000.42" || p.callsByKey["1700000000.42"] != c {
		t.Error("call not moved to its Uniqueid")
	}
	if _, ok := p.callsByKey["tag"]; ok {
		t.Error("call still registered under the tag")
	}
}
