package pbx

import (
	"testing"
	"time"

	"github.com/adee42/ami-tsp/internal/ami"
)

// TestEventsAreNeverDropped: a burst far larger than the event channel (a
// ring-all queue ringing dozens of phones produces hundreds of events at once)
// must reach the consumer complete and in order. Events used to be discarded
// once 512 were waiting, and a discarded call end left a ghost call holding
// one of the line's call slots for good.
func TestEventsAreNeverDropped(t *testing.T) {
	m := newTestMonitor(t)
	const n = 5000

	m.mu.Lock()
	for i := 0; i < n; i++ {
		m.emit(Event{Type: EventLineState, LineIndex: i})
	}
	m.mu.Unlock()

	for i := 0; i < n; i++ {
		select {
		case ev := <-m.Events():
			if ev.LineIndex != i {
				t.Fatalf("event %d arrived as number %d: order lost", ev.LineIndex, i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d events arrived", i, n)
		}
	}

	// Once the backlog has drained, events go straight to the channel again.
	m.mu.Lock()
	m.emit(Event{Type: EventLink, Up: true})
	m.mu.Unlock()
	select {
	case ev := <-m.Events():
		if ev.Type != EventLink {
			t.Errorf("got %v after the backlog drained, want the link event", ev.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event after the backlog drained never arrived")
	}

	m.Stop()
	if _, open := <-m.Events(); open {
		t.Error("event channel still open after Stop")
	}
}

func coreShowChannel(kv ...string) *ami.Message {
	return ami.NewMessage(append([]string{"Event", "CoreShowChannel"}, kv...)...)
}

// TestResyncClearsVanishedCall: a call whose Hangup never arrived is cleared
// by the next channel listing, but a call that began after the listing was
// requested is left alone, since it could not have been in it.
func TestResyncClearsVanishedCall(t *testing.T) {
	m := newTestMonitor(t)
	feed(m, ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
		"ChannelState", "4"))
	time.Sleep(2 * time.Millisecond)
	started := time.Now()
	time.Sleep(2 * time.Millisecond)
	feed(m, ami.NewMessage("Event", "Newchannel", "Uniqueid", "B", "Channel", "PJSIP/1002-00000002",
		"ChannelState", "4"))
	_ = trace(m)

	m.mu.Lock()
	m.reconcile(started, nil)
	m.mu.Unlock()

	events := trace(m)
	if !hasEvent(events, "0/end/disconnected") {
		t.Errorf("vanished call not cleared; got %v", events)
	}
	if _, ok := m.calls["A"]; ok {
		t.Error("vanished call still tracked")
	}
	if _, ok := m.calls["B"]; !ok {
		t.Error("a call newer than the listing was cleared")
	}
}

// TestResyncAdoptsUntrackedCall: a call already in progress when the link
// came up is picked up from the channel listing.
func TestResyncAdoptsUntrackedCall(t *testing.T) {
	m := newTestMonitor(t)
	m.mu.Lock()
	m.reconcile(time.Now(), []*ami.Message{
		coreShowChannel("Uniqueid", "X", "Linkedid", "T", "Channel", "PJSIP/1002-00000003",
			"ChannelState", "6", "CallerIDNum", "1002", "ConnectedLineNum", "0049301234567"),
		// Not one of our lines.
		coreShowChannel("Uniqueid", "T", "Linkedid", "T", "Channel", "PJSIP/trunk-00000004",
			"ChannelState", "6"),
	})
	m.mu.Unlock()

	events := trace(m)
	if !hasEvent(events, "1/new/connected") {
		t.Fatalf("in-progress call not adopted; got %v", events)
	}
	c := m.calls["X"]
	if !c.Inbound {
		t.Error("a channel that did not start its call was adopted as outbound")
	}
	if c.RemoteNumber != "0049301234567" {
		t.Errorf("remote party = %q, want the connected line, not the device's own number", c.RemoteNumber)
	}
	if _, ok := m.calls["T"]; ok {
		t.Error("a trunk channel was adopted")
	}
}

// TestResyncDoesNotResurrectHungUpCall: a listing taken a moment before a
// hangup must not bring the call back after the Hangup has been processed.
func TestResyncDoesNotResurrectHungUpCall(t *testing.T) {
	m := newTestMonitor(t)
	feed(m, ami.NewMessage("Event", "Hangup", "Uniqueid", "Z", "Channel", "PJSIP/1001-00000005", "Cause", "16"))

	m.mu.Lock()
	m.reconcile(time.Now(), []*ami.Message{
		coreShowChannel("Uniqueid", "Z", "Linkedid", "Z", "Channel", "PJSIP/1001-00000005", "ChannelState", "6"),
	})
	m.mu.Unlock()

	if events := trace(m); len(events) != 0 {
		t.Errorf("a hung-up channel was adopted: %v", events)
	}
}

// TestLinkLossFailsPendingOriginate: an originate still waiting for its
// channel when the link drops will never get one, and the application's
// lineMakeCall must hear that rather than wait forever.
func TestLinkLossFailsPendingOriginate(t *testing.T) {
	m := newTestMonitor(t)
	m.pending["tag"] = &pendingOriginate{tag: "tag", lineIndex: 0, dest: "83", created: time.Now()}

	m.onLinkState(false)

	events := trace(m)
	if !hasEvent(events, "0/new/dialing") || !hasEvent(events, "0/end/disconnected") {
		t.Errorf("pending originate not failed on link loss; got %v", events)
	}
	if len(m.pending) != 0 {
		t.Error("pending originate survived the link loss")
	}
}

// TestStaleOriginateExpires: an originate that produced neither a channel nor
// an OriginateResponse is given up once its timeout has clearly passed.
func TestStaleOriginateExpires(t *testing.T) {
	m := newTestMonitor(t)
	m.pending["old"] = &pendingOriginate{tag: "old", lineIndex: 0, dest: "83", created: time.Now().Add(-time.Hour)}
	m.pending["new"] = &pendingOriginate{tag: "new", lineIndex: 0, dest: "84", created: time.Now()}

	m.mu.Lock()
	m.expire(time.Now())
	m.mu.Unlock()

	if _, ok := m.pending["old"]; ok {
		t.Error("an hour-old originate is still pending")
	}
	if _, ok := m.pending["new"]; !ok {
		t.Error("a fresh originate was given up")
	}
}

// TestAbandonedOriginateIsNotShown: once the Originate action has timed out
// the application has been told the call failed, so a channel the PBX creates
// for it afterwards must not appear as a call.
func TestAbandonedOriginateIsNotShown(t *testing.T) {
	m := newTestMonitor(t)
	m.abandoned["tag"] = time.Now()

	feed(m, ami.NewMessage("Event", "Newchannel", "Uniqueid", "tag", "Channel", "PJSIP/1001-00000006",
		"ChannelState", "4"))

	if events := trace(m); len(events) != 0 {
		t.Errorf("abandoned originate produced events: %v", events)
	}
	if _, ok := m.calls["tag"]; ok {
		t.Error("abandoned originate is being tracked")
	}
}

// TestUnknownDeviceAsksForOneScan: device state events fire on every call,
// so a device discovery will never accept (a trunk) used to request a scan
// every few seconds under load.
func TestUnknownDeviceAsksForOneScan(t *testing.T) {
	m := newTestMonitor(t)
	enabled := true
	m.cfg.Discovery.Enabled = &enabled

	scanRequested := func() bool {
		select {
		case <-m.rescan:
			return true
		default:
			return false
		}
	}

	feed(m, ami.NewMessage("Event", "DeviceStateChange", "Device", "PJSIP/trunk", "State", "INUSE"))
	if !scanRequested() {
		t.Fatal("first sighting of an unknown device requested no scan")
	}
	for i := 0; i < 5; i++ {
		feed(m, ami.NewMessage("Event", "DeviceStateChange", "Device", "PJSIP/trunk", "State", "NOT_INUSE"))
	}
	if scanRequested() {
		t.Error("the same unknown device requested a scan again")
	}

	for _, dev := range []string{"Queue:sales_avail", "Custom:DND1001", "PJSIP/1001"} {
		feed(m, ami.NewMessage("Event", "DeviceStateChange", "Device", dev, "State", "INUSE"))
		if scanRequested() {
			t.Errorf("device %q requested a scan", dev)
		}
	}
}

// TestRepeatedEventsReportOnce: an event that restates what the TSP already
// has produces nothing, which keeps bursts short.
func TestRepeatedEventsReportOnce(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "ChannelState", "4"),
		ami.NewMessage("Event", "Newstate", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "ChannelState", "6"),
		ami.NewMessage("Event", "Hold", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001"),
		ami.NewMessage("Event", "Hold", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001"),
	)
	n := 0
	for _, e := range trace(m) {
		if e == "0/state/onhold" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("hold reported %d times, want once", n)
	}
}

// TestRenameFollowsChannel: after a masquerade the call's channel has a new
// name, and actions on the call have to use it.
func TestRenameFollowsChannel(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "ChannelState", "4"),
		ami.NewMessage("Event", "Rename", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"Newname", "PJSIP/1001-00000007"),
	)
	ch, _, err := m.channelOf("A")
	if err != nil || ch != "PJSIP/1001-00000007" {
		t.Errorf("channel after rename = %q (%v), want PJSIP/1001-00000007", ch, err)
	}
}
