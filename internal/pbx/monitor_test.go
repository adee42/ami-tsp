package pbx

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adee42/ami-tsp/internal/ami"
	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/lines"
)

// The registry is exercised here as the monitor's view of the device list.

// newTestMonitor builds a monitor over two phones without connecting to
// anything. NewMonitor does not touch the network until Start, so events can
// be fed straight into onAMIEvent.
func newTestMonitor(t *testing.T) *Monitor {
	t.Helper()
	reg, err := lines.Load(filepath.Join(t.TempDir(), "lines.json"))
	if err != nil {
		t.Fatal(err)
	}
	var found []lines.Entry
	for _, ch := range []string{"PJSIP/1001", "PJSIP/1002"} {
		e := lines.Entry{Line: config.Line{Channel: ch}}
		e.Line.Normalise()
		found = append(found, e)
	}
	reg.Merge(found)

	cfg := &config.Config{}
	disabled := false
	cfg.Discovery.Enabled = &disabled
	return NewMonitor(cfg, reg)
}

// feed delivers AMI packets in order, exactly as the reader goroutine would.
func feed(m *Monitor, packets ...*ami.Message) {
	for _, p := range packets {
		m.onAMIEvent(p)
	}
}

// trace drains the event channel into "line/kind/state" strings, which is a
// readable stand-in for what a TAPI application would be told.
func trace(m *Monitor) []string {
	var out []string
	for {
		select {
		case ev := <-m.events:
			kind := map[EventType]string{
				EventCallNew:   "new",
				EventCallState: "state",
				EventCallInfo:  "info",
				EventCallEnd:   "end",
			}[ev.Type]
			if kind == "" || ev.Call == nil {
				continue
			}
			out = append(out, fmt.Sprintf("%d/%s/%s", ev.LineIndex, kind, ev.Call.State))
		default:
			return out
		}
	}
}

func hasEvent(events []string, want string) bool {
	for _, e := range events {
		if e == want {
			return true
		}
	}
	return false
}

// statesFor returns the call states reported for one line, in order.
func statesFor(events []string, line int) []string {
	var out []string
	prefix := fmt.Sprintf("%d/", line)
	for _, e := range events {
		if strings.HasPrefix(e, prefix) {
			out = append(out, strings.TrimPrefix(e, prefix))
		}
	}
	return out
}

// TestInternalCallReportsBothLines is the regression this file exists for:
// 1001 calls 1002, and the calling line used to report nothing at all because
// DialBegin handled only the destination leg.
func TestInternalCallReportsBothLines(t *testing.T) {
	m := newTestMonitor(t)

	feed(m,
		// The caller's channel is created already off-hook.
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001", "Exten", "1002"),
		ami.NewMessage("Event", "NewExten", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"Extension", "1002", "Application", "Dial"),
		// Asterisk creates the callee's channel and dials it.
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "B", "Channel", "PJSIP/1002-00000002",
			"ChannelState", "0"),
		ami.NewMessage("Event", "DialBegin",
			"Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"DestUniqueid", "B", "DestChannel", "PJSIP/1002-00000002",
			"CallerIDNum", "1001", "CallerIDName", "Buero 1001", "DestExten", "1002"),
		// The callee starts ringing; the caller hears ringback.
		ami.NewMessage("Event", "Newstate", "Uniqueid", "B", "Channel", "PJSIP/1002-00000002",
			"ChannelState", "5", "CallerIDNum", "1001"),
		// Answer, then hang up.
		ami.NewMessage("Event", "Newstate", "Uniqueid", "B", "Channel", "PJSIP/1002-00000002", "ChannelState", "6"),
		ami.NewMessage("Event", "Newstate", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "ChannelState", "6"),
		ami.NewMessage("Event", "Hangup", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "Cause", "16"),
		ami.NewMessage("Event", "Hangup", "Uniqueid", "B", "Channel", "PJSIP/1002-00000002", "Cause", "16"),
	)

	events := trace(m)
	caller := statesFor(events, 0)
	callee := statesFor(events, 1)

	if len(caller) == 0 {
		t.Fatalf("the calling line reported nothing; all events: %v", events)
	}
	for _, want := range []string{
		"0/new/dialing",      // appears at off-hook
		"0/state/proceeding", // destination resolved
		"0/state/ringback",   // the called phone is ringing
		"0/state/connected",  // answered
		"0/end/disconnected", // cleared
	} {
		if !hasEvent(events, want) {
			t.Errorf("calling line missing %q; got %v", want, caller)
		}
	}

	// The called line must be unchanged by all this.
	for _, want := range []string{"1/new/offering", "1/state/connected", "1/end/disconnected"} {
		if !hasEvent(events, want) {
			t.Errorf("called line missing %q; got %v", want, callee)
		}
	}
	if hasEvent(events, "1/state/ringback") {
		t.Errorf("the called line must never report ringback; got %v", callee)
	}
}

// TestInternalCallDestinationNumber checks that each end is told who the other
// end is, which is what a screen pop displays.
func TestInternalCallDestinationNumber(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001"),
		ami.NewMessage("Event", "DialBegin",
			"Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"DestUniqueid", "B", "DestChannel", "PJSIP/1002-00000002",
			"CallerIDNum", "1001", "CallerIDName", "Buero 1001", "DestExten", "1002"),
	)
	_ = trace(m)

	caller, callee := m.calls["A"], m.calls["B"]
	if caller == nil {
		t.Fatal("no call tracked for the calling leg")
	}
	if caller.RemoteNumber != "1002" {
		t.Errorf("caller should be calling 1002, got %q", caller.RemoteNumber)
	}
	if caller.Inbound {
		t.Error("caller leg marked inbound")
	}
	// The callee leg had no Newchannel here, so DialBegin's channel-name
	// fallback is what must find it — or, as here, it stays untracked.
	if callee != nil && !callee.Inbound {
		t.Error("callee leg marked outbound")
	}
}

// lineStates drains the event channel and returns the in-service reports for
// one line index, in order.
func lineStates(m *Monitor, line int) []bool {
	var out []bool
	for {
		select {
		case ev := <-m.events:
			if ev.Type == EventLineState && ev.LineIndex == line {
				out = append(out, ev.Up)
			}
		default:
			return out
		}
	}
}

// TestDeletedDeviceComesBack: a device deleted from the PBX goes out of
// service, and a device that reappears must come back into service. The return
// half used to report nothing at all, leaving the line dead in every
// application until the service was restarted.
func TestDeletedDeviceComesBack(t *testing.T) {
	m := newTestMonitor(t) // PJSIP/1001 and PJSIP/1002

	both := []lines.Entry{
		{Line: config.Line{Channel: "PJSIP/1001"}},
		{Line: config.Line{Channel: "PJSIP/1002"}},
	}
	only1001 := both[:1]

	// Present, then deleted from the PBX, then restored. publishLineStates is
	// the same call runScan makes, so this exercises the real path.
	for _, found := range [][]lines.Entry{both, only1001, both} {
		m.reg.Merge(found)
		m.publishLineStates()
	}

	got := lineStates(m, 1)
	if len(got) != 3 || !got[0] || got[1] || !got[2] {
		t.Fatalf("line 1 state sequence = %v, want [true false true]", got)
	}

	// The untouched line is reported present once and never contradicted.
	for i, up := range lineStates(m, 0) {
		if !up {
			t.Errorf("line 0 reported out of service at report %d", i)
		}
	}
}

// TestOriginatedCallStaysOutbound: a call we place ourselves reaches the phone
// as the *destination* of a Dial, and Asterisk reports the phone itself as the
// connected party while it rings. Neither may turn the call into an inbound
// one from the user's own number.
func TestOriginatedCallStaysOutbound(t *testing.T) {
	m := newTestMonitor(t)

	// Register the originate the way Monitor.Originate does, then replay what
	// the PBX sends back.
	tag := "amitsp-test-tag"
	m.pending[tag] = &pendingOriginate{tag: tag, lineIndex: 0, dest: "83"}

	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", tag, "Channel", "PJSIP/1001-00000001",
			"ChannelState", "0"),
		ami.NewMessage("Event", "NewConnectedLine", "Uniqueid", tag, "Channel", "PJSIP/1001-00000001",
			"ConnectedLineNum", "1001", "ConnectedLineName", "Telefon-1001"),
		ami.NewMessage("Event", "DialBegin",
			"Uniqueid", "L", "Channel", "Local/83@ctx-00000000;1",
			"DestUniqueid", tag, "DestChannel", "PJSIP/1001-00000001",
			"CallerIDNum", "1001", "CallerIDName", "Telefon-1001"),
	)
	_ = trace(m)

	c := m.calls[tag]
	if c == nil {
		t.Fatal("originated call not tracked")
	}
	if c.Inbound {
		t.Error("an originated call was flipped to inbound")
	}
	if c.RemoteNumber != "83" {
		t.Errorf("destination overwritten with %q, want 83", c.RemoteNumber)
	}
}

// TestConnectedLineIgnoresOwnExtension guards the narrower rule on its own:
// the remote party is never this line's own extension.
func TestConnectedLineIgnoresOwnExtension(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001"),
		ami.NewMessage("Event", "NewExten", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"Extension", "1002", "Application", "Dial"),
		ami.NewMessage("Event", "NewConnectedLine", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ConnectedLineNum", "1001", "ConnectedLineName", "Telefon-1001"),
	)
	_ = trace(m)
	if c := m.calls["A"]; c.RemoteNumber != "1002" {
		t.Errorf("own extension leaked in as the remote party: %q", c.RemoteNumber)
	}

	// A genuine far party must still get through.
	feed(m, ami.NewMessage("Event", "NewConnectedLine", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
		"ConnectedLineNum", "1002", "ConnectedLineName", "Telefon-1002"))
	_ = trace(m)
	if c := m.calls["A"]; c.RemoteName != "Telefon-1002" {
		t.Errorf("real connected-line update was dropped: %+v", c)
	}
}

// TestExternalOutboundCall guards the path that already worked: the trunk leg
// is not one of our devices, so there is no peer and no ringback from it.
func TestExternalOutboundCall(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001"),
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "T", "Channel", "PJSIP/trunk-00000002",
			"ChannelState", "0"),
		ami.NewMessage("Event", "DialBegin",
			"Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"DestUniqueid", "T", "DestChannel", "PJSIP/trunk-00000002",
			"DestExten", "0049301234567"),
		ami.NewMessage("Event", "Newstate", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "ChannelState", "6"),
		ami.NewMessage("Event", "Hangup", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "Cause", "16"),
	)

	events := trace(m)
	if _, tracked := m.calls["T"]; tracked {
		t.Error("the trunk leg must not be tracked as a line")
	}
	for _, e := range events {
		if strings.HasPrefix(e, "1/") {
			t.Errorf("an external call produced events on the second line: %v", events)
			break
		}
	}
	for _, want := range []string{"0/new/dialing", "0/state/proceeding", "0/state/connected", "0/end/disconnected"} {
		if !hasEvent(events, want) {
			t.Errorf("missing %q; got %v", want, events)
		}
	}
	if c := m.calls["A"]; c != nil {
		t.Error("the call should have been retired on hangup")
	}
}

// TestExternalInboundCall guards direction: a call arriving from a trunk must
// stay inbound on exactly one line.
func TestExternalInboundCall(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "B", "Channel", "PJSIP/1001-00000009",
			"ChannelState", "0"),
		ami.NewMessage("Event", "DialBegin",
			"Uniqueid", "T", "Channel", "PJSIP/trunk-00000008",
			"DestUniqueid", "B", "DestChannel", "PJSIP/1001-00000009",
			"CallerIDNum", "0049301234567", "CallerIDName", "Ext Caller", "DestExten", "1001"),
		ami.NewMessage("Event", "Newstate", "Uniqueid", "B", "Channel", "PJSIP/1001-00000009", "ChannelState", "5"),
		ami.NewMessage("Event", "Newstate", "Uniqueid", "B", "Channel", "PJSIP/1001-00000009", "ChannelState", "6"),
	)

	events := trace(m)
	if !hasEvent(events, "0/new/offering") {
		t.Errorf("inbound call not offered; got %v", events)
	}
	c := m.calls["B"]
	if c == nil {
		t.Fatal("inbound call not tracked")
	}
	if !c.Inbound {
		t.Error("inbound call flipped to outbound")
	}
	if c.RemoteNumber != "0049301234567" {
		t.Errorf("caller ID lost, got %q", c.RemoteNumber)
	}
	for _, e := range events {
		if strings.HasPrefix(e, "1/") {
			t.Errorf("events leaked onto a second line: %v", events)
			break
		}
	}
}

// TestCallerAbandonsWhileDialling: hanging up before anything is dialled used
// to produce no events at all on the calling line.
func TestCallerAbandonsWhileDialling(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001"),
		ami.NewMessage("Event", "Hangup", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001", "Cause", "16"),
	)
	events := trace(m)
	if !hasEvent(events, "0/new/dialing") || !hasEvent(events, "0/end/disconnected") {
		t.Errorf("an abandoned dial must still open and close a call; got %v", events)
	}
}

// TestBusyDestination: DialEnd's BUSY now reaches an announced call.
func TestBusyDestination(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001"),
		ami.NewMessage("Event", "DialBegin",
			"Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"DestUniqueid", "B", "DestChannel", "PJSIP/1002-00000002", "DestExten", "1002"),
		ami.NewMessage("Event", "DialEnd", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"DialStatus", "BUSY"),
	)
	if events := trace(m); !hasEvent(events, "0/state/busy") {
		t.Errorf("busy destination not reported to the caller; got %v", events)
	}
}

// TestNewExtenTracksDestination covers the dialplan resolving a destination
// after the call object already exists.
func TestNewExtenTracksDestination(t *testing.T) {
	m := newTestMonitor(t)
	feed(m,
		ami.NewMessage("Event", "Newchannel", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"ChannelState", "4", "CallerIDNum", "1001"),
		ami.NewMessage("Event", "NewExten", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"Extension", "s", "Application", "NoOp"),
		ami.NewMessage("Event", "NewExten", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
			"Extension", "1002", "Application", "Dial"),
	)
	events := trace(m)
	if !hasEvent(events, "0/info/dialing") {
		t.Errorf("destination update not reported; got %v", events)
	}
	if c := m.calls["A"]; c == nil || c.RemoteNumber != "1002" {
		t.Errorf("destination not recorded, got %+v", c)
	}

	// Once connected, the connected-line events own the far party.
	m.calls["A"].State = StateConnected
	feed(m, ami.NewMessage("Event", "NewExten", "Uniqueid", "A", "Channel", "PJSIP/1001-00000001",
		"Extension", "9999", "Application", "Hangup"))
	_ = trace(m)
	if c := m.calls["A"]; c.RemoteNumber != "1002" {
		t.Errorf("a connected call had its destination overwritten with %q", c.RemoteNumber)
	}
}
