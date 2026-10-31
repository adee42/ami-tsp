// Package pbx turns the AMI event stream into a call model that maps
// cleanly onto TAPI, and exposes the third-party call control actions the
// TSP needs. It knows nothing about TAPI types.
package pbx

import "time"

// State is a protocol-neutral call state. The TSP maps these to
// LINECALLSTATE_* values.
type State int

const (
	StateUnknown State = iota
	// StateOffering: an inbound call is alerting at our device.
	StateOffering
	// StateDialing: our device has gone off-hook / originate is in flight.
	StateDialing
	// StateProceeding: the network has accepted the digits.
	StateProceeding
	// StateRingback: the far end is alerting.
	StateRingback
	StateConnected
	StateOnHold
	StateBusy
	StateDisconnected
	StateIdle
)

func (s State) String() string {
	switch s {
	case StateOffering:
		return "offering"
	case StateDialing:
		return "dialing"
	case StateProceeding:
		return "proceeding"
	case StateRingback:
		return "ringback"
	case StateConnected:
		return "connected"
	case StateOnHold:
		return "onhold"
	case StateBusy:
		return "busy"
	case StateDisconnected:
		return "disconnected"
	case StateIdle:
		return "idle"
	}
	return "unknown"
}

// Call is the monitor's view of one Asterisk channel that belongs to a
// configured line. It is mutated only by the monitor goroutine.
type Call struct {
	// Key is the Asterisk Uniqueid; it is also the TSP's correlation handle.
	Key     string
	Channel string

	// LineIndex indexes Config.Lines.
	LineIndex int

	Inbound bool
	State   State

	// RemoteNumber/RemoteName are the other party as currently known. They
	// change over the life of a call (connected-line updates after a
	// transfer), which is why the TSP re-reads them on LINE_CALLINFO.
	RemoteNumber string
	RemoteName   string

	// LocalNumber is the number dialled to reach us (inbound) or our own
	// caller ID (outbound).
	LocalNumber string

	// HangupCause is the Asterisk (Q.850) cause code, set on Hangup.
	HangupCause int

	Created   time.Time
	Connected time.Time

	// announced is set once the call has been reported to the TAPI layer.
	// A channel is only announced when its direction is known, so that
	// applications never see a call appear with an unknown origin.
	announced bool

	// reported is what the TAPI layer was last told about this call. Changes
	// are published against it, so an event that repeats what is already
	// known produces nothing.
	reported *Snapshot

	// originateTag correlates an outbound call back to the Originate action
	// that created it.
	originateTag string

	// peerKey is the Uniqueid of the other leg of the same call, learned from
	// DialBegin and only ever set when both legs are our own devices. It is
	// what lets the calling device report ringback: the fact that it should be
	// ringing is only visible as a state change on the *called* leg.
	peerKey string
}

// Snapshot is an immutable copy handed to the TSP layer. The monitor never
// shares *Call across goroutines.
type Snapshot struct {
	Key          string
	Channel      string
	LineIndex    int
	Inbound      bool
	State        State
	RemoteNumber string
	RemoteName   string
	LocalNumber  string
	HangupCause  int
	OriginateTag string
	Created      time.Time
}

func (c *Call) snapshot() *Snapshot {
	return &Snapshot{
		Key:          c.Key,
		Channel:      c.Channel,
		LineIndex:    c.LineIndex,
		Inbound:      c.Inbound,
		State:        c.State,
		RemoteNumber: c.RemoteNumber,
		RemoteName:   c.RemoteName,
		LocalNumber:  c.LocalNumber,
		HangupCause:  c.HangupCause,
		OriginateTag: c.originateTag,
		Created:      c.Created,
	}
}

// EventType describes what changed.
type EventType int

const (
	// EventCallNew: a call became visible on a line. Always the first event
	// for a given Key.
	EventCallNew EventType = iota
	// EventCallState: the call state changed.
	EventCallState
	// EventCallInfo: caller/connected party information changed.
	EventCallInfo
	// EventCallEnd: the call is gone; the Key is retired after this.
	EventCallEnd
	// EventLink: the AMI connection came up or went down.
	EventLink
	// EventLineAdded: discovery appended a line device to the registry.
	// Always the first event for a given LineIndex, so that a call is never
	// announced on a line TAPI has not been told about yet. That ordering is
	// the reason discovery reports through this channel rather than calling
	// into the TSP directly.
	EventLineAdded
	// EventLineState: a line device came into or went out of service,
	// because the PBX gained or lost the underlying device.
	EventLineState
)

// Event is what the TSP layer consumes.
type Event struct {
	Type      EventType
	Call      *Snapshot
	LineIndex int
	Up        bool // for EventLink and EventLineState
}
