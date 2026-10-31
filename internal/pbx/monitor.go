package pbx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/adee42/ami-tsp/internal/ami"
	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/lines"
	"github.com/adee42/ami-tsp/internal/logx"
)

// Asterisk channel states as reported by Newchannel/Newstate.
const (
	chanDown    = 0
	chanRsrvd   = 1
	chanOffHook = 2
	chanDialing = 3
	chanRing    = 4 // a device is dialling into us; caller hears ringback
	chanRinging = 5 // we are ringing a device
	chanUp      = 6
	chanBusy    = 7
)

// eventFilter is the whitelist installed on the AMI session (see
// ami.Client.SetEventFilter): every event onAMIEvent handles, and the one
// VarSet that carries an originate tag. It is a POSIX extended regular
// expression matched anywhere in the event text, so "Event: Dial" also covers
// DialBegin and DialEnd.
//
// Without it Asterisk sends everything the manager account may read, and on a
// busy PBX that is mostly noise: VarSet for every Set() in the dialplan, RTCP
// reports for every media stream, CDR and CEL records. All of it would pass
// through the single reader goroutine that also carries the responses to our
// own actions.
const eventFilter = `Event: (Newchannel|Newstate|Dial|Newexten|NewConnectedLine|NewCallerid|Hold|Unhold|Hangup|Rename|OriginateResponse|DeviceStateChange|ContactStatus|PeerStatus)|Variable: AMITSP_ID`

const (
	// maxBacklog bounds the events queued for a consumer that has stopped
	// draining. It is far beyond any burst a working TapiSrv produces; reaching
	// it means the consumer is wedged, and the memory is better kept.
	maxBacklog = 100000

	// goneRetention is how long a Uniqueid is remembered after its Hangup, so
	// that a resync whose channel list was taken just before the hangup does
	// not bring the call back.
	goneRetention = 10 * time.Minute

	// originateGrace is added to the originate timeout before an originate
	// that never produced a channel or an OriginateResponse is given up.
	originateGrace = 30 * time.Second
)

// Monitor maintains the call model for all configured lines.
//
// All state transitions happen on the AMI reader goroutine (inside the
// onEvent callback), which gives us ordering for free. Events are published
// without ever blocking the reader and without ever being dropped: see emit.
type Monitor struct {
	cfg *config.Config
	cli *ami.Client

	// reg is the line device registry, shared with the TSP layer. Line
	// indices in every event refer to it.
	reg *lines.Registry

	mu      sync.Mutex
	calls   map[string]*Call // Uniqueid -> call
	byChan  map[string]*Call // lower-case channel name -> call
	pending map[string]*pendingOriginate

	// abandoned holds originates whose Originate action timed out. The TSP
	// has already failed the request, so a channel that turns up for one
	// anyway is hung up rather than presented as a call nobody asked for.
	abandoned map[string]time.Time

	// gone remembers recently hung-up Uniqueids; see goneRetention.
	gone map[string]time.Time

	// events is the stream the TSP consumes. backlog holds what did not fit
	// while the consumer was busy, in order; see emit.
	events   chan Event
	backlog  []Event
	flushing bool
	flushWG  sync.WaitGroup
	closed   bool

	// published is the presence last reported for each line index, so that a
	// scan only reports lines whose presence actually changed.
	published map[int]bool

	// scanTried holds devices (lower-case "pjsip/name") that have already
	// triggered a scan, or that a scan rejected. A device seen again after
	// that is not new and is left to the periodic scan.
	scanTried map[string]bool

	// rescan carries discovery triggers; see scanLoop. resync carries
	// channel list reconciliation triggers; see syncLoop.
	rescan chan struct{}
	resync chan struct{}

	stopCh chan struct{}
	stopOn sync.Once
	wg     sync.WaitGroup
}

type pendingOriginate struct {
	tag       string
	lineIndex int
	dest      string
	created   time.Time
}

// NewMonitor creates a monitor over a line registry. Start must be called to
// connect.
func NewMonitor(cfg *config.Config, reg *lines.Registry) *Monitor {
	m := &Monitor{
		cfg:       cfg,
		reg:       reg,
		calls:     make(map[string]*Call),
		byChan:    make(map[string]*Call),
		pending:   make(map[string]*pendingOriginate),
		abandoned: make(map[string]time.Time),
		gone:      make(map[string]time.Time),
		events:    make(chan Event, 512),
		published: make(map[int]bool),
		scanTried: make(map[string]bool),
		rescan:    make(chan struct{}, 1),
		resync:    make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
	m.cli = ami.New(cfg.AMI, m.onAMIEvent, m.onLinkState)
	if cfg.AMI.FilterEvents() {
		m.cli.SetEventFilter(eventFilter)
	}
	return m
}

func (m *Monitor) Start() {
	m.cli.Start()
	m.wg.Add(1)
	go m.syncLoop()
	if m.cfg.Discovery.IsEnabled() {
		m.wg.Add(1)
		go m.scanLoop()
	}
}

func (m *Monitor) Stop() {
	m.stopOn.Do(func() { close(m.stopCh) })
	m.cli.Stop()
	m.wg.Wait()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.mu.Unlock()

	// No flush can start once closed is set, and a running one gives up on
	// stopCh, so the channel can be closed without racing a send.
	m.flushWG.Wait()
	close(m.events)
}

// Events returns the event stream. It is closed by Stop.
func (m *Monitor) Events() <-chan Event { return m.events }

// Connected reports AMI link state.
func (m *Monitor) Connected() bool { return m.cli.Connected() }

// emit publishes an event without blocking the AMI reader and without losing
// it. Caller holds m.mu.
//
// A dropped event is not a cosmetic problem: a lost call end leaves a call on
// the application's screen, and counting against the line's call limit, for
// good. So when the channel is full the event goes to an in-order backlog that
// a helper goroutine feeds into the channel as the consumer catches up. Once
// anything is in the backlog, everything after it goes there too, which is
// what keeps the order intact.
func (m *Monitor) emit(e Event) {
	if m.closed {
		return
	}
	if len(m.backlog) == 0 {
		select {
		case m.events <- e:
			return
		default:
		}
		logx.Warnf("pbx: event consumer is behind, queueing")
	}
	if len(m.backlog) >= maxBacklog {
		logx.Errorf("pbx: %d events waiting for a consumer that is not draining, dropping %v event", len(m.backlog), e.Type)
		return
	}
	m.backlog = append(m.backlog, e)
	if !m.flushing {
		m.flushing = true
		m.flushWG.Add(1)
		go m.flush()
	}
}

// flush moves the backlog into the event channel, oldest first, and exits
// once it is empty.
func (m *Monitor) flush() {
	defer m.flushWG.Done()
	for {
		m.mu.Lock()
		if len(m.backlog) == 0 || m.closed {
			m.flushing = false
			m.mu.Unlock()
			return
		}
		// The head stays in the backlog until it is sent, so emit keeps
		// queueing behind it in the meantime.
		e := m.backlog[0]
		m.mu.Unlock()

		select {
		case m.events <- e:
		case <-m.stopCh:
			m.mu.Lock()
			m.flushing = false
			m.mu.Unlock()
			return
		}

		m.mu.Lock()
		m.backlog[0] = Event{}
		m.backlog = m.backlog[1:]
		if len(m.backlog) == 0 {
			m.backlog = nil
			logx.Infof("pbx: event consumer caught up")
		}
		m.mu.Unlock()
	}
}

// emitCall reports one thing about a call and records it as reported.
// Caller holds m.mu.
func (m *Monitor) emitCall(t EventType, c *Call) {
	s := c.snapshot()
	c.reported = s
	m.emit(Event{Type: t, Call: s, LineIndex: c.LineIndex})
}

func (m *Monitor) onLinkState(up bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	logx.Infof("pbx: AMI link %s", map[bool]string{true: "up", false: "down"}[up])
	if !up {
		// The PBX view is gone; tear down every call we were tracking so
		// TAPI applications do not keep stale calls on screen forever.
		for _, c := range m.calls {
			m.retire(c, 0)
		}
		// An originate still waiting for its channel will not get one on this
		// connection, and the application is waiting on it.
		for _, p := range m.pending {
			m.failOriginate(p, "AMI link lost")
		}
		m.calls = make(map[string]*Call)
		m.byChan = make(map[string]*Call)
		m.pending = make(map[string]*pendingOriginate)
		m.reg.MarkAllAbsent()
	}
	m.emit(Event{Type: EventLink, Up: up})
	if up {
		// Re-read the endpoint list and the live channels: the PBX may have
		// been reloaded, or replaced entirely, and calls may have started or
		// ended while we were away.
		m.requestScan()
		m.requestResync()
	}
}

// lineFor maps an Asterisk channel name to a line index, or -1.
func (m *Monitor) lineFor(channel string) int {
	return m.reg.LineForChannel(channel)
}

func (m *Monitor) onAMIEvent(msg *ami.Message) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch strings.ToLower(msg.Event()) {
	case "newchannel":
		m.onNewchannel(msg)
	case "newstate":
		m.onNewstate(msg)
	case "dialbegin", "dial":
		m.onDialBegin(msg)
	case "dialend":
		m.onDialEnd(msg)
	case "newexten":
		m.onNewExten(msg)
	case "newconnectedline", "newcallerid":
		m.onPartyUpdate(msg)
	case "hold":
		m.onHold(msg, true)
	case "unhold":
		m.onHold(msg, false)
	case "hangup":
		m.onHangup(msg)
	case "rename":
		m.onRename(msg)
	case "varset":
		m.onVarSet(msg)
	case "originateresponse":
		m.onOriginateResponse(msg)
	case "devicestatechange":
		m.noteDeviceActivity(msg.Get("Device"))
	case "contactstatus":
		m.noteDeviceActivity(firstNonEmpty(msg.Get("EndpointName"), msg.Get("AOR")))
	case "peerstatus":
		m.noteDeviceActivity(msg.Get("Peer"))
	}
}

func (m *Monitor) onNewchannel(msg *ami.Message) {
	uid := msg.Get("Uniqueid")
	ch := msg.Get("Channel")
	if uid == "" || ch == "" {
		return
	}
	idx := m.lineFor(ch)
	if idx < 0 {
		return
	}
	if _, exists := m.calls[uid]; exists {
		return
	}
	if _, ok := m.abandoned[uid]; ok {
		m.hangupAbandoned(uid, ch)
		return
	}
	c := m.track(uid, ch, idx)

	// An Originate we placed presets the Uniqueid via the ChannelId header,
	// so a matching pending entry identifies our own outbound call.
	if p, ok := m.pending[uid]; ok {
		c.originateTag = p.tag
		c.Inbound = false
		c.RemoteNumber = p.dest
		c.State = StateDialing
		delete(m.pending, uid)
		m.announce(c)
		logx.Debugf("pbx: newchannel %s uid=%s line=%d (our originate)", ch, uid, idx)
		return
	}

	// A channel arriving *from* a phone is created already off-hook: chan_pjsip
	// allocates it in Ring, and Asterisk sends no Newstate for a state the
	// channel was born in. Announcing here is what puts the call on the
	// calling device's line the moment the handset is lifted, rather than
	// leaving it invisible until somebody answers.
	//
	// A channel created Down is one Asterisk is about to dial out on; its
	// direction is not known yet, so it waits for Newstate as before.
	switch msg.GetInt("ChannelState", chanDown) {
	case chanRing, chanDialing, chanOffHook:
		c.Inbound = false
		c.State = StateDialing
		m.updateParty(c, msg)
		m.announce(c)
	}
	logx.Debugf("pbx: newchannel %s uid=%s line=%d state=%s", ch, uid, idx, c.State)
}

// track starts tracking a channel on one of our lines. Caller holds m.mu.
func (m *Monitor) track(uid, ch string, idx int) *Call {
	c := &Call{
		Key:       uid,
		Channel:   ch,
		LineIndex: idx,
		State:     StateUnknown,
		Created:   time.Now(),
	}
	if e, ok := m.reg.At(idx); ok {
		c.LocalNumber = e.Extension
	}
	m.calls[uid] = c
	m.byChan[strings.ToLower(ch)] = c
	return c
}

func (m *Monitor) onNewstate(msg *ami.Message) {
	c := m.calls[msg.Get("Uniqueid")]
	if c == nil {
		return
	}
	st := msg.GetInt("ChannelState", -1)

	if !c.announced {
		// First hard evidence of direction: a channel we are *ringing*
		// (state Ringing) is an inbound call to the device; a channel that
		// reaches Ring is the device dialling out.
		switch st {
		case chanRinging:
			c.Inbound = true
			c.State = StateOffering
		case chanRing, chanDialing, chanOffHook:
			c.Inbound = false
			c.State = StateDialing
		case chanUp:
			c.State = StateConnected
		default:
			return
		}
		m.updateParty(c, msg)
		m.announce(c)
		if st == chanRinging {
			m.ringbackPeer(c)
		}
		return
	}

	switch st {
	case chanRinging:
		if c.Inbound {
			c.State = StateOffering
			m.ringbackPeer(c)
		} else {
			c.State = StateRingback
		}
	case chanRing:
		if c.Inbound {
			c.State = StateOffering
		} else {
			c.State = StateDialing
		}
	case chanUp:
		c.State = StateConnected
		if c.Connected.IsZero() {
			c.Connected = time.Now()
		}
	case chanBusy:
		c.State = StateBusy
	default:
		return
	}
	m.publishState(c)
}

// ringbackPeer moves the far leg of an internal call to ringback, given that
// the near leg has just started ringing.
//
// The calling channel itself never changes state while it waits, so without
// this the caller's application jumps from proceeding straight to connected
// and never shows a ringing call. On an external call there is no tracked peer
// and nothing happens.
func (m *Monitor) ringbackPeer(c *Call) {
	if c.peerKey == "" {
		return
	}
	peer := m.calls[c.peerKey]
	if peer == nil || !peer.announced || peer.Inbound {
		return
	}
	if peer.State != StateDialing && peer.State != StateProceeding {
		return
	}
	peer.State = StateRingback
	m.publishState(peer)
}

// onDialBegin is the most informative event we get: it names both legs, so it
// settles direction and the remote party in one go.
//
// Both legs are handled, not one or the other. On an internal call each end is
// one of our devices, and treating the event as "inbound or outbound" left the
// calling device with no call at all.
func (m *Monitor) onDialBegin(msg *ami.Message) {
	src, dest := msg.Get("Channel"), msg.Get("DestChannel")
	caller := m.dialLeg(src, msg.Get("Uniqueid"))
	callee := m.dialLeg(dest, msg.Get("DestUniqueid"))

	// A leg we originated ourselves is our own outbound call, whatever Dial
	// says about it. Asterisk rings the phone on our behalf, so the leg shows
	// up as the *destination* of a Dial; treating it as one would flip it to
	// inbound and show the user a call from themselves.
	if callee != nil && callee.originateTag != "" {
		callee = nil
	}

	// Remember the far leg while we can see both. It is what lets the calling
	// device report ringback when the called device starts to ring.
	if caller != nil && callee != nil {
		caller.peerKey, callee.peerKey = callee.Key, caller.Key
	}

	// The called device: something is dialling it.
	if callee != nil {
		callee.Inbound = true
		setIfEmpty(&callee.RemoteNumber, firstNonEmpty(msg.Get("CallerIDNum"), msg.Get("ConnectedLineNum")))
		setIfEmpty(&callee.RemoteName, firstNonEmpty(msg.Get("CallerIDName"), msg.Get("ConnectedLineName")))
		setIfEmpty(&callee.LocalNumber, msg.Get("DestExten"))
		if callee.State == StateUnknown {
			callee.State = StateOffering
		}
		m.publish(callee)
	}

	// The calling device: it is dialling out, whether to a trunk or to another
	// of our phones.
	if caller != nil {
		caller.Inbound = false
		to := firstNonEmpty(msg.Get("DestExten"), msg.Get("DestCallerIDNum"), dialStringNumber(msg.Get("DialString")))
		setIfEmpty(&caller.RemoteNumber, to)
		setIfEmpty(&caller.RemoteName, msg.Get("DestCallerIDName"))
		if caller.State == StateUnknown || caller.State == StateDialing {
			caller.State = StateProceeding
		}
		m.publish(caller)
	}
}

// dialLeg resolves one leg of a Dial to a tracked call, or nil if the channel
// is not one of our devices. The Uniqueid is authoritative; the channel name
// is the fallback for Asterisk versions that omit DestUniqueid.
func (m *Monitor) dialLeg(channel, uniqueid string) *Call {
	if channel == "" || m.lineFor(channel) < 0 {
		return nil
	}
	if c := m.calls[uniqueid]; c != nil {
		return c
	}
	return m.byChan[strings.ToLower(channel)]
}

func (m *Monitor) onDialEnd(msg *ami.Message) {
	src := msg.Get("Channel")
	if src == "" || m.lineFor(src) < 0 {
		return
	}
	c := m.calls[msg.Get("Uniqueid")]
	if c == nil || !c.announced {
		return
	}
	switch strings.ToUpper(msg.Get("DialStatus")) {
	case "BUSY":
		c.State = StateBusy
	case "CONGESTION", "CHANUNAVAIL":
		c.State = StateBusy
	case "ANSWER":
		return // Newstate/Up handles this
	default:
		return
	}
	m.publishState(c)
}

// onNewExten follows the destination of an outbound call as the dialplan
// resolves it, so the number on the caller's screen is the number that will
// actually be reached.
//
// Note that a SIP phone sends the complete number in its INVITE, so in
// practice this fires once with the finished number rather than once per
// keypress; there is no per-digit dialling state for Asterisk to report.
func (m *Monitor) onNewExten(msg *ami.Message) {
	c := m.calls[msg.Get("Uniqueid")]
	if c == nil || !c.announced || c.Inbound {
		return
	}
	// Once the call is up the far party is settled, and NewConnectedLine is
	// the event that reports changes to it.
	if c.State == StateConnected || c.State == StateOnHold {
		return
	}
	exten := strings.TrimSpace(msg.Get("Extension"))
	if !isRealNumber(exten) || exten == c.RemoteNumber {
		return
	}
	c.RemoteNumber = exten
	m.emitCall(EventCallInfo, c)
}

// onPartyUpdate handles NewConnectedLine / NewCallerid, which is how the
// identity of the other party changes mid-call (after a transfer, say).
func (m *Monitor) onPartyUpdate(msg *ami.Message) {
	c := m.calls[msg.Get("Uniqueid")]
	if c == nil || !c.announced {
		return
	}
	num := firstNonEmpty(msg.Get("ConnectedLineNum"), msg.Get("CallerIDNum"))
	name := firstNonEmpty(msg.Get("ConnectedLineName"), msg.Get("CallerIDName"))

	// The far party is never our own device. While a call we originated is
	// still being set up, Asterisk reports the phone we are ringing as the
	// connected line, which would otherwise replace the destination the user
	// asked for with their own number.
	if e, ok := m.reg.At(c.LineIndex); ok && num != "" && num == e.Extension {
		return
	}

	changed := false
	if isRealNumber(num) && num != c.RemoteNumber {
		c.RemoteNumber = num
		changed = true
	}
	if name != "" && name != "<unknown>" && name != c.RemoteName {
		c.RemoteName = name
		changed = true
	}
	if changed {
		m.emitCall(EventCallInfo, c)
	}
}

func (m *Monitor) onHold(msg *ami.Message, defaultOn bool) {
	c := m.calls[msg.Get("Uniqueid")]
	if c == nil || !c.announced {
		return
	}
	on := defaultOn
	// Asterisk 1.8 signalled hold as a single event with a Status header;
	// 12+ uses separate Hold/Unhold events.
	if s := msg.Get("Status"); s != "" {
		on = strings.EqualFold(s, "On")
	}
	if on {
		c.State = StateOnHold
	} else {
		c.State = StateConnected
	}
	m.publishState(c)
}

func (m *Monitor) onHangup(msg *ami.Message) {
	uid := msg.Get("Uniqueid")
	if uid == "" {
		return
	}
	// Recorded for every channel, tracked or not: a resync working from a
	// channel list taken a moment earlier must not adopt it afterwards.
	m.gone[uid] = time.Now()
	c := m.calls[uid]
	if c == nil {
		return
	}
	m.retire(c, msg.GetInt("Cause", 0))
	logx.Debugf("pbx: hangup %s uid=%s cause=%d", c.Channel, uid, c.HangupCause)
}

// retire stops tracking a call and, if the TSP knows about it, reports its
// end. Caller holds m.mu.
func (m *Monitor) retire(c *Call, cause int) {
	delete(m.calls, c.Key)
	if m.byChan[strings.ToLower(c.Channel)] == c {
		delete(m.byChan, strings.ToLower(c.Channel))
	}
	if c.originateTag != "" {
		delete(m.pending, c.originateTag)
	}
	m.gone[c.Key] = time.Now()
	if !c.announced {
		return
	}
	c.HangupCause = cause
	c.State = StateDisconnected
	m.emitCall(EventCallState, c)
	m.emitCall(EventCallEnd, c)
}

// onRename follows a channel through a masquerade (a transfer, a pickup), so
// that actions addressed by channel name still reach it.
func (m *Monitor) onRename(msg *ami.Message) {
	c := m.calls[msg.Get("Uniqueid")]
	newName := strings.TrimSpace(msg.Get("Newname"))
	if c == nil || newName == "" {
		return
	}
	if m.byChan[strings.ToLower(c.Channel)] == c {
		delete(m.byChan, strings.ToLower(c.Channel))
	}
	logx.Debugf("pbx: %s renamed to %s", c.Channel, newName)
	c.Channel = newName
	m.byChan[strings.ToLower(newName)] = c
}

// onVarSet binds an originate to its channel on Asterisk versions that do
// not honour the ChannelId header (pre-12). The call keeps the channel's own
// Uniqueid as its Key and carries the tag in OriginateTag, which is how the
// TSP finds the call object lineMakeCall created for it.
func (m *Monitor) onVarSet(msg *ami.Message) {
	if !strings.EqualFold(msg.Get("Variable"), "AMITSP_ID") {
		return
	}
	tag := msg.Get("Value")
	uid := msg.Get("Uniqueid")
	if uid == "" {
		return
	}
	if _, ok := m.abandoned[tag]; ok {
		ch := msg.Get("Channel")
		if c := m.calls[uid]; c != nil {
			// Not announced: a channel born Down waits for its first Newstate.
			delete(m.calls, uid)
			if m.byChan[strings.ToLower(c.Channel)] == c {
				delete(m.byChan, strings.ToLower(c.Channel))
			}
			ch = c.Channel
		}
		if ch != "" {
			m.hangupAbandoned(tag, ch)
		}
		return
	}
	p, ok := m.pending[tag]
	if !ok {
		return
	}
	c := m.calls[uid]
	if c == nil {
		c = m.byChan[strings.ToLower(msg.Get("Channel"))]
	}
	if c == nil {
		return
	}
	delete(m.pending, tag)
	c.originateTag = tag
	c.Inbound = false
	setIfEmpty(&c.RemoteNumber, p.dest)
	if c.State == StateUnknown {
		c.State = StateDialing
	}
	m.publish(c)
}

func (m *Monitor) onOriginateResponse(msg *ami.Message) {
	tag := msg.Get("ActionID")
	p, ok := m.pending[tag]
	if !ok {
		return
	}
	if strings.EqualFold(msg.Get("Response"), "Success") {
		return // the channel events carry the real state
	}
	m.failOriginate(p, firstNonEmpty(msg.Get("Reason"), msg.Get("Message")))
}

// failOriginate reports an originate that never produced a channel through a
// synthetic call, so the application's lineMakeCall does not wait forever for
// a state it will never see. Caller holds m.mu.
func (m *Monitor) failOriginate(p *pendingOriginate, reason string) {
	delete(m.pending, p.tag)
	logx.Warnf("pbx: originate %s failed: %s", p.tag, reason)
	c := &Call{
		Key:          p.tag,
		LineIndex:    p.lineIndex,
		RemoteNumber: p.dest,
		Created:      p.created,
		originateTag: p.tag,
		State:        StateDialing,
	}
	m.announce(c)
	c.State = StateDisconnected
	m.emitCall(EventCallState, c)
	m.emitCall(EventCallEnd, c)
}

// hangupAbandoned clears a channel that turned up for an originate the TSP
// had already given up on. Caller holds m.mu; the action itself runs on its
// own goroutine, because its response arrives on the reader this is called
// from.
func (m *Monitor) hangupAbandoned(tag, channel string) {
	delete(m.abandoned, tag)
	logx.Warnf("pbx: channel %s belongs to an originate that already timed out, hanging it up", channel)
	go func() {
		defer logx.Recover("pbx: hangup of abandoned originate")
		if err := m.simpleAction(ami.NewMessage("Action", "Hangup", "Channel", channel)); err != nil {
			logx.Warnf("pbx: cannot hang up %s: %v", channel, err)
		}
	}()
}

func (m *Monitor) announce(c *Call) {
	if c.announced {
		return
	}
	c.announced = true
	m.emitCall(EventCallNew, c)
	if c.State != StateUnknown {
		m.emitCall(EventCallState, c)
	}
}

// publish announces a call, or reports whatever changed since the TSP was
// last told about it. Caller holds m.mu.
func (m *Monitor) publish(c *Call) {
	if !c.announced {
		m.announce(c)
		return
	}
	r := c.reported
	infoChanged := r == nil || r.RemoteNumber != c.RemoteNumber || r.RemoteName != c.RemoteName ||
		r.LocalNumber != c.LocalNumber || r.Inbound != c.Inbound
	stateChanged := r == nil || r.State != c.State
	if infoChanged {
		m.emitCall(EventCallInfo, c)
	}
	if stateChanged {
		m.emitCall(EventCallState, c)
	}
}

// publishState reports a state change on an announced call, and nothing if
// the state is what the TSP already has. Caller holds m.mu.
func (m *Monitor) publishState(c *Call) {
	if c.reported != nil && c.reported.State == c.State {
		return
	}
	m.emitCall(EventCallState, c)
}

func (m *Monitor) updateParty(c *Call, msg *ami.Message) {
	if c.Inbound {
		setIfEmpty(&c.RemoteNumber, msg.Get("CallerIDNum"))
		setIfEmpty(&c.RemoteName, msg.Get("CallerIDName"))
	} else {
		setIfEmpty(&c.RemoteNumber, firstNonEmpty(msg.Get("Exten"), msg.Get("ConnectedLineNum")))
	}
	if !isRealNumber(c.RemoteNumber) {
		c.RemoteNumber = ""
	}
	if c.RemoteName == "<unknown>" {
		c.RemoteName = ""
	}
}

// ------------------------------------------------------------- resync

// requestResync asks for a channel list reconciliation as soon as the sync
// loop is free.
func (m *Monitor) requestResync() {
	select {
	case m.resync <- struct{}{}:
	default:
	}
}

// syncLoop reconciles the call model against the PBX's channel list whenever
// the link comes up and every ami.resync_sec after that.
//
// Events are the primary mechanism and this is the repair: calls that were in
// progress when the link came up, events Asterisk never sent, an originate
// whose answer never arrived. Without it any of those leaves a call on an
// application's screen, or missing from it, until the service restarts.
func (m *Monitor) syncLoop() {
	defer m.wg.Done()
	defer logx.Recover("pbx: resync loop")

	interval := time.Duration(m.cfg.AMI.ResyncSec) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	failing := false
	for {
		select {
		case <-m.stopCh:
			return
		case <-tick.C:
		case <-m.resync:
		}
		if !m.cli.Connected() {
			continue
		}
		err := m.runResync()
		switch {
		case err != nil && !failing:
			logx.Warnf("pbx: resync failed: %v (CoreShowChannels needs read=system or reporting)", err)
		case err == nil && failing:
			logx.Infof("pbx: resync working again")
		}
		failing = err != nil
	}
}

func (m *Monitor) runResync() error {
	// Anything created after this instant may be missing from the list for
	// the innocent reason that it did not exist yet.
	started := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(m.cfg.AMI.ActionTimeoutSec)*time.Second*4)
	defer cancel()
	msgs, err := m.cli.ActionList(ctx, ami.NewMessage("Action", "CoreShowChannels"), "CoreShowChannelsComplete")

	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		m.reconcile(started, msgs)
	}
	m.expire(time.Now())
	return err
}

// reconcile brings the call model in line with a CoreShowChannels listing
// taken at started. Caller holds m.mu.
func (m *Monitor) reconcile(started time.Time, msgs []*ami.Message) {
	live := make(map[string]*ami.Message)
	for _, msg := range msgs {
		if !strings.EqualFold(msg.Event(), "CoreShowChannel") {
			continue
		}
		if uid := msg.Get("Uniqueid"); uid != "" {
			live[uid] = msg
		}
	}

	// Calls the PBX no longer has: their Hangup never reached us.
	for uid, c := range m.calls {
		if _, ok := live[uid]; ok || !c.Created.Before(started) {
			continue
		}
		logx.Infof("pbx: resync: %s (%s) no longer exists on the PBX, clearing it", c.Channel, uid)
		m.retire(c, 0)
	}

	// Channels on our lines that nothing told us about.
	for uid, msg := range live {
		if m.calls[uid] != nil {
			continue
		}
		if _, hungUp := m.gone[uid]; hungUp {
			continue
		}
		m.adopt(uid, msg)
	}
}

// adopt starts tracking a channel found by a resync. Caller holds m.mu.
func (m *Monitor) adopt(uid string, msg *ami.Message) {
	ch := msg.Get("Channel")
	idx := m.lineFor(ch)
	if idx < 0 {
		return
	}
	if _, ok := m.abandoned[uid]; ok {
		m.hangupAbandoned(uid, ch)
		return
	}
	c := m.track(uid, ch, idx)

	// Our own originate, whose Newchannel we missed.
	if p, ok := m.pending[uid]; ok {
		c.originateTag = p.tag
		c.RemoteNumber = p.dest
		delete(m.pending, uid)
	}

	// The channel that started a call is the call's Linkedid. Anything else
	// was dialled from somewhere: an inbound call to this device.
	linked := msg.Get("Linkedid")
	c.Inbound = c.originateTag == "" && linked != "" && linked != uid

	switch msg.GetInt("ChannelState", -1) {
	case chanUp:
		c.State = StateConnected
		c.Connected = time.Now()
	case chanRinging:
		c.Inbound = true
		c.State = StateOffering
	case chanRing, chanDialing, chanOffHook:
		c.Inbound = false
		c.State = StateDialing
	case chanBusy:
		c.State = StateBusy
	default:
		// Not yet anything to show; its own events take it from here.
		return
	}

	// Connected-line is the far party from either end. A device's own caller
	// ID is never it.
	own := ""
	if e, ok := m.reg.At(idx); ok {
		own = e.Extension
	}
	for _, num := range []string{msg.Get("ConnectedLineNum"), msg.Get("CallerIDNum")} {
		if isRealNumber(num) && num != own {
			setIfEmpty(&c.RemoteNumber, num)
		}
	}
	if !c.Inbound && c.State != StateConnected {
		setIfEmpty(&c.RemoteNumber, msg.Get("Exten"))
	}
	if name := msg.Get("ConnectedLineName"); name != "" && name != "<unknown>" {
		c.RemoteName = name
	}

	logx.Infof("pbx: resync: picked up %s call %s (%s) in state %s",
		map[bool]string{true: "inbound", false: "outbound"}[c.Inbound], ch, uid, c.State)
	m.announce(c)
}

// expire gives up on originates that never produced a channel or an answer,
// and forgets what no longer needs remembering. Caller holds m.mu.
func (m *Monitor) expire(now time.Time) {
	limit := time.Duration(m.cfg.Dialplan.OriginateTimeoutMS)*time.Millisecond +
		time.Duration(m.cfg.AMI.ActionTimeoutSec)*time.Second + originateGrace
	for _, p := range m.pending {
		if now.Sub(p.created) > limit {
			m.failOriginate(p, "no channel and no response from the PBX")
		}
	}
	for tag, t := range m.abandoned {
		if now.Sub(t) > limit {
			delete(m.abandoned, tag)
		}
	}
	for uid, t := range m.gone {
		if now.Sub(t) > goneRetention {
			delete(m.gone, uid)
		}
	}
}

// ---------------------------------------------------------------- actions

// Lookup returns a snapshot of a tracked call.
func (m *Monitor) Lookup(key string) (*Snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.calls[key]
	if !ok {
		return nil, false
	}
	return c.snapshot(), true
}

// Originate places an outbound call from a line.
//
// The caller supplies the tag (see NewTag) so that it can register its own
// bookkeeping before the first AMI event arrives; the tag is preset as the
// channel's Uniqueid, and is therefore the Key the resulting call will be
// reported under.
//
// The call is placed to the *device* first; the dialplan then dials the
// destination once the user picks up. That is the only third-party dial
// pattern that works for arbitrary SIP phones.
func (m *Monitor) Originate(lineIndex int, dest, tag string) error {
	entry, ok := m.reg.At(lineIndex)
	if !ok {
		return fmt.Errorf("pbx: invalid line index %d", lineIndex)
	}
	line := entry.Line
	number := m.cfg.Dialplan.RewriteNumber(dest)
	if number == "" {
		return fmt.Errorf("pbx: empty destination after rewrite (input %q)", dest)
	}

	callerID := line.CallerIDNum
	if line.CallerIDName != "" {
		callerID = fmt.Sprintf("%q <%s>", line.CallerIDName, line.CallerIDNum)
	}

	dialContext := m.contextFor(line)

	act := ami.NewMessage(
		"Action", "Originate",
		"ActionID", tag,
		"Channel", line.Channel,
		"ChannelId", tag, // Asterisk 12+: presets the Uniqueid
		"Context", dialContext,
		"Exten", number,
		"Priority", fmt.Sprint(m.cfg.Dialplan.Priority),
		"CallerID", callerID,
		"Timeout", fmt.Sprint(m.cfg.Dialplan.OriginateTimeoutMS),
		"Async", "true",
	)
	act.Add("Variable", "AMITSP_ID="+tag)

	m.mu.Lock()
	m.pending[tag] = &pendingOriginate{tag: tag, lineIndex: lineIndex, dest: number, created: time.Now()}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.cfg.AMI.ActionTimeoutSec)*time.Second)
	defer cancel()
	if _, err := m.cli.Action(ctx, act); err != nil {
		m.mu.Lock()
		delete(m.pending, tag)
		if errors.Is(err, context.DeadlineExceeded) {
			// The PBX may still act on it. The caller is about to fail the
			// request, so whatever channel turns up is not wanted, and one
			// that already has is hung up now.
			m.abandoned[tag] = time.Now()
			if c := m.calls[tag]; c != nil {
				m.retire(c, 0)
				m.hangupAbandoned(tag, c.Channel)
			}
		}
		m.mu.Unlock()
		// "Extension does not exist" is by far the most common failure here
		// and the bare message says nothing about what was tried, so spell out
		// the three fields Asterisk actually checked.
		return fmt.Errorf("%w (tried %s@%s priority %d from %s)",
			err, number, dialContext, m.cfg.Dialplan.Priority, line.Channel)
	}
	logx.Infof("pbx: originate line=%d %s -> %s@%s (tag %s)", lineIndex, line.Channel, number, dialContext, tag)
	return nil
}

// contextFor is the dialplan context numbers from a line are sent into.
//
// The endpoint's own context is the one the phone dials into, so a number
// sent through it behaves exactly as if it had been keyed in. Fall back to
// the configured context for manually written lines and for PBXs that do not
// report one.
func (m *Monitor) contextFor(line config.Line) string {
	return firstNonEmpty(line.Context, m.cfg.Dialplan.Context)
}

// Hangup drops a call.
func (m *Monitor) Hangup(key string) error {
	ch, _, err := m.channelOf(key)
	if err != nil {
		return err
	}
	return m.simpleAction(ami.NewMessage("Action", "Hangup", "Channel", ch))
}

// Redirect performs a blind transfer of a call to dest. This covers both
// TSPI_lineRedirect (call still offering) and TSPI_lineBlindTransfer
// (call already connected) — AMI models both as Redirect.
//
// The destination is resolved in the line's own context, exactly as an
// Originate from the same line would be.
func (m *Monitor) Redirect(key, dest string) error {
	ch, lineIndex, err := m.channelOf(key)
	if err != nil {
		return err
	}
	number := m.cfg.Dialplan.RewriteNumber(dest)
	if number == "" {
		return fmt.Errorf("pbx: empty transfer destination")
	}
	dialContext := m.cfg.Dialplan.Context
	if entry, ok := m.reg.At(lineIndex); ok {
		dialContext = m.contextFor(entry.Line)
	}
	return m.simpleAction(ami.NewMessage(
		"Action", "Redirect",
		"Channel", ch,
		"Context", dialContext,
		"Exten", number,
		"Priority", fmt.Sprint(m.cfg.Dialplan.Priority),
	))
}

// SendDigits plays DTMF into a call, one digit per action.
func (m *Monitor) SendDigits(key, digits string) error {
	ch, _, err := m.channelOf(key)
	if err != nil {
		return err
	}
	for _, d := range digits {
		if strings.ContainsRune("0123456789*#ABCD", d) {
			if err := m.simpleAction(ami.NewMessage("Action", "PlayDTMF", "Channel", ch, "Digit", string(d))); err != nil {
				return err
			}
		}
	}
	return nil
}

// Answer asks the phone to pick up an offering call. There is no generic
// AMI answer for a third party, so this depends on the phone honouring a
// SIP NOTIFY; see Line.AnswerMode.
func (m *Monitor) Answer(key string) error {
	snap, ok := m.Lookup(key)
	if !ok {
		return fmt.Errorf("pbx: unknown call %s", key)
	}
	entry, ok := m.reg.At(snap.LineIndex)
	if !ok {
		return fmt.Errorf("pbx: call %s is on unknown line %d", key, snap.LineIndex)
	}
	line := entry.Line
	return m.notify(line, line.AnswerMode, line.AnswerNotifyHeaders, "answer")
}

// Hold/Unhold likewise have no third-party AMI equivalent and rely on a
// NOTIFY the phone understands.
func (m *Monitor) Hold(key string, on bool) error {
	snap, ok := m.Lookup(key)
	if !ok {
		return fmt.Errorf("pbx: unknown call %s", key)
	}
	entry, ok := m.reg.At(snap.LineIndex)
	if !ok {
		return fmt.Errorf("pbx: call %s is on unknown line %d", key, snap.LineIndex)
	}
	line := entry.Line
	event := "hold"
	if !on {
		event = "talk"
	}
	return m.notify(line, line.HoldMode, map[string]string{"Event": event}, "hold")
}

func (m *Monitor) notify(line config.Line, mode string, headers map[string]string, what string) error {
	var action string
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "pjsip-notify", "pjsip":
		action = "PJSIPNotify"
	case "sip-notify", "sip":
		action = "SIPnotify"
	case "", "none":
		return fmt.Errorf("pbx: %s not enabled for line %s", what, line.Channel)
	default:
		return fmt.Errorf("pbx: unknown mode %q for %s on line %s", mode, what, line.Channel)
	}

	endpoint := line.Channel
	if idx := strings.Index(endpoint, "/"); idx >= 0 {
		endpoint = endpoint[idx+1:]
	}
	act := ami.NewMessage("Action", action)
	if action == "PJSIPNotify" {
		act.Add("Endpoint", endpoint)
	} else {
		act.Add("Channel", endpoint)
	}
	for k, v := range headers {
		act.Add("Variable", k+"="+v)
	}
	return m.simpleAction(act)
}

func (m *Monitor) simpleAction(msg *ami.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.cfg.AMI.ActionTimeoutSec)*time.Second)
	defer cancel()
	_, err := m.cli.Action(ctx, msg)
	return err
}

// channelOf returns a call's current channel name and line index.
func (m *Monitor) channelOf(key string) (string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.calls[key]
	if !ok {
		return "", -1, fmt.Errorf("pbx: unknown call %s", key)
	}
	if c.Channel == "" {
		// An outbound call whose channel has not appeared yet: AMI actions
		// address channels by name, so there is nothing to act on. The
		// originate timeout will clean it up.
		return "", -1, fmt.Errorf("pbx: call %s has no channel yet", key)
	}
	return c.Channel, c.LineIndex, nil
}

// ------------------------------------------------------------------ util

// NewTag mints a correlation tag for an outbound call. It doubles as the
// Asterisk Uniqueid (via the Originate ChannelId header) and as the AMI
// ActionID, so it must be unique and free of AMI-hostile characters.
func NewTag() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("amitsp-%d", time.Now().UnixNano())
	}
	return "amitsp-" + hex.EncodeToString(b[:])
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" && isRealNumber(v) {
		*dst = v
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// isRealNumber filters the placeholders Asterisk uses for "no caller ID".
func isRealNumber(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "<unknown>", "unknown", "anonymous", "s", "<null>":
		return false
	}
	return true
}

// dialStringNumber extracts the number from a Dial() dial string such as
// "PJSIP/004930123456@trunk" or "SIP/trunk/00493012345".
func dialStringNumber(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}
