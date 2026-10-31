package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "shim.h"
*/
import "C"

import (
	"time"

	"github.com/adee42/ami-tsp/internal/logx"
	"github.com/adee42/ami-tsp/internal/pbx"
)

// startPump runs the single goroutine that turns PBX events into TAPI
// messages. Keeping it single-threaded preserves the ordering the monitor
// established, which TAPI applications depend on (a call must not be told it
// is connected before it exists).
//
// Work that sends call messages from elsewhere — completing a lineMakeCall,
// acknowledging a lineAccept — is posted here too (see post), so that it is
// ordered with the PBX's events instead of racing them.
func (p *providerState) startPump() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		events := p.mon.Events()
		for {
			select {
			case <-p.stop:
				return
			case fn := <-p.tasks:
				p.runTask(fn)
			case ev, ok := <-events:
				if !ok {
					return
				}
				p.runTask(func() { p.handleEvent(ev) })
			}
		}
	}()
}

// runTask runs one unit of pump work. A panic loses that unit, not the pump:
// with the pump gone no application would hear about a call again.
func (p *providerState) runTask(fn func()) {
	defer logx.Recover("tsp: event pump")
	fn()
}

// post queues fn to run on the pump goroutine. It blocks only while the pump
// is busy, and gives up once the provider is stopping.
func (p *providerState) post(fn func()) {
	select {
	case p.tasks <- fn:
	case <-p.stop:
	}
}

// stopPump asks the pump to finish and waits for it.
//
// This can block indefinitely and the caller must assume it will: the pump may
// be inside a LINEEVENT callback waiting for the very lock TapiSrv holds while
// it waits for TSPI_providerShutdown to return. TSPI_providerShutdown runs it
// under a deadline for exactly that reason.
func (p *providerState) stopPump() {
	close(p.stop)
	p.wg.Wait()
}

// runBounded runs fn on its own goroutine and reports whether it finished
// within d. A goroutine left behind is deliberate: the DLL is pinned and never
// unloaded, so it cannot outlive its own code, and the callbacksAllowed guard
// means the worst it can do is nothing.
func runBounded(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer logx.Recover("tsp: bounded teardown")
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func (p *providerState) handleEvent(ev pbx.Event) {
	switch ev.Type {
	case pbx.EventLink:
		p.handleLink(ev.Up)
	case pbx.EventCallNew:
		p.handleCallNew(ev.Call)
	case pbx.EventCallState:
		p.handleCallState(ev.Call)
	case pbx.EventCallInfo:
		p.handleCallInfo(ev.Call)
	case pbx.EventCallEnd:
		p.handleCallEnd(ev.Call)
	case pbx.EventLineAdded:
		p.handleLineAdded(ev.LineIndex)
	case pbx.EventLineState:
		p.handleLineState(ev.LineIndex, ev.Up)
	}
}

// lineEvent sends one LINEEVENT message, unless TAPI is shutting the provider
// down. Every message to TAPI goes through here or through one of the other
// shim calls guarded the same way.
func (p *providerState) lineEvent(proc C.LINEEVENT, htLine C.HTAPILINE, htCall C.HTAPICALL, m lineMsg) {
	if !p.callbacksAllowed() {
		return
	}
	C.amitsp_line_event(proc, htLine, htCall, m.msg, m.p1, m.p2, m.p3)
}

// callForLocked finds the call object a PBX snapshot refers to. Caller holds
// mu.
//
// The Key is the Asterisk Uniqueid, which for a call we placed is the tag
// TSPI_lineMakeCall registered the call under. On Asterisk before 12 the
// Uniqueid cannot be preset, so the call arrives under a Key of its own and
// names our tag in OriginateTag; the call object is then moved to the real
// Key so that later events, and actions on the call, find it.
func (p *providerState) callForLocked(s *pbx.Snapshot) *callDev {
	if c := p.callsByKey[s.Key]; c != nil {
		return c
	}
	if s.OriginateTag == "" || s.OriginateTag == s.Key {
		return nil
	}
	c := p.callsByKey[s.OriginateTag]
	if c == nil {
		return nil
	}
	delete(p.callsByKey, s.OriginateTag)
	c.key = s.Key
	p.callsByKey[s.Key] = c
	return c
}

// handleLineAdded creates a TAPI line device for a line discovery appended to
// the registry.
//
// LINE_CREATE is synchronous in the same way LINE_NEWCALL is: TapiSrv calls
// straight back into TSPI_providerCreateLineDevice, which needs p.mu, so the
// callback must be made without it.
func (p *providerState) handleLineAdded(index int) {
	entry, ok := p.reg.At(index)
	if !ok {
		return
	}

	proc, hProv := lineCreateCallback()
	if proc == nil || hProv == nil {
		logx.Warnf("tsp: cannot announce new line %s, TAPI gave us no create callback", entry.Channel)
		return
	}

	p.mu.Lock()
	l := p.addLineLocked(index, entry.Line)
	if l == nil || l.created {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	if !p.callbacksAllowed() {
		return
	}
	logx.Infof("tsp: announcing new line device %s (%s)", entry.Channel, entry.Name)
	C.amitsp_line_create(proc, hProv, C.DWORD_PTR(index))

	p.mu.Lock()
	created := l.created
	p.mu.Unlock()
	if !created {
		// TAPI ignored the message. The device stays in the registry, so the
		// next TapiSrv start will enumerate it normally.
		logx.Warnf("tsp: TAPI did not create a device for %s; it will appear after a restart", entry.Channel)
	}
}

// handleLineState reports a line coming into or going out of service because
// the underlying device appeared or disappeared on the PBX. Reports that
// repeat what TAPI already has are filtered out here.
func (p *providerState) handleLineState(index int, up bool) {
	p.mu.Lock()
	l := p.lineByIndexLocked(index)
	if l == nil || l.present == up {
		p.mu.Unlock()
		return
	}
	l.present = up
	inService := p.inServiceLocked(l)
	p.mu.Unlock()

	state := uint32(C.LINEDEVSTATE_OUTOFSERVICE)
	if inService {
		state = C.LINEDEVSTATE_INSERVICE
	}
	p.fireLineDevState(l, state)
}

func (p *providerState) handleLink(up bool) {
	p.mu.Lock()
	p.linkUp = up
	type target struct {
		htLine C.HTAPILINE
		proc   C.LINEEVENT
		state  C.DWORD_PTR
	}
	var targets []target
	for _, l := range p.lines {
		if !l.open {
			continue
		}
		state := C.DWORD_PTR(C.LINEDEVSTATE_OUTOFSERVICE)
		if p.inServiceLocked(l) {
			state = C.LINEDEVSTATE_INSERVICE
		}
		targets = append(targets, target{l.htLine, l.eventProc, state})
	}
	p.mu.Unlock()

	for _, t := range targets {
		p.lineEvent(t.proc, t.htLine, nil, lineMsg{msg: C.LINE_LINEDEVSTATE, p1: t.state})
	}
}

func (p *providerState) handleCallNew(s *pbx.Snapshot) {
	p.mu.Lock()

	l := p.lineByIndexLocked(s.LineIndex)
	if l == nil || !l.open {
		p.mu.Unlock()
		return
	}

	// An outbound call we placed already has a callDev, created by
	// TSPI_lineMakeCall and registered under the originate tag.
	if c := p.callForLocked(s); c != nil {
		c.bound = true
		applySnapshot(c, s)
		p.mu.Unlock()
		p.fireCallState(c, callStateFor(s.State), 0)
		return
	}

	if p.activeCallsLocked(l) >= maxCallsPerLine {
		p.mu.Unlock()
		logx.Warnf("tsp: line %s already has %d calls (tapi.max_calls_per_line), not offering %s from %s to applications",
			l.cfg.Channel, maxCallsPerLine, s.Key, s.RemoteNumber)
		return
	}

	c := &callDev{
		token:   newToken(),
		line:    l,
		key:     s.Key,
		bound:   true,
		created: time.Now(),
		state:   C.LINECALLSTATE_UNKNOWN,
	}
	applySnapshot(c, s)
	p.callsByToken[c.token] = c
	p.callsByKey[c.key] = c
	htLine, proc := l.htLine, l.eventProc
	p.mu.Unlock()

	if !p.callbacksAllowed() {
		return
	}
	// LINE_NEWCALL is synchronous: TAPI hands back the application-side
	// handle or refuses the call by returning a null handle.
	htCall := C.amitsp_new_call(proc, htLine, C.HDRVCALL(c.token))
	if htCall == nil {
		logx.Warnf("tsp: TAPI refused new call %s on %s", s.Key, l.cfg.Channel)
		p.mu.Lock()
		delete(p.callsByToken, c.token)
		if p.callsByKey[c.key] == c {
			delete(p.callsByKey, c.key)
		}
		tok := c.token
		c.token = nil
		c.ended = true
		p.mu.Unlock()
		freeToken(tok)
		return
	}

	p.mu.Lock()
	c.htCall = htCall
	p.mu.Unlock()

	logx.Infof("tsp: new %s call on %s: %s (%s)", direction(s.Inbound), l.cfg.Name, s.RemoteNumber, s.Key)
	p.fireCallState(c, callStateFor(s.State), 0)
}

func (p *providerState) handleCallState(s *pbx.Snapshot) {
	p.mu.Lock()
	c := p.callForLocked(s)
	if c == nil {
		p.mu.Unlock()
		return
	}
	applySnapshot(c, s)
	p.mu.Unlock()

	var mode uint32
	if s.State == pbx.StateDisconnected {
		mode = disconnectMode(s.HangupCause)
	}
	p.fireCallState(c, callStateFor(s.State), mode)
}

func (p *providerState) handleCallInfo(s *pbx.Snapshot) {
	info := lineMsg{
		msg: C.LINE_CALLINFO,
		p1: C.DWORD_PTR(C.LINECALLINFOSTATE_CONNECTEDID | C.LINECALLINFOSTATE_CALLERID |
			C.LINECALLINFOSTATE_CALLEDID),
	}

	p.mu.Lock()
	c := p.callForLocked(s)
	if c == nil {
		p.mu.Unlock()
		return
	}
	applySnapshot(c, s)
	if c.ended {
		p.mu.Unlock()
		return
	}
	if c.awaiting {
		c.deferred = append(c.deferred, info)
		p.mu.Unlock()
		return
	}
	htLine, htCall, proc := c.line.htLine, c.htCall, c.line.eventProc
	p.mu.Unlock()

	if htCall == nil {
		return
	}
	p.lineEvent(proc, htLine, htCall, info)
}

func (p *providerState) handleCallEnd(s *pbx.Snapshot) {
	p.mu.Lock()
	c := p.callForLocked(s)
	if c == nil {
		p.mu.Unlock()
		return
	}
	// The key is retired now, but the callDev survives until TAPI calls
	// TSPI_lineCloseCall; TAPI may still query it after the idle transition.
	delete(p.callsByKey, c.key)
	p.mu.Unlock()

	p.fireCallState(c, C.LINECALLSTATE_IDLE, 0)

	p.mu.Lock()
	c.ended = true
	p.mu.Unlock()
}

// finishMakeCall completes a TSPI_lineMakeCall request on the pump goroutine,
// then releases the call messages the PBX produced while it was outstanding.
func (p *providerState) finishMakeCall(c *callDev, id C.DRV_REQUESTID, err error) {
	if err != nil {
		p.mu.Lock()
		if p.callsByKey[c.key] == c {
			delete(p.callsByKey, c.key)
		}
		c.ended = true
		c.awaiting = false
		c.deferred = nil
		p.mu.Unlock()
		// TAPI destroys the call itself when the request fails, and will
		// follow up with TSPI_lineCloseCall.
		p.completeRequest(id, lerr(C.LINEERR_OPERATIONFAILED))
		return
	}

	p.completeRequest(id, 0)

	p.mu.Lock()
	c.awaiting = false
	deferred := c.deferred
	c.deferred = nil
	htLine, htCall, proc := c.line.htLine, c.htCall, c.line.eventProc
	p.mu.Unlock()

	if len(deferred) == 0 {
		// Give the application a state to show while Asterisk rings the
		// phone; channel events refine it from here on.
		p.fireCallState(c, C.LINECALLSTATE_DIALING, 0)
		return
	}
	if htCall == nil {
		return
	}
	for _, m := range deferred {
		p.lineEvent(proc, htLine, htCall, m)
	}
}

// fireCallState updates the cached state and notifies TAPI. It must not be
// called with p.mu held: TAPI is entitled to call back into TSPI (typically
// TSPI_lineGetCallInfo) from inside the callback.
//
// Nothing is reported after IDLE, which is the end of a call for TAPI, and
// nothing is reported twice.
func (p *providerState) fireCallState(c *callDev, state, mode uint32) {
	p.mu.Lock()
	if c.state == C.LINECALLSTATE_IDLE || c.state == state || (c.ended && state != C.LINECALLSTATE_IDLE) {
		p.mu.Unlock()
		return
	}
	c.state = state
	c.stateMode = mode
	if state == C.LINECALLSTATE_CONNECTED && c.connected.IsZero() {
		c.connected = time.Now()
	}
	m := lineMsg{
		msg: C.LINE_CALLSTATE,
		p1:  C.DWORD_PTR(state),
		p2:  C.DWORD_PTR(mode),
		p3:  C.DWORD_PTR(C.LINEMEDIAMODE_INTERACTIVEVOICE),
	}
	if c.awaiting {
		c.deferred = append(c.deferred, m)
		p.mu.Unlock()
		return
	}
	htLine, htCall, proc := c.line.htLine, c.htCall, c.line.eventProc
	name := c.line.cfg.Name
	key := c.key
	p.mu.Unlock()

	if htCall == nil {
		return
	}
	logx.Debugf("tsp: %s call %s -> state 0x%x", name, key, state)
	p.lineEvent(proc, htLine, htCall, m)
}

// fireLineDevState reports a line-level change such as a new call count.
func (p *providerState) fireLineDevState(l *lineDev, state uint32) {
	p.mu.Lock()
	if !l.open {
		p.mu.Unlock()
		return
	}
	htLine, proc := l.htLine, l.eventProc
	p.mu.Unlock()
	p.lineEvent(proc, htLine, nil, lineMsg{msg: C.LINE_LINEDEVSTATE, p1: C.DWORD_PTR(state)})
}

// applySnapshot copies PBX-side facts into the call. Caller holds p.mu.
func applySnapshot(c *callDev, s *pbx.Snapshot) {
	c.inbound = s.Inbound
	if s.RemoteNumber != "" {
		c.remoteNum = s.RemoteNumber
	}
	if s.RemoteName != "" {
		c.remoteName = s.RemoteName
	}
	if s.LocalNumber != "" {
		c.localNum = s.LocalNumber
	}
	if c.localNum == "" {
		c.localNum = c.line.cfg.Extension
	}
}

// callStateFor maps the PBX call model onto LINECALLSTATE_*.
func callStateFor(s pbx.State) uint32 {
	switch s {
	case pbx.StateOffering:
		return C.LINECALLSTATE_OFFERING
	case pbx.StateDialing:
		return C.LINECALLSTATE_DIALING
	case pbx.StateProceeding:
		return C.LINECALLSTATE_PROCEEDING
	case pbx.StateRingback:
		return C.LINECALLSTATE_RINGBACK
	case pbx.StateConnected:
		return C.LINECALLSTATE_CONNECTED
	case pbx.StateOnHold:
		return C.LINECALLSTATE_ONHOLD
	case pbx.StateBusy:
		return C.LINECALLSTATE_BUSY
	case pbx.StateDisconnected:
		return C.LINECALLSTATE_DISCONNECTED
	case pbx.StateIdle:
		return C.LINECALLSTATE_IDLE
	default:
		return C.LINECALLSTATE_UNKNOWN
	}
}

// disconnectMode maps Q.850 hangup causes onto LINEDISCONNECTMODE_*, which
// is what an application shows as "busy", "no answer" and so on.
func disconnectMode(cause int) uint32 {
	switch cause {
	case 16: // normal clearing
		return C.LINEDISCONNECTMODE_NORMAL
	case 17: // user busy
		return C.LINEDISCONNECTMODE_BUSY
	case 18, 19: // no user responding / no answer
		return C.LINEDISCONNECTMODE_NOANSWER
	case 21: // call rejected
		return C.LINEDISCONNECTMODE_REJECT
	case 1, 20, 22: // unallocated number, subscriber absent, number changed
		return C.LINEDISCONNECTMODE_UNAVAIL
	case 34, 42, 44: // no circuit, switching equipment congestion
		return C.LINEDISCONNECTMODE_CONGESTION
	case 0:
		return C.LINEDISCONNECTMODE_UNKNOWN
	default:
		return C.LINEDISCONNECTMODE_UNKNOWN
	}
}

func direction(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// completeRequest reports the outcome of an asynchronous TSPI request.
func (p *providerState) completeRequest(id C.DRV_REQUESTID, result C.LONG) {
	p.mu.Lock()
	proc := p.completion
	p.mu.Unlock()
	// These run on goroutines started by async(), which shutdown does not wait
	// for; the completion proc is not ours to call once TAPI has taken the
	// provider down.
	if !p.callbacksAllowed() {
		return
	}
	C.amitsp_completion(proc, id, result)
}
