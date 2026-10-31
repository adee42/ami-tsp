package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "shim.h"
*/
import "C"

import (
	"errors"
	"time"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/logx"
	"github.com/adee42/ami-tsp/internal/pbx"
)

// async runs work off the TSPI thread and reports the outcome through the
// completion proc. TSPI entry points must not block TapiSrv, and every AMI
// round trip can take as long as the PBX feels like taking.
//
// It returns the value the TSPI function itself must return: the request ID.
func (p *providerState) async(id C.DRV_REQUESTID, what string, fn func() error) C.LONG {
	go func() {
		res := lerr(C.LINEERR_OPERATIONFAILED)
		// Completion is reported even if fn panics: a request TAPI never hears
		// back about leaves the application waiting on it.
		defer func() { p.completeRequest(id, res) }()
		defer logx.Recover("tsp: " + what)
		if err := fn(); err != nil {
			logx.Warnf("tsp: %s failed: %v", what, err)
			return
		}
		res = 0
	}()
	return C.LONG(int32(uint32(id)))
}

// TSPI_lineMakeCall places an outbound call.
//
// The driver-side call object is created synchronously so TAPI has a handle
// immediately; the Originate itself is asynchronous and reported through the
// completion proc.
//
//export TSPI_lineMakeCall
func TSPI_lineMakeCall(dwRequestID C.DRV_REQUESTID, hdLine C.HDRVLINE, htCall C.HTAPICALL,
	lphdCall *C.HDRVCALL, lpszDestAddress *C.WCHAR, dwCountryCode C.DWORD, lpCallParams *C.LINECALLPARAMS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineMakeCall", &rc)

	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lphdCall == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	l := p.lineByToken(hdLine)
	if l == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}

	dest := wstring(lpszDestAddress)
	if dest == "" {
		// A null destination means "go off-hook and wait for lineDial".
		// AMI cannot make a phone go off-hook, so this is refused rather
		// than half-implemented.
		return lerr(C.LINEERR_INVALADDRESS)
	}

	p.mu.Lock()
	if p.activeCallsLocked(l) >= maxCallsPerLine {
		p.mu.Unlock()
		return lerr(C.LINEERR_CALLUNAVAIL)
	}
	c := &callDev{
		token:    newToken(),
		htCall:   htCall,
		line:     l,
		key:      pbx.NewTag(),
		inbound:  false,
		state:    C.LINECALLSTATE_UNKNOWN,
		localNum: l.cfg.Extension,
		created:  time.Now(),
		// No call message may reach TAPI before the request completes; see
		// finishMakeCall.
		awaiting: true,
	}
	c.remoteNum = p.cfg.Dialplan.RewriteNumber(dest)
	p.callsByToken[c.token] = c
	p.callsByKey[c.key] = c
	index := l.index
	tag := c.key
	p.mu.Unlock()

	*lphdCall = C.HDRVCALL(c.token)
	logx.Infof("tsp: makeCall on %s to %q (key %s)", l.cfg.Name, dest, tag)

	id := dwRequestID
	go func() {
		err := errors.New("originate did not return")
		// Whatever happens to the Originate, the request is completed, and
		// on the pump, behind any events the PBX has already sent for it.
		defer func() { p.post(func() { p.finishMakeCall(c, id, err) }) }()
		defer logx.Recover("tsp: makeCall")
		err = p.mon.Originate(index, dest, tag)
		if err != nil {
			logx.Warnf("tsp: makeCall to %q failed: %v", dest, err)
		}
	}()

	return C.LONG(int32(uint32(dwRequestID)))
}

// TSPI_lineAnswer answers an offering call.
//
// AMI has no third-party answer primitive. Where the configuration enables
// it, this sends the SIP NOTIFY that makes the phone auto-answer; otherwise
// it reports the operation as unavailable rather than silently doing
// nothing. LINECALLFEATURE_ANSWER is advertised to match.
//
//export TSPI_lineAnswer
func TSPI_lineAnswer(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpsUserUserInfo *C.char, dwSize C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineAnswer", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	if !enabledMode(c.line.cfg.AnswerMode) {
		return lerr(C.LINEERR_OPERATIONUNAVAIL)
	}
	key := p.keyOf(c)
	return p.async(dwRequestID, "answer", func() error { return p.mon.Answer(key) })
}

// TSPI_lineAccept acknowledges an offering call without answering it.
// Asterisk is already alerting the caller, so there is nothing to send.
//
//export TSPI_lineAccept
func TSPI_lineAccept(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpsUserUserInfo *C.char, dwSize C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineAccept", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	// On the pump, so that ACCEPTED is ordered with the PBX's own states and
	// is never sent after the call has gone idle.
	go p.post(func() {
		p.completeRequest(dwRequestID, 0)
		p.fireCallState(c, C.LINECALLSTATE_ACCEPTED, 0)
	})
	return C.LONG(int32(uint32(dwRequestID)))
}

// TSPI_lineDrop hangs up a call.
//
//export TSPI_lineDrop
func TSPI_lineDrop(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpsUserUserInfo *C.char, dwSize C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineDrop", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	key := p.keyOf(c)
	return p.async(dwRequestID, "drop", func() error { return p.mon.Hangup(key) })
}

// TSPI_lineDropOnClose is TAPI cleaning up after an application that exited
// while owning a call.
//
//export TSPI_lineDropOnClose
func TSPI_lineDropOnClose(hdCall C.HDRVCALL) (rc C.LONG) {
	defer recoverEntry("TSPI_lineDropOnClose", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	key := p.keyOf(c)
	go func() {
		defer logx.Recover("tsp: dropOnClose")
		if err := p.mon.Hangup(key); err != nil {
			logx.Warnf("tsp: dropOnClose failed: %v", err)
		}
	}()
	return 0
}

// TSPI_lineDropNoOwner is TAPI telling us nobody owns this call any more.
// The PBX keeps the call up; leaving it alone is the least surprising
// behaviour for a call the user is still holding to their ear.
//
//export TSPI_lineDropNoOwner
func TSPI_lineDropNoOwner(hdCall C.HDRVCALL) (rc C.LONG) {
	defer recoverEntry("TSPI_lineDropNoOwner", &rc)
	return 0
}

// TSPI_lineCloseCall releases the driver-side call object. It is the last
// thing TAPI does with the handle.
//
//export TSPI_lineCloseCall
func TSPI_lineCloseCall(hdCall C.HDRVCALL) (rc C.LONG) {
	defer recoverEntry("TSPI_lineCloseCall", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	p.mu.Lock()
	c := p.callsByToken[unsafe.Pointer(hdCall)]
	if c == nil {
		p.mu.Unlock()
		return lerr(C.LINEERR_INVALCALLHANDLE)
	}
	delete(p.callsByToken, c.token)
	if existing, ok := p.callsByKey[c.key]; ok && existing == c {
		delete(p.callsByKey, c.key)
	}
	tok := c.token
	c.token = nil
	c.htCall = nil
	c.ended = true
	c.deferred = nil
	p.mu.Unlock()

	freeToken(tok)
	return 0
}

// TSPI_lineGetCallInfo returns the static-ish description of a call.
//
//export TSPI_lineGetCallInfo
func TSPI_lineGetCallInfo(hdCall C.HDRVCALL, lpCallInfo *C.LINECALLINFO) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetCallInfo", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	if lpCallInfo == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	return fillCallInfo(p, c, lpCallInfo)
}

// TSPI_lineGetCallStatus returns the current state of a call.
//
//export TSPI_lineGetCallStatus
func TSPI_lineGetCallStatus(hdCall C.HDRVCALL, lpCallStatus *C.LINECALLSTATUS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetCallStatus", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	if lpCallStatus == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	return fillCallStatus(p, c, lpCallStatus)
}

// TSPI_lineGetCallAddressID reports which address a call is on. There is
// only one.
//
//export TSPI_lineGetCallAddressID
func TSPI_lineGetCallAddressID(hdCall C.HDRVCALL, lpdwAddressID *C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetCallAddressID", &rc)
	_, _, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	if lpdwAddressID == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	*lpdwAddressID = 0
	return 0
}

// TSPI_lineBlindTransfer transfers a connected call away without
// consultation. On the AMI side this is a Redirect into the dialplan.
//
//export TSPI_lineBlindTransfer
func TSPI_lineBlindTransfer(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpszDestAddress *C.WCHAR, dwCountryCode C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineBlindTransfer", &rc)
	return redirectCall(dwRequestID, hdCall, lpszDestAddress, "blindTransfer")
}

// TSPI_lineRedirect sends an offering call elsewhere before it is answered.
// AMI models this the same way as a blind transfer.
//
//export TSPI_lineRedirect
func TSPI_lineRedirect(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpszDestAddress *C.WCHAR, dwCountryCode C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineRedirect", &rc)
	return redirectCall(dwRequestID, hdCall, lpszDestAddress, "redirect")
}

func redirectCall(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpszDestAddress *C.WCHAR, what string) C.LONG {
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	dest := wstring(lpszDestAddress)
	if dest == "" {
		return lerr(C.LINEERR_INVALADDRESS)
	}
	key := p.keyOf(c)
	return p.async(dwRequestID, what, func() error { return p.mon.Redirect(key, dest) })
}

// TSPI_lineHold and TSPI_lineUnhold depend on the phone honouring a NOTIFY;
// see Line.HoldMode. Without one configured they are refused, and the
// capability bits reported to the application say so.
//
//export TSPI_lineHold
func TSPI_lineHold(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL) (rc C.LONG) {
	defer recoverEntry("TSPI_lineHold", &rc)
	return holdCall(dwRequestID, hdCall, true)
}

//export TSPI_lineUnhold
func TSPI_lineUnhold(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL) (rc C.LONG) {
	defer recoverEntry("TSPI_lineUnhold", &rc)
	return holdCall(dwRequestID, hdCall, false)
}

func holdCall(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, on bool) C.LONG {
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	if !enabledMode(c.line.cfg.HoldMode) {
		return lerr(C.LINEERR_OPERATIONUNAVAIL)
	}
	key := p.keyOf(c)
	what := "hold"
	if !on {
		what = "unhold"
	}
	return p.async(dwRequestID, what, func() error { return p.mon.Hold(key, on) })
}

// TSPI_lineDial would dial further digits on a call set up with a null
// destination, which TSPI_lineMakeCall refuses; there is nothing coherent
// to do here.
//
//export TSPI_lineDial
func TSPI_lineDial(dwRequestID C.DRV_REQUESTID, hdCall C.HDRVCALL, lpszDestAddress *C.WCHAR, dwCountryCode C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineDial", &rc)
	return lerr(C.LINEERR_OPERATIONUNAVAIL)
}

// TSPI_lineGenerateDigits sends DTMF into an established call. It is
// synchronous, and reports completion with LINE_GENERATE.
//
//export TSPI_lineGenerateDigits
func TSPI_lineGenerateDigits(hdCall C.HDRVCALL, dwEndToEndID, dwDigitMode C.DWORD, lpszDigits *C.WCHAR, dwDuration C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGenerateDigits", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	digits := wstring(lpszDigits)
	key := p.keyOf(c)
	endToEnd := dwEndToEndID

	go func() {
		defer logx.Recover("tsp: generateDigits")
		if digits != "" {
			if err := p.mon.SendDigits(key, digits); err != nil {
				logx.Warnf("tsp: generateDigits failed: %v", err)
			}
		}
		p.post(func() {
			p.mu.Lock()
			htLine, htCall, proc := c.line.htLine, c.htCall, c.line.eventProc
			ended := c.ended
			p.mu.Unlock()
			if htCall != nil && !ended {
				p.lineEvent(proc, htLine, htCall, lineMsg{
					msg: C.LINE_GENERATE,
					p1:  C.DWORD_PTR(C.LINEGENERATETERM_DONE),
					p2:  C.DWORD_PTR(endToEnd),
				})
			}
		})
	}()
	return 0
}

// TSPI_lineSetAppSpecific stores the application's private tag on a call.
//
//export TSPI_lineSetAppSpecific
func TSPI_lineSetAppSpecific(hdCall C.HDRVCALL, dwAppSpecific C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineSetAppSpecific", &rc)
	p, c, e := callFor(hdCall)
	if e != 0 {
		return e
	}
	p.mu.Lock()
	c.appSpecific = uint32(dwAppSpecific)
	htLine, htCall, proc := c.line.htLine, c.htCall, c.line.eventProc
	p.mu.Unlock()

	if htCall != nil {
		p.lineEvent(proc, htLine, htCall, lineMsg{
			msg: C.LINE_CALLINFO,
			p1:  C.DWORD_PTR(C.LINECALLINFOSTATE_APPSPECIFIC),
		})
	}
	return 0
}

// keyOf reads a call's correlation key. It can change once, on the pump, when
// a call placed on a pre-12 Asterisk learns its real Uniqueid.
func (p *providerState) keyOf(c *callDev) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return c.key
}

// TSPI_lineSetMediaMode records the media mode an application believes a
// call carries. Everything here is interactive voice.
//
//export TSPI_lineSetMediaMode
func TSPI_lineSetMediaMode(hdCall C.HDRVCALL, dwMediaMode C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineSetMediaMode", &rc)
	_, _, e := callFor(hdCall)
	return e
}

// TSPI_lineMonitorDigits and TSPI_lineMonitorMedia need access to the media
// stream, which a manager-interface provider does not have.
//
//export TSPI_lineMonitorDigits
func TSPI_lineMonitorDigits(hdCall C.HDRVCALL, dwDigitModes C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineMonitorDigits", &rc)
	return lerr(C.LINEERR_OPERATIONUNAVAIL)
}

//export TSPI_lineMonitorMedia
func TSPI_lineMonitorMedia(hdCall C.HDRVCALL, dwMediaModes C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineMonitorMedia", &rc)
	return lerr(C.LINEERR_OPERATIONUNAVAIL)
}

// callFor resolves a call handle, returning a TSPI error code in the third
// result when it cannot.
func callFor(hdCall C.HDRVCALL) (*providerState, *callDev, C.LONG) {
	p := provider()
	if p == nil {
		return nil, nil, lerr(C.LINEERR_UNINITIALIZED)
	}
	c := p.callByToken(hdCall)
	if c == nil {
		return nil, nil, lerr(C.LINEERR_INVALCALLHANDLE)
	}
	return p, c, 0
}
