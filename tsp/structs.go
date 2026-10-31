package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "shim.h"
*/
import "C"

import (
	"crypto/sha1"
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"
)

// TAPI's variable-size structures all follow the same shape: a fixed header
// ending with pairs of size/offset fields, followed by a variable region.
// varBuf appends into that region and tracks dwUsedSize / dwNeededSize.
//
// TSPI structures carry Unicode strings (TAPISRV converts down for ANSI
// applications), which is why everything here is UTF-16.
type varBuf struct {
	base   unsafe.Pointer
	total  uint32
	cursor uint32
	needed uint32
	failed bool
}

func newVarBuf(base unsafe.Pointer, total, fixed uint32) *varBuf {
	return &varBuf{base: base, total: total, cursor: fixed, needed: fixed}
}

// used returns the value for dwUsedSize.
func (b *varBuf) used() uint32 {
	if b.failed {
		return b.cursor
	}
	return b.cursor
}

func (b *varBuf) addString(s string) (size, offset uint32) {
	if s == "" {
		return 0, 0
	}
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	return b.addBytes(utf16Bytes(u))
}

// addStringList writes a REG_MULTI_SZ style list (each item NUL terminated,
// the list terminated by an extra NUL), which is how TAPI reports device
// class lists.
func (b *varBuf) addStringList(items []string) (size, offset uint32) {
	if len(items) == 0 {
		return 0, 0
	}
	var u []uint16
	for _, s := range items {
		u = append(u, utf16.Encode([]rune(s))...)
		u = append(u, 0)
	}
	u = append(u, 0)
	return b.addBytes(utf16Bytes(u))
}

func (b *varBuf) addBytes(raw []byte) (size, offset uint32) {
	n := uint32(len(raw))
	if n == 0 {
		return 0, 0
	}
	// Keep offsets DWORD aligned; some applications copy these regions with
	// aligned reads.
	if pad := b.needed % 4; pad != 0 {
		b.needed += 4 - pad
		if !b.failed {
			b.cursor = b.needed
		}
	}
	if b.failed || b.needed+n > b.total {
		// Once anything overflows, stop writing entirely: a partially
		// written region with valid-looking offsets is worse than a clean
		// LINEERR_STRUCTURETOOSMALL.
		b.failed = true
		b.needed += n
		return 0, 0
	}
	off := b.needed
	copy(unsafe.Slice((*byte)(unsafe.Add(b.base, off)), n), raw)
	b.needed += n
	b.cursor = b.needed
	return n, off
}

func utf16Bytes(u []uint16) []byte {
	out := make([]byte, len(u)*2)
	for i, c := range u {
		out[2*i] = byte(c)
		out[2*i+1] = byte(c >> 8)
	}
	return out
}

// zeroTail clears a TAPI structure from just past dwTotalSize to the end of
// its fixed part. dwTotalSize is the caller's and must survive.
func zeroTail(p unsafe.Pointer, fixed uint32) {
	if fixed <= 4 {
		return
	}
	buf := unsafe.Slice((*byte)(unsafe.Add(p, 4)), fixed-4)
	for i := range buf {
		buf[i] = 0
	}
}

// wstring converts a NUL-terminated UTF-16 string from TAPI into a Go string.
func wstring(p *C.WCHAR) string {
	if p == nil {
		return ""
	}
	var u []uint16
	for i := 0; ; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), uintptr(i)*2))
		if c == 0 {
			break
		}
		u = append(u, c)
		if i > 4096 {
			break
		}
	}
	return string(utf16.Decode(u))
}

// ---------------------------------------------------------------- devcaps

const providerInfoString = "AMI TSP - Asterisk Manager Interface provider"

// deviceClasses is what TSPI_lineGetID accepts, and is reported on both the
// line and the address.
//
// "tapi/providerid" is the standard way for an application to ask which
// service provider a line came from, and applications that group or filter
// lines by provider expect every TSP to answer it. Reporting only "tapi/line"
// left those applications unable to place our lines. There is no media stream
// to hand over -- AMI gives this provider call control only -- so no wave or
// comm class belongs here.
var deviceClasses = []string{"tapi/line", "tapi/providerid"}

// lineGUIDNamespace scopes the name-based GUIDs below. It is an arbitrary but
// fixed UUID: its only job is to keep the GUIDs this provider generates from
// colliding with anyone else's. It must never change, because the GUIDs
// derived from it are what applications remember a line device by.
var lineGUIDNamespace = [16]byte{
	0x6b, 0x1f, 0xa4, 0xd2, 0x0e, 0x7c, 0x4b, 0x8e,
	0x9a, 0x31, 0xc5, 0x0d, 0x7e, 0x62, 0x14, 0x93,
}

// permanentLineGUID derives a stable RFC 4122 version 5 (SHA-1, name based)
// UUID from the Asterisk channel name.
//
// LINEDEVCAPS.PermanentLineGuid used to be left as all zeros, which meant
// every line device reported the same null GUID. Applications that key their
// line list by GUID rather than by dwPermanentLineID then see one device
// where there are many, or reject the lot as duplicates. Deriving it from the
// channel keeps it stable across restarts, reinstalls and machines, which is
// what "permanent" has to mean for an application storing it in a profile.
func permanentLineGUID(channel string, permanentID uint32) [16]byte {
	// Channel is the registry's identity key and is unique per line; fall
	// back to the permanent ID only if a line somehow has no channel.
	name := strings.ToLower(strings.TrimSpace(channel))
	if name == "" {
		name = "permanent-id:" + strconv.FormatUint(uint64(permanentID), 10)
	}

	h := sha1.New()
	h.Write(lineGUIDNamespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)

	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return u
}

// setGUID writes an RFC 4122 byte order UUID into a Windows GUID, whose first
// three fields are stored in native (little endian) order.
func setGUID(g *C.GUID, u [16]byte) {
	g.Data1 = C.ulong(binary.BigEndian.Uint32(u[0:4]))
	g.Data2 = C.ushort(binary.BigEndian.Uint16(u[4:6]))
	g.Data3 = C.ushort(binary.BigEndian.Uint16(u[6:8]))
	for i := 0; i < 8; i++ {
		g.Data4[i] = C.uchar(u[8+i])
	}
}

func fillLineDevCaps(l *lineDev, p *C.LINEDEVCAPS) C.LONG {
	fixed := uint32(unsafe.Sizeof(*p))
	if uint32(p.dwTotalSize) < fixed {
		p.dwNeededSize = C.DWORD(fixed)
		p.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	total := uint32(p.dwTotalSize)
	zeroTail(unsafe.Pointer(p), fixed)
	b := newVarBuf(unsafe.Pointer(p), total, fixed)

	sz, off := b.addString(providerInfoString)
	p.dwProviderInfoSize, p.dwProviderInfoOffset = C.DWORD(sz), C.DWORD(off)

	sz, off = b.addString("Asterisk " + l.cfg.Channel)
	p.dwSwitchInfoSize, p.dwSwitchInfoOffset = C.DWORD(sz), C.DWORD(off)

	sz, off = b.addString(l.cfg.Name)
	p.dwLineNameSize, p.dwLineNameOffset = C.DWORD(sz), C.DWORD(off)

	sz, off = b.addStringList(deviceClasses)
	p.dwDeviceClassesSize, p.dwDeviceClassesOffset = C.DWORD(sz), C.DWORD(off)

	p.dwPermanentLineID = C.DWORD(l.cfg.PermanentID)
	// The dwTotalSize check above guarantees the whole fixed part, GUID
	// included, is inside the caller's buffer.
	setGUID(&p.PermanentLineGuid, permanentLineGUID(l.cfg.Channel, l.cfg.PermanentID))
	p.dwStringFormat = C.STRINGFORMAT_UNICODE
	p.dwAddressModes = C.LINEADDRESSMODE_ADDRESSID
	p.dwNumAddresses = 1
	p.dwBearerModes = C.LINEBEARERMODE_VOICE
	p.dwMaxRate = 64000
	// Every call this provider reports is interactive voice; it never reports
	// LINEMEDIAMODE_UNKNOWN, so claiming it here only invites an application
	// that compares this field for equality rather than by bit to reject the
	// line. LINEADDRESSCAPS still offers UNKNOWN as an accepted mode.
	p.dwMediaModes = C.LINEMEDIAMODE_INTERACTIVEVOICE

	// No tone generation or digit gathering: AMI gives us call control, not
	// media, so everything media related stays zero.
	p.dwDevCapFlags = C.LINEDEVCAPFLAGS_CLOSEDROP
	p.dwMaxNumActiveCalls = C.DWORD(maxCallsPerLine)

	// What happens to the call already up when a second one is answered. With
	// a hold mechanism configured the phone parks the first call; without one
	// nothing happens to it, because we cannot make it happen.
	p.dwAnswerMode = C.LINEANSWERMODE_NONE
	if enabledMode(l.cfg.HoldMode) {
		p.dwAnswerMode = C.LINEANSWERMODE_HOLD
	}
	p.dwRingModes = 1
	p.dwLineStates = C.LINEDEVSTATE_OTHER | C.LINEDEVSTATE_RINGING |
		C.LINEDEVSTATE_CONNECTED | C.LINEDEVSTATE_DISCONNECTED |
		C.LINEDEVSTATE_INSERVICE | C.LINEDEVSTATE_OUTOFSERVICE |
		C.LINEDEVSTATE_NUMCALLS | C.LINEDEVSTATE_OPEN | C.LINEDEVSTATE_CLOSE |
		C.LINEDEVSTATE_REINIT
	p.dwLineFeatures = C.LINEFEATURE_MAKECALL

	p.dwNeededSize = C.DWORD(b.needed)
	p.dwUsedSize = C.DWORD(b.used())
	if b.failed {
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	return 0
}

// fillLineDevCapsInto fills a LINEDEVCAPS placed at the start of raw, whose
// length becomes dwTotalSize. It exists because `go test` refuses cgo in
// _test.go files, and the structure's layout is worth testing: cmd/amitsp-ctl
// decodes the same bytes using hard-coded offsets.
//
// raw must be aligned for the structure; allocate it as []uint64 and take a
// byte view.
func fillLineDevCapsInto(l *lineDev, raw []byte) int32 {
	if len(raw) < 4 {
		return int32(lerr(C.LINEERR_STRUCTURETOOSMALL))
	}
	caps := (*C.LINEDEVCAPS)(unsafe.Pointer(&raw[0]))
	caps.dwTotalSize = C.DWORD(len(raw))
	return int32(fillLineDevCaps(l, caps))
}

func fillLineAddressCaps(p *providerState, l *lineDev, ac *C.LINEADDRESSCAPS) C.LONG {
	fixed := uint32(unsafe.Sizeof(*ac))
	if uint32(ac.dwTotalSize) < fixed {
		ac.dwNeededSize = C.DWORD(fixed)
		ac.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	total := uint32(ac.dwTotalSize)
	zeroTail(unsafe.Pointer(ac), fixed)
	b := newVarBuf(unsafe.Pointer(ac), total, fixed)

	sz, off := b.addString(l.cfg.Extension)
	ac.dwAddressSize, ac.dwAddressOffset = C.DWORD(sz), C.DWORD(off)

	ac.dwLineDeviceID = C.DWORD(l.deviceID)
	ac.dwAddressSharing = C.LINEADDRESSSHARING_PRIVATE
	ac.dwAddressStates = C.LINEADDRESSSTATE_INUSEZERO | C.LINEADDRESSSTATE_INUSEONE |
		C.LINEADDRESSSTATE_NUMCALLS | C.LINEADDRESSSTATE_OTHER
	ac.dwCallInfoStates = C.LINECALLINFOSTATE_CALLERID | C.LINECALLINFOSTATE_CALLEDID |
		C.LINECALLINFOSTATE_CONNECTEDID | C.LINECALLINFOSTATE_ORIGIN |
		C.LINECALLINFOSTATE_REASON | C.LINECALLINFOSTATE_NUMOWNERINCR |
		C.LINECALLINFOSTATE_NUMOWNERDECR | C.LINECALLINFOSTATE_APPSPECIFIC

	partyID := C.DWORD(C.LINECALLPARTYID_BLOCKED | C.LINECALLPARTYID_UNKNOWN |
		C.LINECALLPARTYID_ADDRESS | C.LINECALLPARTYID_NAME)
	ac.dwCallerIDFlags = partyID
	ac.dwCalledIDFlags = partyID
	ac.dwConnectedIDFlags = partyID
	ac.dwRedirectionIDFlags = partyID
	ac.dwRedirectingIDFlags = partyID

	ac.dwCallStates = C.LINECALLSTATE_IDLE | C.LINECALLSTATE_OFFERING |
		C.LINECALLSTATE_ACCEPTED | C.LINECALLSTATE_DIALING |
		C.LINECALLSTATE_PROCEEDING | C.LINECALLSTATE_RINGBACK |
		C.LINECALLSTATE_BUSY | C.LINECALLSTATE_CONNECTED |
		C.LINECALLSTATE_ONHOLD | C.LINECALLSTATE_DISCONNECTED |
		C.LINECALLSTATE_UNKNOWN
	ac.dwDisconnectModes = C.LINEDISCONNECTMODE_NORMAL | C.LINEDISCONNECTMODE_UNKNOWN |
		C.LINEDISCONNECTMODE_BUSY | C.LINEDISCONNECTMODE_NOANSWER |
		C.LINEDISCONNECTMODE_REJECT | C.LINEDISCONNECTMODE_UNAVAIL |
		C.LINEDISCONNECTMODE_CONGESTION | C.LINEDISCONNECTMODE_NODIALTONE

	ac.dwMaxNumActiveCalls = C.DWORD(maxCallsPerLine)
	ac.dwAddrCapFlags = C.LINEADDRCAPFLAGS_DIALED
	ac.dwCallFeatures = C.DWORD(lineCallFeatures(l))
	ac.dwAddressFeatures = C.LINEADDRFEATURE_MAKECALL

	// The media this address can carry. Leaving it zero contradicts the line's
	// dwMediaModes, and an application that checks the address rather than the
	// line concludes it cannot carry a voice call.
	ac.dwAvailableMediaModes = C.LINEMEDIAMODE_INTERACTIVEVOICE | C.LINEMEDIAMODE_UNKNOWN

	// The address answers the same device classes as the line it belongs to.
	sz, off = b.addStringList(deviceClasses)
	ac.dwDeviceClassesSize, ac.dwDeviceClassesOffset = C.DWORD(sz), C.DWORD(off)

	if enabledMode(l.cfg.HoldMode) {
		// Advertising LINECALLFEATURE_HOLD while claiming room for no held
		// calls is a contradiction, and applications resolve it by not
		// offering hold at all.
		ac.dwMaxNumOnHoldCalls = C.DWORD(maxCallsPerLine)
	}
	if enabledMode(l.cfg.AnswerMode) {
		// With an answer mechanism configured the device is taken off hook for
		// us when a call is originated, so the application does not have to
		// prompt the user to lift the handset first.
		ac.dwAddrCapFlags |= C.LINEADDRCAPFLAGS_ORIGOFFHOOK
	}

	// Blind transfer is a Redirect on the AMI side and needs no consultation
	// call, so only the blind mode is advertised.
	if l.cfg.Channel != "" {
		ac.dwTransferModes = C.LINETRANSFERMODE_TRANSFER
	}

	ac.dwNeededSize = C.DWORD(b.needed)
	ac.dwUsedSize = C.DWORD(b.used())
	if b.failed {
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	return 0
}

// fillLineAddressCapsInto is the LINEADDRESSCAPS counterpart of
// fillLineDevCapsInto; see that function for why it exists.
func fillLineAddressCapsInto(l *lineDev, raw []byte) int32 {
	if len(raw) < 4 {
		return int32(lerr(C.LINEERR_STRUCTURETOOSMALL))
	}
	ac := (*C.LINEADDRESSCAPS)(unsafe.Pointer(&raw[0]))
	ac.dwTotalSize = C.DWORD(len(raw))
	return int32(fillLineAddressCaps(nil, l, ac))
}

// lineCallFeatures reports what a call on this line can do. Answer and hold
// are only advertised when the configuration enables a mechanism for them,
// so applications grey out buttons that would fail.
func lineCallFeatures(l *lineDev) uint32 {
	f := uint32(C.LINECALLFEATURE_DROP | C.LINECALLFEATURE_BLINDTRANSFER |
		C.LINECALLFEATURE_REDIRECT | C.LINECALLFEATURE_GENERATEDIGITS)
	if enabledMode(l.cfg.AnswerMode) {
		f |= C.LINECALLFEATURE_ANSWER
	}
	if enabledMode(l.cfg.HoldMode) {
		f |= C.LINECALLFEATURE_HOLD | C.LINECALLFEATURE_UNHOLD
	}
	return f
}

func enabledMode(m string) bool {
	return m != "" && m != "none"
}

// --------------------------------------------------------------- statuses

func fillLineDevStatus(p *providerState, l *lineDev, st *C.LINEDEVSTATUS) C.LONG {
	fixed := uint32(unsafe.Sizeof(*st))
	if uint32(st.dwTotalSize) < fixed {
		st.dwNeededSize = C.DWORD(fixed)
		st.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	zeroTail(unsafe.Pointer(st), fixed)

	p.mu.Lock()
	active := p.activeCallsLocked(l)
	inService := p.inServiceLocked(l)
	open := l.open
	media := l.mediaModes
	p.mu.Unlock()

	if open {
		st.dwNumOpens = 1
	}
	st.dwOpenMediaModes = C.DWORD(media)
	st.dwNumActiveCalls = C.DWORD(active)
	st.dwLineFeatures = C.LINEFEATURE_MAKECALL
	st.dwAvailableMediaModes = C.LINEMEDIAMODE_INTERACTIVEVOICE | C.LINEMEDIAMODE_UNKNOWN
	if inService {
		st.dwDevStatusFlags = C.LINEDEVSTATUSFLAGS_CONNECTED | C.LINEDEVSTATUSFLAGS_INSERVICE
	}
	st.dwNeededSize = C.DWORD(fixed)
	st.dwUsedSize = C.DWORD(fixed)
	return 0
}

func fillLineAddressStatus(p *providerState, l *lineDev, st *C.LINEADDRESSSTATUS) C.LONG {
	fixed := uint32(unsafe.Sizeof(*st))
	if uint32(st.dwTotalSize) < fixed {
		st.dwNeededSize = C.DWORD(fixed)
		st.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	zeroTail(unsafe.Pointer(st), fixed)

	p.mu.Lock()
	var active, held uint32
	for _, c := range p.callsByToken {
		if c.line != l || c.ended {
			continue
		}
		active++
		if c.state == C.LINECALLSTATE_ONHOLD {
			held++
		}
	}
	p.mu.Unlock()

	if active > 0 {
		st.dwNumInUse = 1
	}
	st.dwNumActiveCalls = C.DWORD(active)
	st.dwNumOnHoldCalls = C.DWORD(held)
	st.dwAddressFeatures = C.LINEADDRFEATURE_MAKECALL
	st.dwNeededSize = C.DWORD(fixed)
	st.dwUsedSize = C.DWORD(fixed)
	return 0
}

// ------------------------------------------------------------- call info

func fillCallInfo(p *providerState, c *callDev, ci *C.LINECALLINFO) C.LONG {
	fixed := uint32(unsafe.Sizeof(*ci))
	if uint32(ci.dwTotalSize) < fixed {
		ci.dwNeededSize = C.DWORD(fixed)
		ci.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	total := uint32(ci.dwTotalSize)
	zeroTail(unsafe.Pointer(ci), fixed)
	b := newVarBuf(unsafe.Pointer(ci), total, fixed)

	p.mu.Lock()
	line := c.line
	inbound := c.inbound
	remoteNum, remoteName, localNum := c.remoteNum, c.remoteName, c.localNum
	state := c.state
	appSpecific := c.appSpecific
	p.mu.Unlock()

	ci.dwLineDeviceID = C.DWORD(line.deviceID)
	ci.dwAddressID = 0
	ci.dwBearerMode = C.LINEBEARERMODE_VOICE
	ci.dwRate = 64000
	ci.dwMediaMode = C.LINEMEDIAMODE_INTERACTIVEVOICE
	ci.dwAppSpecific = C.DWORD(appSpecific)
	ci.dwCallStates = C.DWORD(state)
	ci.dwNumOwners = 1
	ci.dwNumMonitors = 0
	ci.dwReason = C.LINECALLREASON_DIRECT

	// Caller/called are fixed at call setup; connected reflects who is
	// actually on the call now, which can change after a transfer.
	var callerNum, callerName, calledNum string
	if inbound {
		ci.dwOrigin = C.LINECALLORIGIN_EXTERNAL
		callerNum, callerName, calledNum = remoteNum, remoteName, localNum
	} else {
		ci.dwOrigin = C.LINECALLORIGIN_OUTBOUND
		callerNum, callerName, calledNum = localNum, line.cfg.CallerIDName, remoteNum
	}

	if callerNum != "" {
		sz, off := b.addString(callerNum)
		ci.dwCallerIDSize, ci.dwCallerIDOffset = C.DWORD(sz), C.DWORD(off)
		ci.dwCallerIDFlags = C.LINECALLPARTYID_ADDRESS
	} else {
		ci.dwCallerIDFlags = C.LINECALLPARTYID_UNKNOWN
	}
	if callerName != "" {
		sz, off := b.addString(callerName)
		ci.dwCallerIDNameSize, ci.dwCallerIDNameOffset = C.DWORD(sz), C.DWORD(off)
		ci.dwCallerIDFlags |= C.LINECALLPARTYID_NAME
	}

	if calledNum != "" {
		sz, off := b.addString(calledNum)
		ci.dwCalledIDSize, ci.dwCalledIDOffset = C.DWORD(sz), C.DWORD(off)
		ci.dwCalledIDFlags = C.LINECALLPARTYID_ADDRESS
	} else {
		ci.dwCalledIDFlags = C.LINECALLPARTYID_UNKNOWN
	}

	if remoteNum != "" {
		sz, off := b.addString(remoteNum)
		ci.dwConnectedIDSize, ci.dwConnectedIDOffset = C.DWORD(sz), C.DWORD(off)
		ci.dwConnectedIDFlags = C.LINECALLPARTYID_ADDRESS
		if remoteName != "" {
			sz, off = b.addString(remoteName)
			ci.dwConnectedIDNameSize, ci.dwConnectedIDNameOffset = C.DWORD(sz), C.DWORD(off)
			ci.dwConnectedIDFlags |= C.LINECALLPARTYID_NAME
		}
		sz, off = b.addString(remoteNum)
		ci.dwDisplayableAddressSize, ci.dwDisplayableAddressOffset = C.DWORD(sz), C.DWORD(off)
	} else {
		ci.dwConnectedIDFlags = C.LINECALLPARTYID_UNKNOWN
	}

	ci.dwNeededSize = C.DWORD(b.needed)
	ci.dwUsedSize = C.DWORD(b.used())
	if b.failed {
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	return 0
}

func fillCallStatus(p *providerState, c *callDev, cs *C.LINECALLSTATUS) C.LONG {
	fixed := uint32(unsafe.Sizeof(*cs))
	if uint32(cs.dwTotalSize) < fixed {
		cs.dwNeededSize = C.DWORD(fixed)
		cs.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	zeroTail(unsafe.Pointer(cs), fixed)

	p.mu.Lock()
	state, mode, line := c.state, c.stateMode, c.line
	p.mu.Unlock()

	cs.dwCallState = C.DWORD(state)
	cs.dwCallStateMode = C.DWORD(mode)
	cs.dwCallPrivilege = C.LINECALLPRIVILEGE_OWNER
	cs.dwCallFeatures = C.DWORD(callFeaturesForState(line, state))
	cs.dwNeededSize = C.DWORD(fixed)
	cs.dwUsedSize = C.DWORD(fixed)
	return 0
}

// callFeaturesForState narrows the line's capabilities to what is legal in
// the call's current state, which is what drives button enablement in most
// TAPI applications.
func callFeaturesForState(l *lineDev, state uint32) uint32 {
	all := lineCallFeatures(l)
	switch state {
	case C.LINECALLSTATE_OFFERING:
		return all & uint32(C.LINECALLFEATURE_ANSWER|C.LINECALLFEATURE_DROP|C.LINECALLFEATURE_REDIRECT)
	case C.LINECALLSTATE_CONNECTED:
		return all &^ uint32(C.LINECALLFEATURE_ANSWER|C.LINECALLFEATURE_UNHOLD)
	case C.LINECALLSTATE_ONHOLD:
		return all & uint32(C.LINECALLFEATURE_UNHOLD|C.LINECALLFEATURE_DROP)
	case C.LINECALLSTATE_IDLE, C.LINECALLSTATE_DISCONNECTED:
		return 0
	default:
		return all & uint32(C.LINECALLFEATURE_DROP)
	}
}

// ------------------------------------------------------------- varstring

func fillVarStringBinary(vs *C.VARSTRING, data []byte) C.LONG {
	fixed := uint32(unsafe.Sizeof(*vs))
	if uint32(vs.dwTotalSize) < fixed {
		vs.dwNeededSize = C.DWORD(fixed + uint32(len(data)))
		vs.dwUsedSize = 3 * 4
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	total := uint32(vs.dwTotalSize)
	zeroTail(unsafe.Pointer(vs), fixed)
	b := newVarBuf(unsafe.Pointer(vs), total, fixed)

	vs.dwStringFormat = C.STRINGFORMAT_BINARY
	sz, off := b.addBytes(data)
	vs.dwStringSize, vs.dwStringOffset = C.DWORD(sz), C.DWORD(off)
	vs.dwNeededSize = C.DWORD(b.needed)
	vs.dwUsedSize = C.DWORD(b.used())
	if b.failed {
		return lerr(C.LINEERR_STRUCTURETOOSMALL)
	}
	return 0
}
