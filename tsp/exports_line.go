package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "shim.h"
*/
import "C"

import (
	"encoding/binary"
	"strings"
	"time"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/logx"
)

// TSPI_lineGetDevCaps describes a line device to TAPI.
//
//export TSPI_lineGetDevCaps
func TSPI_lineGetDevCaps(dwDeviceID, dwTSPIVersion, dwExtVersion C.DWORD, lpLineDevCaps *C.LINEDEVCAPS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetDevCaps", &rc)
	// The enumeration path is traced at debug level: when an application
	// enumerates the lines but offers none of them, the last call it makes
	// before giving up is what identifies the capability it wanted.
	logx.Debugf("tsp: lineGetDevCaps device %d, TSPI %08x, ext %08x",
		uint32(dwDeviceID), uint32(dwTSPIVersion), uint32(dwExtVersion))

	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpLineDevCaps == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	l := p.lineByDeviceID(dwDeviceID)
	if l == nil {
		return lerr(C.LINEERR_BADDEVICEID)
	}
	return fillLineDevCaps(l, lpLineDevCaps)
}

// TSPI_lineGetAddressCaps describes address 0 of a line. Every line here has
// exactly one address: the extension the device registers as.
//
//export TSPI_lineGetAddressCaps
func TSPI_lineGetAddressCaps(dwDeviceID, dwAddressID, dwTSPIVersion, dwExtVersion C.DWORD, lpAddressCaps *C.LINEADDRESSCAPS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetAddressCaps", &rc)
	logx.Debugf("tsp: lineGetAddressCaps device %d, address %d, TSPI %08x, ext %08x",
		uint32(dwDeviceID), uint32(dwAddressID), uint32(dwTSPIVersion), uint32(dwExtVersion))

	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpAddressCaps == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	if dwAddressID != 0 {
		return lerr(C.LINEERR_INVALADDRESSID)
	}
	l := p.lineByDeviceID(dwDeviceID)
	if l == nil {
		return lerr(C.LINEERR_BADDEVICEID)
	}
	return fillLineAddressCaps(p, l, lpAddressCaps)
}

// TSPI_lineOpen hands TAPI a driver handle for the line and records the
// event callback used for every subsequent notification on it.
//
//export TSPI_lineOpen
func TSPI_lineOpen(dwDeviceID C.DWORD, htLine C.HTAPILINE, lphdLine *C.HDRVLINE, dwTSPIVersion C.DWORD, lpfnEventProc C.LINEEVENT) (rc C.LONG) {
	defer recoverEntry("TSPI_lineOpen", &rc)
	logx.Debugf("tsp: lineOpen device %d, TSPI %08x", uint32(dwDeviceID), uint32(dwTSPIVersion))

	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lphdLine == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	l := p.lineByDeviceID(dwDeviceID)
	if l == nil {
		return lerr(C.LINEERR_BADDEVICEID)
	}

	p.mu.Lock()
	if l.open {
		p.mu.Unlock()
		return lerr(C.LINEERR_ALLOCATED)
	}
	l.token = newToken()
	l.htLine = htLine
	l.eventProc = lpfnEventProc
	l.open = true
	p.linesByToken[l.token] = l
	inService := p.inServiceLocked(l)
	p.mu.Unlock()

	*lphdLine = C.HDRVLINE(l.token)
	logx.Infof("tsp: line %d (%s) opened", uint32(dwDeviceID), l.cfg.Name)

	// Tell the application whether the PBX is reachable, rather than leaving it
	// to guess until the next link transition.
	//
	// This has to happen after TSPI_lineOpen has returned: TAPI does not
	// consider the line open until then, and a LINE_LINEDEVSTATE arriving
	// first is an event on a handle it has not finished setting up. The
	// goroutine is tracked so shutdown knows about it, and the short delay is
	// what keeps it behind the return above.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer logx.Recover("tsp: lineOpen status report")
		state := uint32(C.LINEDEVSTATE_OUTOFSERVICE)
		if inService {
			state = C.LINEDEVSTATE_INSERVICE
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-p.stop:
			return
		}
		p.fireLineDevState(l, state)
	}()
	return 0
}

// TSPI_lineClose releases the driver handle. TAPI has already dropped every
// call on the line by this point.
//
//export TSPI_lineClose
func TSPI_lineClose(hdLine C.HDRVLINE) (rc C.LONG) {
	defer recoverEntry("TSPI_lineClose", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	p.mu.Lock()
	l := p.linesByToken[unsafe.Pointer(hdLine)]
	if l == nil {
		p.mu.Unlock()
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	delete(p.linesByToken, l.token)
	tok := l.token
	l.token = nil
	l.open = false
	l.htLine = nil
	l.eventProc = nil
	l.mediaModes = 0
	name := l.cfg.Name
	p.mu.Unlock()

	freeToken(tok)
	logx.Infof("tsp: line %s closed", name)
	return 0
}

// TSPI_lineGetNumAddressIDs reports the number of addresses on the line.
//
//export TSPI_lineGetNumAddressIDs
func TSPI_lineGetNumAddressIDs(hdLine C.HDRVLINE, lpdwNumAddressIDs *C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetNumAddressIDs", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpdwNumAddressIDs == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	if p.lineByToken(hdLine) == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	*lpdwNumAddressIDs = 1
	return 0
}

// TSPI_lineGetAddressID resolves an address string to an address ID. With a
// single address per line the answer is always zero.
//
//export TSPI_lineGetAddressID
func TSPI_lineGetAddressID(hdLine C.HDRVLINE, lpdwAddressID *C.DWORD, dwAddressMode C.DWORD, lpsAddress *C.WCHAR, dwSize C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetAddressID", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpdwAddressID == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	if p.lineByToken(hdLine) == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	*lpdwAddressID = 0
	return 0
}

// TSPI_lineSetDefaultMediaDetection records which media modes the
// application wants offered calls filtered to. We only ever report
// interactive voice, so this is bookkeeping for LINEDEVSTATUS.
//
//export TSPI_lineSetDefaultMediaDetection
func TSPI_lineSetDefaultMediaDetection(hdLine C.HDRVLINE, dwMediaModes C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineSetDefaultMediaDetection", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	l := p.lineByToken(hdLine)
	if l == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	// The media modes an application asks for here are the ones it expects the
	// line to carry; anything outside what LINEDEVCAPS advertises is a
	// mismatch worth seeing.
	logx.Debugf("tsp: lineSetDefaultMediaDetection %s, media modes %08x", l.cfg.Name, uint32(dwMediaModes))
	p.mu.Lock()
	l.mediaModes = uint32(dwMediaModes)
	p.mu.Unlock()
	return 0
}

// TSPI_lineConditionalMediaDetection is the per-call variant. There is no
// media negotiation to do, so accepting is correct.
//
//export TSPI_lineConditionalMediaDetection
func TSPI_lineConditionalMediaDetection(hdLine C.HDRVLINE, dwMediaModes C.DWORD, lpCallParams *C.LINECALLPARAMS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineConditionalMediaDetection", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if p.lineByToken(hdLine) == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	logx.Debugf("tsp: lineConditionalMediaDetection, media modes %08x", uint32(dwMediaModes))
	return 0
}

// TSPI_lineSetStatusMessages records which state changes the application
// wants. We send everything we know regardless; TapiSrv filters.
//
//export TSPI_lineSetStatusMessages
func TSPI_lineSetStatusMessages(hdLine C.HDRVLINE, dwLineStates, dwAddressStates C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineSetStatusMessages", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	l := p.lineByToken(hdLine)
	if l == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	p.mu.Lock()
	l.lineStates = uint32(dwLineStates)
	l.addressStates = uint32(dwAddressStates)
	p.mu.Unlock()
	return 0
}

// TSPI_lineGetLineDevStatus reports the live state of a line.
//
//export TSPI_lineGetLineDevStatus
func TSPI_lineGetLineDevStatus(hdLine C.HDRVLINE, lpLineDevStatus *C.LINEDEVSTATUS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetLineDevStatus", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpLineDevStatus == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	l := p.lineByToken(hdLine)
	if l == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	return fillLineDevStatus(p, l, lpLineDevStatus)
}

// TSPI_lineGetAddressStatus reports the live state of an address.
//
//export TSPI_lineGetAddressStatus
func TSPI_lineGetAddressStatus(hdLine C.HDRVLINE, dwAddressID C.DWORD, lpAddressStatus *C.LINEADDRESSSTATUS) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetAddressStatus", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpAddressStatus == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	if dwAddressID != 0 {
		return lerr(C.LINEERR_INVALADDRESSID)
	}
	l := p.lineByToken(hdLine)
	if l == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}
	return fillLineAddressStatus(p, l, lpAddressStatus)
}

// TSPI_lineGetID returns a device identifier for a device class.
//
// "tapi/line" yields the line's device ID and "tapi/providerid" the permanent
// provider ID, which is how an application discovers that a set of lines all
// belong to this TSP. No media class is offered: AMI gives this provider call
// control only, so there is no stream to hand over.
//
//export TSPI_lineGetID
func TSPI_lineGetID(hdLine C.HDRVLINE, dwAddressID C.DWORD, hdCall C.HDRVCALL, dwSelect C.DWORD,
	lpDeviceID *C.VARSTRING, lpszDeviceClass *C.WCHAR, hTargetProcess C.HANDLE) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetID", &rc)

	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}
	if lpDeviceID == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}

	var l *lineDev
	if c := p.callByToken(hdCall); c != nil {
		l = c.line
	} else {
		l = p.lineByToken(hdLine)
	}
	if l == nil {
		return lerr(C.LINEERR_INVALLINEHANDLE)
	}

	// A device class we do not answer is a strong hint about why an
	// application rejected the line, so it is logged as a warning rather than
	// buried at debug level.
	var id uint32
	switch class := wstring(lpszDeviceClass); {
	case strings.EqualFold(class, "tapi/line"):
		id = l.deviceID
	case strings.EqualFold(class, "tapi/providerid"):
		id = p.permProviderID
	default:
		logx.Warnf("tsp: lineGetID asked for unsupported device class %q on %s", class, l.cfg.Name)
		return lerr(C.LINEERR_INVALDEVICECLASS)
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], id)
	return fillVarStringBinary(lpDeviceID, buf[:])
}

// TSPI_lineGetIcon has no icon resource to hand out.
//
//export TSPI_lineGetIcon
func TSPI_lineGetIcon(dwDeviceID C.DWORD, lpszDeviceClass *C.WCHAR, lphIcon *C.HICON) (rc C.LONG) {
	defer recoverEntry("TSPI_lineGetIcon", &rc)
	// TAPI substitutes a default icon, but an application that insists on one
	// of its own drops the line instead, so record that it asked.
	if logx.Enabled(logx.LevelDebug) {
		logx.Debugf("tsp: lineGetIcon device %d, class %q, refusing (no icon resource)",
			uint32(dwDeviceID), wstring(lpszDeviceClass))
	}
	return lerr(C.LINEERR_OPERATIONUNAVAIL)
}

// TSPI_lineDevSpecific exposes no vendor extensions.
//
//export TSPI_lineDevSpecific
func TSPI_lineDevSpecific(dwRequestID C.DRV_REQUESTID, hdLine C.HDRVLINE, dwAddressID C.DWORD,
	hdCall C.HDRVCALL, lpParams unsafe.Pointer, dwSize C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineDevSpecific", &rc)
	// An application reaching for a vendor extension is looking for a specific
	// PBX's TSP, and will not settle for this one; worth knowing about.
	logx.Warnf("tsp: lineDevSpecific requested (%d bytes), no vendor extensions are offered", uint32(dwSize))
	return lerr(C.LINEERR_OPERATIONUNAVAIL)
}
