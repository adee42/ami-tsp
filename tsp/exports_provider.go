package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "shim.h"
*/
import "C"

import (
	"time"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/logx"
	"github.com/adee42/ami-tsp/internal/pbx"
)

// TSPI_lineNegotiateTSPIVersion agrees a TSPI version with TapiSrv. It is the
// very first thing called, and is also called per device.
//
//export TSPI_lineNegotiateTSPIVersion
func TSPI_lineNegotiateTSPIVersion(dwDeviceID, dwLowVersion, dwHighVersion C.DWORD, lpdwTSPIVersion *C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_lineNegotiateTSPIVersion", &rc)
	if lpdwTSPIVersion == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	low, high := uint32(dwLowVersion), uint32(dwHighVersion)
	v := uint32(tspiVersionHigh)
	if v > high {
		v = high
	}
	if v < low || v < tspiVersionLow {
		// This is where an application that requires a newer TAPI than this
		// provider speaks loses the line, and it does so silently: TAPI simply
		// omits the device from what the application sees.
		logx.Warnf("tsp: version negotiation failed for device %d, caller wants %08x..%08x, we offer %08x..%08x",
			uint32(dwDeviceID), low, high, uint32(tspiVersionLow), uint32(tspiVersionHigh))
		return lerr(C.LINEERR_INCOMPATIBLEAPIVERSION)
	}
	logx.Debugf("tsp: negotiated TSPI %08x for device %d (caller wants %08x..%08x)",
		v, uint32(dwDeviceID), low, high)
	*lpdwTSPIVersion = C.DWORD(v)
	return 0
}

// TSPI_providerEnumDevices reports how many devices this provider offers.
// TapiSrv calls it before TSPI_providerInit, so this is where configuration
// is read and logging is brought up.
//
//export TSPI_providerEnumDevices
func TSPI_providerEnumDevices(dwPermanentProviderID C.DWORD, lpdwNumLines, lpdwNumPhones *C.DWORD,
	hProvider C.HPROVIDER, lpfnLineCreateProc C.LINEEVENT, lpfnPhoneCreateProc C.PHONEEVENT) (rc C.LONG) {
	defer recoverEntry("TSPI_providerEnumDevices", &rc)

	if lpdwNumLines == nil || lpdwNumPhones == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	*lpdwNumPhones = 0
	*lpdwNumLines = 0

	// Save the runtime device-creation callback before anything else can fail:
	// without it, a line discovered later could never be announced.
	createMu.Lock()
	createProc, provHandle = lpfnLineCreateProc, hProvider
	createMu.Unlock()

	_, reg, err := loadConfig()
	if err != nil {
		// Reporting zero devices lets the provider load and leaves a
		// diagnosable log behind. Failing here would make TapiSrv discard
		// the provider with no explanation for the administrator.
		logx.Errorf("tsp: no devices, configuration unusable: %v", err)
		return 0
	}
	*lpdwNumLines = C.DWORD(reg.Len())
	logx.Infof("tsp: enumerated %d line device(s), provider id %d", reg.Len(), uint32(dwPermanentProviderID))
	return 0
}

// TSPI_providerInit brings the provider up: it fixes the device ID range,
// stores the completion callback and connects to the PBX.
//
//export TSPI_providerInit
func TSPI_providerInit(dwTSPIVersion, dwPermanentProviderID, dwLineDeviceIDBase, dwPhoneDeviceIDBase C.DWORD,
	dwNumLines, dwNumPhones C.DWORD_PTR, lpfnCompletionProc C.ASYNC_COMPLETION, lpdwTSPIOptions *C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_providerInit", &rc)

	// The Go runtime cannot be unloaded; make sure nobody tries.
	C.amitsp_pin_module()

	cfg, reg, err := cachedConfig()
	if err != nil {
		logx.Errorf("tsp: providerInit aborted: %v", err)
		return lerr(C.LINEERR_INIFILECORRUPT)
	}
	// A previous shutdown closed the log; TapiSrv may re-initialise us
	// without re-enumerating, so reopen it here rather than assume.
	logx.Configure(cfg.Log.File, logx.ParseLevel(cfg.Log.Level))

	provMu.Lock()
	if prov != nil {
		provMu.Unlock()
		logx.Warnf("tsp: providerInit called while already initialised")
		return 0
	}

	p := &providerState{
		cfg:              cfg,
		reg:              reg,
		tspiVersion:      uint32(dwTSPIVersion),
		permProviderID:   uint32(dwPermanentProviderID),
		lineDeviceIDBase: uint32(dwLineDeviceIDBase),
		completion:       lpfnCompletionProc,
		linesByDeviceID:  make(map[uint32]*lineDev),
		linesByToken:     make(map[unsafe.Pointer]*lineDev),
		callsByToken:     make(map[unsafe.Pointer]*callDev),
		callsByKey:       make(map[string]*callDev),
		tasks:            make(chan func(), 1024),
		stop:             make(chan struct{}),
	}
	// Set before any device is described, and never again: TapiSrv is not
	// told about a change to LINEDEVCAPS.
	maxCallsPerLine = uint32(cfg.TAPI.MaxCallsPerLine)
	// The devices TapiSrv already knows about occupy the ID range it reserved
	// for us, in registry order. Anything discovered later gets its ID from
	// TSPI_providerCreateLineDevice instead.
	for i, e := range reg.Entries() {
		l := &lineDev{
			index:    i,
			cfg:      e.Line,
			deviceID: uint32(dwLineDeviceIDBase) + uint32(i),
			created:  true,
			present:  true,
		}
		p.lines = append(p.lines, l)
		p.linesByDeviceID[l.deviceID] = l
	}
	p.mon = pbx.NewMonitor(cfg, reg)
	prov = p
	provMu.Unlock()

	p.startPump()
	p.mon.Start()

	if lpdwTSPIOptions != nil {
		// Ask TapiSrv to serialise calls into this provider. Every entry
		// point here returns promptly, so the throughput cost is nil and it
		// removes a whole class of races.
		*lpdwTSPIOptions = C.LINETSPIOPTION_NONREENTRANT
	}

	logx.Infof("tsp: initialised, TSPI %08x, %d lines from device id %d",
		uint32(dwTSPIVersion), len(p.lines), uint32(dwLineDeviceIDBase))
	return 0
}

// TSPI_providerShutdown tears the provider down. The DLL stays loaded
// (see amitsp_pin_module), so this must leave the process able to run
// TSPI_providerInit again.
//
//export TSPI_providerShutdown
func TSPI_providerShutdown(dwTSPIVersion, dwPermanentProviderID C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_providerShutdown", &rc)
	provMu.Lock()
	p := prov
	prov = nil
	provMu.Unlock()

	if p == nil {
		return 0
	}
	// Before anything else: TapiSrv is inside this call holding the lock that
	// serialises the provider, so from here on nothing may call back into it.
	p.closing.Store(true)
	logx.Infof("tsp: shutting down")

	// Nothing below may hold TapiSrv up. It is blocked inside this call with
	// every TAPI application on the machine queued behind it, and both halves
	// of the teardown can block for their own reasons: the event pump may be
	// inside a callback waiting for the lock TapiSrv is holding right now, and
	// the monitor waits on network goroutines. This is not theoretical --
	// `amitsp-ctl lines` on its own is enough to reach it, because as the only
	// TAPI client its lineShutdown makes TapiSrv tear the provider down.
	if !runBounded(3*time.Second, func() {
		p.mon.Stop()
		p.stopPump()
	}) {
		logx.Warnf("tsp: AMI monitor and event pump did not stop within 3s, completing shutdown without them")
	}

	// Persist anything the last scan learned, so the next start enumerates
	// the same devices with the same permanent IDs.
	if err := p.reg.Save(); err != nil {
		logx.Errorf("tsp: cannot persist line registry: %v", err)
	}

	// Release every handle we ever gave TAPI.
	p.mu.Lock()
	for tok := range p.callsByToken {
		freeToken(tok)
	}
	for tok := range p.linesByToken {
		freeToken(tok)
	}
	p.callsByToken = make(map[unsafe.Pointer]*callDev)
	p.callsByKey = make(map[string]*callDev)
	p.linesByToken = make(map[unsafe.Pointer]*lineDev)
	p.linesByDeviceID = make(map[uint32]*lineDev)
	p.mu.Unlock()

	logx.Infof("tsp: shutdown complete")
	logx.Close()
	return 0
}

// TSPI_providerCreateLineDevice completes the creation of a line device that
// discovery found after the provider was initialised.
//
// TAPI calls this in response to the LINE_CREATE message we sent, and it is
// where the device gets the ID that every later TSPI_line* call will use. The
// temporary ID is the registry index the line was announced under.
//
//export TSPI_providerCreateLineDevice
func TSPI_providerCreateLineDevice(dwTempID C.DWORD_PTR, dwDeviceID C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_providerCreateLineDevice", &rc)
	p := provider()
	if p == nil {
		return lerr(C.LINEERR_UNINITIALIZED)
	}

	p.mu.Lock()
	l := p.lineByIndexLocked(int(dwTempID))
	if l == nil {
		p.mu.Unlock()
		logx.Errorf("tsp: createLineDevice for unknown temp id %d", uint64(dwTempID))
		return lerr(C.LINEERR_BADDEVICEID)
	}
	// Never move a device that already has an ID: applications have it.
	if l.created && l.deviceID != uint32(dwDeviceID) {
		id, name := l.deviceID, l.cfg.Name
		p.mu.Unlock()
		logx.Warnf("tsp: createLineDevice would move %s from device %d to %d, refusing", name, id, uint32(dwDeviceID))
		return lerr(C.LINEERR_OPERATIONFAILED)
	}
	l.deviceID = uint32(dwDeviceID)
	l.created = true
	p.linesByDeviceID[l.deviceID] = l
	name := l.cfg.Name
	p.mu.Unlock()

	logx.Infof("tsp: line device %d created for %s", uint32(dwDeviceID), name)
	return 0
}

// TSPI_providerInstall / Remove / Config are what telephon.cpl and
// lineAddProvider invoke. Configuration lives in a JSON file rather than a
// dialog, so these only need to succeed.
//
//export TSPI_providerInstall
func TSPI_providerInstall(hwndOwner C.HWND, dwPermanentProviderID C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_providerInstall", &rc)
	return 0
}

//export TSPI_providerRemove
func TSPI_providerRemove(hwndOwner C.HWND, dwPermanentProviderID C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_providerRemove", &rc)
	return 0
}

//export TSPI_providerConfig
func TSPI_providerConfig(hwndOwner C.HWND, dwPermanentProviderID C.DWORD) (rc C.LONG) {
	defer recoverEntry("TSPI_providerConfig", &rc)
	return 0
}
