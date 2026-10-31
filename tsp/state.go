// Command amitsp is a Windows TAPI 2.x Telephony Service Provider that
// proxies TAPI line devices onto Asterisk's Manager Interface (AMI).
//
// It is built as a c-shared DLL and loaded by TapiSrv, so there is no main
// entry point in the usual sense; every entry point is an exported TSPI_*
// function.
//
// Threading model
//
//	TapiSrv  --TSPI_* --> (this DLL)      serialised: we ask for
//	                                      LINETSPIOPTION_NONREENTRANT
//	pump goroutine --LINEEVENT--> TapiSrv  asynchronous, never under lock
//
// Every TSPI entry point returns promptly: anything that needs to talk to
// the PBX is queued to a goroutine which later calls the completion proc.
package main

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -static-libgcc
#include "shim.h"
#include <stdlib.h>
*/
import "C"

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/lines"
	"github.com/adee42/ami-tsp/internal/logx"
	"github.com/adee42/ami-tsp/internal/pbx"
)

// providerVersionLow/High bound the TSPI versions we implement.
const (
	tspiVersionLow  = 0x00020000
	tspiVersionHigh = 0x00020002
)

// maxCallsPerLine caps concurrent TAPI calls per line device. Asterisk
// devices can hold more, but TAPI applications want a fixed number in
// LINEDEVCAPS. It is tapi.max_calls_per_line, set once in TSPI_providerInit
// before any device is described; the default is plenty for a desk phone.
var maxCallsPerLine uint32 = 4

// lineDev is one TAPI line device, backed by one Asterisk device.
type lineDev struct {
	index int // index into the line registry
	cfg   config.Line

	// deviceID is the TAPI device ID. For lines present at provider
	// initialisation it is lineDeviceIDBase+index; for lines discovered later
	// TAPI assigns it in TSPI_providerCreateLineDevice, and until then the
	// line has no ID and created is false.
	deviceID uint32
	created  bool

	// present is false once discovery reports the underlying device gone from
	// the PBX. The device keeps its slot either way — TAPI 2.x has no way for
	// a provider to withdraw one — but it stops claiming to be in service.
	present bool

	// TAPI-facing state, valid between lineOpen and lineClose.
	open      bool
	token     unsafe.Pointer // the HDRVLINE we handed TAPI
	htLine    C.HTAPILINE
	eventProc C.LINEEVENT

	mediaModes    uint32
	lineStates    uint32
	addressStates uint32
}

// callDev is one TAPI call. Its lifetime is from lineMakeCall / LINE_NEWCALL
// until TSPI_lineCloseCall.
type callDev struct {
	token unsafe.Pointer // the HDRVCALL we handed TAPI

	// htCall is the application-side handle. For outbound calls TAPI passes
	// it to TSPI_lineMakeCall; for inbound calls we get it back from
	// LINE_NEWCALL.
	htCall C.HTAPICALL

	line *lineDev

	// key correlates with pbx.Snapshot.Key (the Asterisk Uniqueid, or for a
	// call we originated, the tag we preset as the ChannelId).
	key string

	state       uint32 // LINECALLSTATE_*
	stateMode   uint32
	inbound     bool
	remoteNum   string
	remoteName  string
	localNum    string
	appSpecific uint32

	created   time.Time
	connected time.Time

	// bound is set once the PBX has reported a channel for this call.
	bound bool
	// ended is set after LINECALLSTATE_IDLE; the object lives on until TAPI
	// calls TSPI_lineCloseCall.
	ended bool

	// awaiting is set while the TSPI_lineMakeCall that created this call has
	// not been completed. TSPI forbids call messages before that completion,
	// and the PBX's events can easily overtake the Originate response, so
	// they are held in deferred and sent, in order, once it has.
	awaiting bool
	deferred []lineMsg
}

// lineMsg is one LINEEVENT message, as held for a call that is awaiting its
// lineMakeCall completion.
type lineMsg struct {
	msg        C.DWORD
	p1, p2, p3 C.DWORD_PTR
}

// providerState is the whole provider. Guarded by mu; see the note in the
// package comment about never calling into TAPI while holding it.
type providerState struct {
	mu sync.Mutex

	cfg *config.Config
	reg *lines.Registry
	mon *pbx.Monitor

	tspiVersion      uint32
	permProviderID   uint32
	lineDeviceIDBase uint32
	completion       C.ASYNC_COMPLETION

	// lines is indexed by registry index and only ever grows, mirroring the
	// registry itself.
	lines []*lineDev

	// linesByDeviceID is the authority for TAPI device ID lookups. Device IDs
	// for runtime-created lines are assigned by TAPI and are not required to
	// continue the initial contiguous range, so they cannot be derived from
	// lineDeviceIDBase.
	linesByDeviceID map[uint32]*lineDev

	linesByToken map[unsafe.Pointer]*lineDev
	callsByToken map[unsafe.Pointer]*callDev
	callsByKey   map[string]*callDev

	linkUp bool

	// closing is set the moment TapiSrv asks us to shut down, before anything
	// else happens. Once it is set, nothing may call into TAPI again: TAPI is
	// inside TSPI_providerShutdown and, having been asked for
	// LINETSPIOPTION_NONREENTRANT, is holding the lock our callbacks need.
	closing atomic.Bool

	// tasks carries work that must run on the event pump goroutine, so that
	// it is ordered with the call messages the pump sends; see post.
	tasks chan func()

	stop chan struct{}
	wg   sync.WaitGroup
}

// recoverEntry keeps a panic in a TSPI entry point from unwinding into
// TapiSrv, which would end svchost and telephony for every application on the
// machine. It must be deferred directly by the entry point.
func recoverEntry(name string, rc *C.LONG) {
	if r := recover(); r != nil {
		logx.Errorf("tsp: panic in %s: %v\n%s", name, r, debug.Stack())
		*rc = lerr(C.LINEERR_OPERATIONFAILED)
	}
}

// callbacksAllowed reports whether it is still safe to call into TAPI.
func (p *providerState) callbacksAllowed() bool { return !p.closing.Load() }

var (
	// provMu guards the provider pointer itself, so that entry points
	// arriving during init/shutdown see a consistent value.
	provMu sync.RWMutex
	prov   *providerState

	// enumCfg and enumReg are built by TSPI_providerEnumDevices, which TapiSrv
	// calls before TSPI_providerInit, and consumed by the latter.
	enumMu  sync.Mutex
	enumCfg *config.Config
	enumReg *lines.Registry
	enumErr error

	// createProc and provHandle are handed to us by TSPI_providerEnumDevices
	// and are how a line device discovered later is announced to TAPI. They
	// stay valid for the lifetime of the provider.
	createMu   sync.Mutex
	createProc C.LINEEVENT
	provHandle C.HPROVIDER
)

// lineCreateCallback returns the runtime device-creation callback.
func lineCreateCallback() (C.LINEEVENT, C.HPROVIDER) {
	createMu.Lock()
	defer createMu.Unlock()
	return createProc, provHandle
}

func provider() *providerState {
	provMu.RLock()
	defer provMu.RUnlock()
	return prov
}

// lerr converts a LINEERR_* constant (which is an unsigned value with the
// high bit set) into the signed LONG that TSPI functions return.
func lerr(v uint32) C.LONG { return C.LONG(int32(v)) }

// newToken allocates an opaque handle to give TAPI. C memory is used rather
// than a Go pointer or a fabricated integer so that the value is a valid,
// stable, unique pointer that the Go garbage collector never inspects. It is
// only ever used as a map key; it is never dereferenced.
func newToken() unsafe.Pointer { return C.malloc(1) }

func freeToken(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}

// ---- handle lookup ---------------------------------------------------

func (p *providerState) lineByToken(h C.HDRVLINE) *lineDev {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.linesByToken[unsafe.Pointer(h)]
}

func (p *providerState) callByToken(h C.HDRVCALL) *callDev {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.callsByToken[unsafe.Pointer(h)]
}

// lineByDeviceID maps a TAPI device ID to a line device.
func (p *providerState) lineByDeviceID(id C.DWORD) *lineDev {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.linesByDeviceID[uint32(id)]
}

// lineByIndexLocked returns the line device at a registry index. Caller holds
// mu.
func (p *providerState) lineByIndexLocked(i int) *lineDev {
	if i < 0 || i >= len(p.lines) {
		return nil
	}
	return p.lines[i]
}

// addLineLocked appends a line device for a registry index, or returns the
// existing one. Caller holds mu.
func (p *providerState) addLineLocked(i int, cfg config.Line) *lineDev {
	if l := p.lineByIndexLocked(i); l != nil {
		return l
	}
	// The registry is append-only, so an index arriving out of order would
	// mean the two lists had diverged; refuse rather than mis-map a device.
	if i != len(p.lines) {
		logx.Errorf("tsp: line index %d out of sequence (have %d), ignoring", i, len(p.lines))
		return nil
	}
	l := &lineDev{index: i, cfg: cfg, present: true}
	p.lines = append(p.lines, l)
	return l
}

// inServiceLocked reports whether a line should be advertised as in service.
// Caller holds mu.
func (p *providerState) inServiceLocked(l *lineDev) bool {
	return p.linkUp && l.present
}

// activeCalls counts calls on a line that are not yet idle. Caller holds mu.
func (p *providerState) activeCallsLocked(l *lineDev) uint32 {
	var n uint32
	for _, c := range p.callsByToken {
		if c.line == l && !c.ended {
			n++
		}
	}
	return n
}

// loadConfig reads the configuration, sets up logging and builds the line
// registry. It is called from TSPI_providerEnumDevices, the first entry point
// TapiSrv invokes.
func loadConfig() (*config.Config, *lines.Registry, error) {
	enumMu.Lock()
	defer enumMu.Unlock()

	path := config.Path()
	cfg, err := config.Load(path)
	if err != nil {
		// Logging is not configured yet, so fall back to the default
		// location to make the failure visible at all.
		logx.Configure(config.DataDir()+`\ami-tsp.log`, logx.LevelInfo)
		logx.Errorf("config: %v", err)
		enumCfg, enumReg, enumErr = nil, nil, err
		return nil, nil, err
	}
	logx.Configure(cfg.Log.File, logx.ParseLevel(cfg.Log.Level))

	reg, err := pbx.BuildRegistry(cfg, true)
	if err != nil {
		logx.Errorf("config: %v", err)
		enumCfg, enumReg, enumErr = nil, nil, err
		return nil, nil, err
	}
	logx.Infof("config: loaded %s (%d configured line(s), %d device(s) known, discovery %s, ami %s:%d)",
		path, len(cfg.Lines), reg.Len(),
		map[bool]string{true: "on", false: "off"}[cfg.Discovery.IsEnabled()],
		cfg.AMI.Host, cfg.AMI.Port)

	enumCfg, enumReg, enumErr = cfg, reg, nil
	return cfg, reg, nil
}

func cachedConfig() (*config.Config, *lines.Registry, error) {
	enumMu.Lock()
	c, r, err := enumCfg, enumReg, enumErr
	enumMu.Unlock()
	if c != nil || err != nil {
		return c, r, err
	}
	return loadConfig()
}

func main() {}
