package main

import (
	"testing"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/config"
)

// LINEDEVCAPS member offsets, duplicated from cmd/amitsp-ctl/caps.go. That
// command decodes the structure from a byte buffer using literals, because it
// reads bytes TAPI hands back rather than a cgo type. This test is what keeps
// the two in agreement: it fills the real structure through cgo and checks the
// literals still find the right fields.
const (
	offPermanentLineID     = 28
	offNumAddresses        = 48
	offMediaModes          = 60
	offDevCapFlags         = 112
	offMaxNumActiveCalls   = 116
	offAnswerMode          = 120
	offLineStates          = 128
	offLineFeatures        = 236
	offDeviceClassesSize   = 244
	offDeviceClassesOffset = 248
	offPermanentLineGuid   = 252
)

// Expected bit values, from tapi.h. Spelled out rather than taken from cgo so
// that a header change shows up as a failure instead of moving both sides.
const (
	wantLineFeatureMakeCall  = 0x00000008
	wantDevCapFlagsCloseDrop = 0x00000020
	wantMediaInteractive     = 0x00000004
	wantDevStateRinging      = 0x00000002
)

// tapi22DevCapsSize is the fixed size of a TAPI 2.2 LINEDEVCAPS: everything up
// to and including PermanentLineGuid.
const tapi22DevCapsSize = offPermanentLineGuid + 16

// devCapsBuffer returns a size-byte buffer aligned for LINEDEVCAPS. A plain
// []byte is not guaranteed to be, and the structure contains 4 and 8 byte
// members.
//
// The backing allocation is always large enough for the whole structure, even
// when size is deliberately short. The code under test converts the pointer to
// *LINEDEVCAPS before it consults dwTotalSize, and a conversion that overruns
// its allocation is invalid however little gets written through it -- checkptr
// fails the test under -race. TAPI itself always allocates the full structure,
// so only the short-buffer case here can produce that shape.
func devCapsBuffer(size int) []byte {
	const backing = 8192
	if size > backing {
		panic("devCapsBuffer: size exceeds the backing allocation")
	}
	words := make([]uint64, backing/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), size)
}

func u32At(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func testLine() *lineDev {
	return &lineDev{cfg: config.Line{
		Name:        "Buero 1002",
		Channel:     "PJSIP/1002",
		Extension:   "1002",
		PermanentID: 1002,
	}}
}

func TestFillLineDevCapsFieldOffsets(t *testing.T) {
	raw := devCapsBuffer(4096)
	if rc := fillLineDevCapsInto(testLine(), raw); rc != 0 {
		t.Fatalf("fillLineDevCaps = 0x%08X, want 0", uint32(rc))
	}

	// If tapi.h ever moves a field, these are the assertions that catch it
	// before `lines -v` starts printing plausible nonsense.
	if got := u32At(raw, offPermanentLineID); got != 1002 {
		t.Errorf("dwPermanentLineID at %d = %d, want 1002", offPermanentLineID, got)
	}
	if got := u32At(raw, offNumAddresses); got != 1 {
		t.Errorf("dwNumAddresses at %d = %d, want 1", offNumAddresses, got)
	}
	if got := u32At(raw, offMaxNumActiveCalls); got != maxCallsPerLine {
		t.Errorf("dwMaxNumActiveCalls at %d = %d, want %d", offMaxNumActiveCalls, got, maxCallsPerLine)
	}
	if got := u32At(raw, offLineFeatures); got != wantLineFeatureMakeCall {
		t.Errorf("dwLineFeatures at %d = 0x%08X, want 0x%08X", offLineFeatures, got, wantLineFeatureMakeCall)
	}
	if got := u32At(raw, offDevCapFlags); got != wantDevCapFlagsCloseDrop {
		t.Errorf("dwDevCapFlags at %d = 0x%08X, want 0x%08X", offDevCapFlags, got, wantDevCapFlagsCloseDrop)
	}
	// Exactly INTERACTIVEVOICE, not a superset: an application that compares
	// this field for equality is a real thing, and every call we report is
	// interactive voice anyway.
	if got := u32At(raw, offMediaModes); got != wantMediaInteractive {
		t.Errorf("dwMediaModes at %d = 0x%08X, want exactly 0x%08X",
			offMediaModes, got, wantMediaInteractive)
	}
	if got := u32At(raw, offLineStates); got&wantDevStateRinging == 0 {
		t.Errorf("dwLineStates at %d = 0x%08X, want RINGING set", offLineStates, got)
	}
}

func TestFillLineDevCapsWritesPermanentLineGuid(t *testing.T) {
	raw := devCapsBuffer(4096)
	if rc := fillLineDevCapsInto(testLine(), raw); rc != 0 {
		t.Fatalf("fillLineDevCaps = 0x%08X, want 0", uint32(rc))
	}

	guid := raw[offPermanentLineGuid : offPermanentLineGuid+16]
	var zero [16]byte
	if string(guid) == string(zero[:]) {
		t.Fatal("PermanentLineGuid is the null GUID; applications keying on it cannot tell lines apart")
	}

	// Data1..Data3 are stored little endian, so the RFC 4122 version nibble
	// lands in the high half of Data3's last byte and the variant in Data4[0].
	if v := guid[7] >> 4; v != 5 {
		t.Errorf("GUID version = %d, want 5 (name based, SHA-1)", v)
	}
	if got := guid[8] & 0xc0; got != 0x80 {
		t.Errorf("GUID variant bits = 0x%02X, want 0x80 (RFC 4122)", got)
	}
}

func TestFillLineDevCapsGuidMatchesDerivation(t *testing.T) {
	raw := devCapsBuffer(4096)
	if rc := fillLineDevCapsInto(testLine(), raw); rc != 0 {
		t.Fatalf("fillLineDevCaps = 0x%08X, want 0", uint32(rc))
	}

	// The structure stores Data1..Data3 little endian while the derivation
	// produces RFC 4122 (big endian) bytes; confirm the byte swap happened.
	u := permanentLineGUID("PJSIP/1002", 1002)
	got := raw[offPermanentLineGuid : offPermanentLineGuid+16]
	want := []byte{
		u[3], u[2], u[1], u[0],
		u[5], u[4],
		u[7], u[6],
		u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15],
	}
	if string(got) != string(want) {
		t.Errorf("PermanentLineGuid bytes = % X, want % X", got, want)
	}
}

func TestPermanentLineGUIDIsStableAndDistinct(t *testing.T) {
	a := permanentLineGUID("PJSIP/1002", 1002)
	if b := permanentLineGUID("PJSIP/1002", 1002); a != b {
		t.Error("same channel produced different GUIDs; applications would lose the line on restart")
	}
	// Case and surrounding space come from hand-edited configuration and must
	// not change a line's identity.
	if b := permanentLineGUID("  pjsip/1002 ", 1002); a != b {
		t.Error("channel normalisation failed: case or spacing changed the GUID")
	}
	// The permanent ID is only a fallback, so it must not perturb the result.
	if b := permanentLineGUID("PJSIP/1002", 7); a != b {
		t.Error("permanent ID leaked into the GUID of a channel-identified line")
	}
	if b := permanentLineGUID("PJSIP/1003", 1002); a == b {
		t.Error("different channels produced the same GUID")
	}

	// A line with no channel still needs a unique GUID.
	if x, y := permanentLineGUID("", 11), permanentLineGUID("", 12); x == y {
		t.Error("channel-less lines collided; the permanent ID fallback is not being used")
	}
}

// LINEADDRESSCAPS is a flat run of DWORDs, so cmd/amitsp-ctl/caps.go indexes
// it by member number. These are those indices, times four.
const (
	offAcLineDeviceID        = 3 * 4
	offAcAddressSharing      = 8 * 4
	offAcMaxNumActiveCalls   = 21 * 4
	offAcMaxNumOnHoldCalls   = 22 * 4
	offAcAddrCapFlags        = 26 * 4
	offAcCallFeatures        = 27 * 4
	offAcTransferModes       = 30 * 4
	offAcAddressFeatures     = 44 * 4
	offAcDeviceClassesSize   = 49 * 4
	offAcDeviceClassesOffset = 50 * 4
	offAcAvailableMedia      = 56 * 4
)

// sizeofAddressCaps is 57 DWORD members; the last one must end exactly here.
const sizeofAddressCaps = offAcAvailableMedia + 4

const (
	wantAddressSharingPrivate = 0x00000001
	wantAddrCapFlagsDialed    = 0x00000020
	wantAddrCapFlagsOrigOff   = 0x00000040
	wantAddrFeatureMakeCall   = 0x00000002
	wantTransferModeTransfer  = 0x00000001
	wantCallFeatureDrop       = 0x00000080
	wantCallFeatureBlindXfer  = 0x00000008
	wantCallFeatureHold       = 0x00000800
	wantMediaUnknown          = 0x00000002
)

func TestFillLineAddressCapsFieldOffsets(t *testing.T) {
	l := testLine()
	l.deviceID = 17

	raw := devCapsBuffer(4096)
	if rc := fillLineAddressCapsInto(l, raw); rc != 0 {
		t.Fatalf("fillLineAddressCaps = 0x%08X, want 0", uint32(rc))
	}

	if got := u32At(raw, offAcLineDeviceID); got != 17 {
		t.Errorf("dwLineDeviceID at %d = %d, want 17", offAcLineDeviceID, got)
	}
	if got := u32At(raw, offAcAddressSharing); got != wantAddressSharingPrivate {
		t.Errorf("dwAddressSharing at %d = 0x%08X, want 0x%08X", offAcAddressSharing, got, wantAddressSharingPrivate)
	}
	if got := u32At(raw, offAcMaxNumActiveCalls); got != maxCallsPerLine {
		t.Errorf("dwMaxNumActiveCalls at %d = %d, want %d", offAcMaxNumActiveCalls, got, maxCallsPerLine)
	}
	if got := u32At(raw, offAcAddrCapFlags); got != wantAddrCapFlagsDialed {
		t.Errorf("dwAddrCapFlags at %d = 0x%08X, want 0x%08X", offAcAddrCapFlags, got, wantAddrCapFlagsDialed)
	}
	if got := u32At(raw, offAcAddressFeatures); got != wantAddrFeatureMakeCall {
		t.Errorf("dwAddressFeatures at %d = 0x%08X, want 0x%08X", offAcAddressFeatures, got, wantAddrFeatureMakeCall)
	}
	if got := u32At(raw, offAcTransferModes); got != wantTransferModeTransfer {
		t.Errorf("dwTransferModes at %d = 0x%08X, want 0x%08X", offAcTransferModes, got, wantTransferModeTransfer)
	}
	if got := u32At(raw, offAcCallFeatures); got&wantCallFeatureDrop == 0 || got&wantCallFeatureBlindXfer == 0 {
		t.Errorf("dwCallFeatures at %d = 0x%08X, want DROP and BLINDTRANSFER set", offAcCallFeatures, got)
	}
	// An address that reports no media cannot carry a voice call as far as an
	// application is concerned, however good the line's own dwMediaModes look.
	if got := u32At(raw, offAcAvailableMedia); got&wantMediaInteractive == 0 || got&wantMediaUnknown == 0 {
		t.Errorf("dwAvailableMediaModes at %d = 0x%08X, want INTERACTIVEVOICE|UNKNOWN",
			offAcAvailableMedia, got)
	}
	if used := u32At(raw, 2*4); used < sizeofAddressCaps {
		t.Errorf("dwUsedSize = %d, want at least the %d byte fixed part", used, sizeofAddressCaps)
	}
}

// The capabilities that depend on configuration have to move together: a line
// that cannot answer must not claim ANSWER, and one that can must claim it
// everywhere an application looks. Discovered lines inherit
// discovery.defaults, so a "none" there disables these for every line.
func TestConfiguredModesDriveAnswerAndHold(t *testing.T) {
	const (
		wantAnswerModeNone = 0x00000001
		wantAnswerModeHold = 0x00000004
		wantCallFeatAnswer = 0x00000004
	)

	off := testLine() // answer_mode and hold_mode unset, as discovery leaves them
	raw := devCapsBuffer(4096)
	if rc := fillLineDevCapsInto(off, raw); rc != 0 {
		t.Fatalf("fillLineDevCaps = 0x%08X, want 0", uint32(rc))
	}
	if got := u32At(raw, offAnswerMode); got != wantAnswerModeNone {
		t.Errorf("dwAnswerMode = 0x%08X with hold unavailable, want NONE", got)
	}
	acRaw := devCapsBuffer(4096)
	if rc := fillLineAddressCapsInto(off, acRaw); rc != 0 {
		t.Fatalf("fillLineAddressCaps = 0x%08X, want 0", uint32(rc))
	}
	if got := u32At(acRaw, offAcCallFeatures); got&wantCallFeatAnswer != 0 {
		t.Error("ANSWER advertised with no answer_mode configured")
	}

	on := testLine()
	on.cfg.AnswerMode = "pjsip-notify"
	on.cfg.HoldMode = "pjsip-notify"
	raw = devCapsBuffer(4096)
	if rc := fillLineDevCapsInto(on, raw); rc != 0 {
		t.Fatalf("fillLineDevCaps = 0x%08X, want 0", uint32(rc))
	}
	if got := u32At(raw, offAnswerMode); got != wantAnswerModeHold {
		t.Errorf("dwAnswerMode = 0x%08X with hold available, want HOLD", got)
	}
	acRaw = devCapsBuffer(4096)
	if rc := fillLineAddressCapsInto(on, acRaw); rc != 0 {
		t.Fatalf("fillLineAddressCaps = 0x%08X, want 0", uint32(rc))
	}
	if got := u32At(acRaw, offAcCallFeatures); got&wantCallFeatAnswer == 0 {
		t.Error("ANSWER not advertised with answer_mode configured")
	}
}

func TestFillLineAddressCapsReportsDeviceClasses(t *testing.T) {
	raw := devCapsBuffer(4096)
	if rc := fillLineAddressCapsInto(testLine(), raw); rc != 0 {
		t.Fatalf("fillLineAddressCaps = 0x%08X, want 0", uint32(rc))
	}
	size := u32At(raw, offAcDeviceClassesSize)
	off := u32At(raw, offAcDeviceClassesOffset)
	if size == 0 || off == 0 {
		t.Fatal("LINEADDRESSCAPS reports no device classes")
	}
	if got := decodeMultiSz(raw, off, size); len(got) != 2 ||
		got[0] != "tapi/line" || got[1] != "tapi/providerid" {
		t.Errorf("address device classes = %q, want [tapi/line tapi/providerid]", got)
	}
}

func TestFillLineDevCapsReportsProviderIDClass(t *testing.T) {
	raw := devCapsBuffer(4096)
	if rc := fillLineDevCapsInto(testLine(), raw); rc != 0 {
		t.Fatalf("fillLineDevCaps = 0x%08X, want 0", uint32(rc))
	}
	got := decodeMultiSz(raw, u32At(raw, offDeviceClassesOffset), u32At(raw, offDeviceClassesSize))
	if len(got) != 2 || got[0] != "tapi/line" || got[1] != "tapi/providerid" {
		t.Errorf("line device classes = %q, want [tapi/line tapi/providerid]", got)
	}
}

// Hold and answer are advertised only when the configuration provides a
// mechanism, and the fields that describe them have to agree.
func TestFillLineAddressCapsHoldAndAnswerAreConsistent(t *testing.T) {
	off := testLine() // answer_mode and hold_mode unset
	raw := devCapsBuffer(4096)
	if rc := fillLineAddressCapsInto(off, raw); rc != 0 {
		t.Fatalf("fillLineAddressCaps = 0x%08X, want 0", uint32(rc))
	}
	if got := u32At(raw, offAcCallFeatures); got&wantCallFeatureHold != 0 {
		t.Error("HOLD advertised with no hold_mode configured")
	}
	if got := u32At(raw, offAcMaxNumOnHoldCalls); got != 0 {
		t.Errorf("dwMaxNumOnHoldCalls = %d with hold unavailable, want 0", got)
	}
	if got := u32At(raw, offAcAddrCapFlags); got&wantAddrCapFlagsOrigOff != 0 {
		t.Error("ORIGOFFHOOK advertised with no answer_mode configured")
	}

	on := testLine()
	on.cfg.HoldMode = "pjsip-notify"
	on.cfg.AnswerMode = "pjsip-notify"
	raw = devCapsBuffer(4096)
	if rc := fillLineAddressCapsInto(on, raw); rc != 0 {
		t.Fatalf("fillLineAddressCaps = 0x%08X, want 0", uint32(rc))
	}
	if got := u32At(raw, offAcCallFeatures); got&wantCallFeatureHold == 0 {
		t.Error("HOLD not advertised with hold_mode configured")
	}
	if got := u32At(raw, offAcMaxNumOnHoldCalls); got == 0 {
		t.Error("HOLD advertised but dwMaxNumOnHoldCalls is 0; applications will not offer hold")
	}
	if got := u32At(raw, offAcAddrCapFlags); got&wantAddrCapFlagsOrigOff == 0 {
		t.Error("ORIGOFFHOOK not advertised with answer_mode configured")
	}
}

// decodeMultiSz mirrors cmd/amitsp-ctl's decoder for the NUL separated,
// double NUL terminated lists TAPI uses for device classes.
func decodeMultiSz(b []byte, off, size uint32) []string {
	if size == 0 || int(off)+int(size) > len(b) {
		return nil
	}
	var out []string
	var cur []rune
	for i := uint32(0); i+1 < size; i += 2 {
		c := uint16(b[off+i]) | uint16(b[off+i+1])<<8
		if c == 0 {
			if len(cur) == 0 {
				break
			}
			out = append(out, string(cur))
			cur = nil
			continue
		}
		cur = append(cur, rune(c))
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func TestFillLineDevCapsRejectsShortBuffer(t *testing.T) {
	// One byte short of the TAPI 2.2 fixed part: writing the GUID here would
	// run past the caller's buffer.
	raw := devCapsBuffer(tapi22DevCapsSize - 1)
	if rc := fillLineDevCapsInto(testLine(), raw); rc == 0 {
		t.Fatal("fillLineDevCaps accepted a buffer too small to hold PermanentLineGuid")
	}
}
