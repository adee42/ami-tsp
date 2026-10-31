package main

import "testing"

// The flag tables are transcribed from tapi.h by hand, and a single omitted
// constant silently shifts every name above it onto the wrong bit -- which
// produces a dump that looks entirely plausible and is wrong. These tests pin
// the shape of every table and the boundaries that have gone wrong before.

func checkFlagTable(t *testing.T, name string, tbl map[uint32]string) {
	t.Helper()
	seen := map[string]uint32{}
	for bit, n := range tbl {
		if bit == 0 || bit&(bit-1) != 0 {
			t.Errorf("%s: 0x%X (%s) is not a single bit", name, bit, n)
		}
		if prev, dup := seen[n]; dup {
			t.Errorf("%s: name %q used for both 0x%X and 0x%X", name, n, prev, bit)
		}
		seen[n] = bit
	}
}

func TestFlagTablesAreWellFormed(t *testing.T) {
	for name, tbl := range map[string]map[uint32]string{
		"addressModeFlags":    addressModeFlags,
		"bearerModeFlags":     bearerModeFlags,
		"mediaModeFlags":      mediaModeFlags,
		"devCapFlagFlags":     devCapFlagFlags,
		"lineFeatureFlags":    lineFeatureFlags,
		"devStateFlags":       devStateFlags,
		"addressSharingFlags": addressSharingFlags,
		"addrCapFlagFlags":    addrCapFlagFlags,
		"addrFeatureFlags":    addrFeatureFlags,
		"callFeatureFlags":    callFeatureFlags,
		"callFeature2Flags":   callFeature2Flags,
		"callStateFlags":      callStateFlags,
		"transferModeFlags":   transferModeFlags,
		"forwardModeFlags":    forwardModeFlags,
	} {
		checkFlagTable(t, name, tbl)
	}
}

// TestFlagTablesAreContiguous catches the omitted-constant bug directly: TAPI
// allocates these bitmasks from bit 0 upwards with no gaps, so a table missing
// an entry shows up as a hole.
func TestFlagTablesAreContiguous(t *testing.T) {
	for name, tc := range map[string]struct {
		tbl   map[uint32]string
		first uint32
	}{
		"addrCapFlagFlags":  {addrCapFlagFlags, 0x1},
		"callFeatureFlags":  {callFeatureFlags, 0x1},
		"callFeature2Flags": {callFeature2Flags, 0x1},
		"devStateFlags":     {devStateFlags, 0x1},
		"lineFeatureFlags":  {lineFeatureFlags, 0x1},
		"addrFeatureFlags":  {addrFeatureFlags, 0x1},
		"callStateFlags":    {callStateFlags, 0x1},
		"devCapFlagFlags":   {devCapFlagFlags, 0x1},
		"mediaModeFlags":    {mediaModeFlags, 0x2},
		"forwardModeFlags":  {forwardModeFlags, 0x1},
	} {
		bit := tc.first
		for i := 0; i < len(tc.tbl); i++ {
			if _, ok := tc.tbl[bit]; !ok {
				t.Errorf("%s: no entry for 0x%X; every bit above it is shifted onto the wrong name", name, bit)
				break
			}
			bit <<= 1
		}
	}
}

// Anchors taken from tapi.h. These are the exact boundaries that were wrong.
func TestFlagTableAnchors(t *testing.T) {
	for _, tc := range []struct {
		table map[uint32]string
		bit   uint32
		want  string
	}{
		{callFeatureFlags, 0x00040000, "REMOVEFROMCONF"},
		{callFeatureFlags, 0x00080000, "SECURECALL"},
		{callFeatureFlags, 0x08000000, "UNHOLD"},
		{callFeatureFlags, 0x10000000, "RELEASEUSERUSERINFO"},
		{callFeatureFlags, 0x80000000, "SETCALLDATA"},
		{addrCapFlagFlags, 0x00000040, "ORIGOFFHOOK"},
		{addrCapFlagFlags, 0x00004000, "CONFERENCEHELD"},
		{addrCapFlagFlags, 0x00008000, "CONFERENCEMAKE"},
		{addrCapFlagFlags, 0x00400000, "PICKUPCALLWAIT"},
		{addrCapFlagFlags, 0x00800000, "PREDICTIVEDIALER"},
		{devCapFlagFlags, 0x00000400, "CALLHUB"},
		{devCapFlagFlags, 0x00000800, "CALLHUBTRACKING"},
		{lineFeatureFlags, 0x00000008, "MAKECALL"},
	} {
		if got := tc.table[tc.bit]; got != tc.want {
			t.Errorf("bit 0x%08X = %q, want %q", tc.bit, got, tc.want)
		}
	}
}

// TestFlagStringDecodesReference decodes the values from a working third-party
// TSP, which is the reference this provider's capabilities were compared
// against.
func TestFlagStringDecodesReference(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table map[uint32]string
		v     uint32
		want  string
	}{
		{
			"dwCallFeatures", callFeatureFlags, 0x8F270AEE,
			"0x8F270AEE  ADDTOCONF|ANSWER|BLINDTRANSFER|COMPLETETRANSF|DIAL|DROP|" +
				"GENERATEDIGITS|HOLD|PREPAREADDCONF|REDIRECT|REMOVEFROMCONF|" +
				"SETCALLPARAMS|SETUPCONF|SETUPTRANSFER|SWAPHOLD|UNHOLD|SETCALLDATA",
		},
		{
			"dwAddrCapFlags", addrCapFlagFlags, 0x00463460,
			"0x00463460  DIALED|ORIGOFFHOOK|AUTORECONNECT|TRANSFERHELD|TRANSFERMAKE|" +
				"FWDSTATUSVALID|FWDINTEXTADDR|PICKUPCALLWAIT",
		},
		{
			"dwDevCapFlags", devCapFlagFlags, 0x00000C00,
			"0x00000C00  CALLHUB|CALLHUBTRACKING",
		},
		{
			"dwCallFeatures2", callFeature2Flags, 0x000000C2,
			"0x000000C2  ONESTEPTRANSFER|TRANSFERNORM|TRANSFERCONF",
		},
	} {
		if got := flagString(tc.v, tc.table); got != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.name, got, tc.want)
		}
	}
}

func TestFlagStringReportsUnknownBits(t *testing.T) {
	got := flagString(0x00000021, devCapFlagFlags) // CLOSEDROP + an unnamed bit 0x1? no, 0x1 is named
	if want := "0x00000021  CROSSADDRCONF|CLOSEDROP"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// A bit no table knows about must still be visible.
	if got := flagString(0x00010000, transferModeFlags); got != "0x00010000  0x10000?" {
		t.Errorf("unknown bit not surfaced: %q", got)
	}
}

func TestMultiSzAt(t *testing.T) {
	// "tapi/line\0tapi/providerid\0\0" as UTF-16LE.
	var raw []byte
	for _, s := range []string{"tapi/line", "tapi/providerid"} {
		for _, r := range s {
			raw = append(raw, byte(r), 0)
		}
		raw = append(raw, 0, 0)
	}
	raw = append(raw, 0, 0)

	got := multiSzAt(raw, 0, uint32(len(raw)))
	if len(got) != 2 || got[0] != "tapi/line" || got[1] != "tapi/providerid" {
		t.Errorf("multiSzAt = %q, want [tapi/line tapi/providerid]", got)
	}
}

func TestGuidAt(t *testing.T) {
	// {BC835BFF-9320-40F1-896C-2DCA31E020F1} as Windows stores it.
	raw := []byte{
		0xFF, 0x5B, 0x83, 0xBC,
		0x20, 0x93,
		0xF1, 0x40,
		0x89, 0x6C, 0x2D, 0xCA, 0x31, 0xE0, 0x20, 0xF1,
	}
	if got, want := guidAt(raw, 0), "{BC835BFF-9320-40F1-896C-2DCA31E020F1}"; got != want {
		t.Errorf("guidAt = %s, want %s", got, want)
	}
}
