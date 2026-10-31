package main

// Decoding for the two structures an application reads while deciding which
// line devices to offer its user: LINEDEVCAPS and LINEADDRESSCAPS. When an
// application "does not see" the lines, the answer is almost always a bit it
// wanted in one of these, so `lines -v` prints them in full.
//
// The field offsets are the ones tapi.h produces for a TAPI 2.2 structure on
// a 64-bit build; every member is a DWORD except the embedded LINEDIALPARAMS
// blocks (4 DWORDs each) and PermanentLineGuid (a 16 byte GUID), which is why
// the LINEDEVCAPS offsets are listed literally instead of computed.

import (
	"fmt"
	"sort"
	"strings"
)

// LINEDEVCAPS member offsets, in bytes.
const (
	dcProviderInfoSize    = 12
	dcProviderInfoOffset  = 16
	dcSwitchInfoSize      = 20
	dcSwitchInfoOffset    = 24
	dcPermanentLineID     = 28
	dcLineNameSize        = 32
	dcLineNameOffset      = 36
	dcStringFormat        = 40
	dcAddressModes        = 44
	dcNumAddresses        = 48
	dcBearerModes         = 52
	dcMaxRate             = 56
	dcMediaModes          = 60
	dcDevCapFlags         = 112
	dcMaxNumActiveCalls   = 116
	dcAnswerMode          = 120
	dcRingModes           = 124
	dcLineStates          = 128
	dcNumTerminals        = 204
	dcDevSpecificSize     = 228
	dcLineFeatures        = 236
	dcSettableDevStatus   = 240
	dcDeviceClassesSize   = 244
	dcDeviceClassesOffset = 248
	dcPermanentLineGuid   = 252
)

// LINEADDRESSCAPS is a flat run of DWORDs, so its members are addressed by
// index rather than by a table of literals.
const (
	acLineDeviceID = 3 + iota
	acAddressSize
	acAddressOffset
	acDevSpecificSize
	acDevSpecificOffset
	acAddressSharing
	acAddressStates
	acCallInfoStates
	acCallerIDFlags
	acCalledIDFlags
	acConnectedIDFlags
	acRedirectionIDFlags
	acRedirectingIDFlags
	acCallStates
	acDialToneModes
	acBusyModes
	acSpecialInfo
	acDisconnectModes
	acMaxNumActiveCalls
	acMaxNumOnHoldCalls
	acMaxNumOnHoldPendingCalls
	acMaxNumConference
	acMaxNumTransConf
	acAddrCapFlags
	acCallFeatures
	acRemoveFromConfCaps
	acRemoveFromConfState
	acTransferModes
	acParkModes
	acForwardModes
	acMaxForwardEntries
	acMaxSpecificEntries
	acMinFwdNumRings
	acMaxFwdNumRings
	acMaxCallCompletions
	acCallCompletionConds
	acCallCompletionModes
	acNumCompletionMessages
	acCompletionMsgTextEntrySize
	acCompletionMsgTextSize
	acCompletionMsgTextOffset
	acAddressFeatures
	acPredictiveAutoTransferStates
	acNumCallTreatments
	acCallTreatmentListSize
	acCallTreatmentListOffset
	acDeviceClassesSize
	acDeviceClassesOffset
	acMaxCallDataSize
	acCallFeatures2
	acMaxNoAnswerTimeout
	acConnectedModes
	acOfferingModes
	acAvailableMediaModes
)

// ---------------------------------------------------------- constant tables

var stringFormats = map[uint32]string{
	1: "ASCII", 2: "DBCS", 3: "UNICODE", 4: "BINARY",
}

var addressModeFlags = map[uint32]string{
	0x1: "ADDRESSID", 0x2: "DIALABLEADDR",
}

var answerModes = map[uint32]string{
	0x1: "NONE", 0x2: "DROP", 0x4: "HOLD",
}

var bearerModeFlags = map[uint32]string{
	0x1: "VOICE", 0x2: "SPEECH", 0x4: "MULTIUSE", 0x8: "DATA",
	0x10: "ALTSPEECHDATA", 0x20: "NONCALLSIGNALING", 0x40: "PASSTHROUGH",
	0x80: "RESTRICTEDDATA",
}

var mediaModeFlags = map[uint32]string{
	0x2: "UNKNOWN", 0x4: "INTERACTIVEVOICE", 0x8: "AUTOMATEDVOICE",
	0x10: "DATAMODEM", 0x20: "G3FAX", 0x40: "TDD", 0x80: "G4FAX",
	0x100: "DIGITALDATA", 0x200: "TELETEX", 0x400: "VIDEOTEX", 0x800: "TELEX",
	0x1000: "MIXED", 0x2000: "ADSI", 0x4000: "VOICEVIEW", 0x8000: "VIDEO",
}

var devCapFlagFlags = map[uint32]string{
	0x1: "CROSSADDRCONF", 0x2: "HIGHLEVCOMP", 0x4: "LOWLEVCOMP",
	0x8: "MEDIACONTROL", 0x10: "MULTIPLEADDR", 0x20: "CLOSEDROP",
	0x40: "DIALBILLING", 0x80: "DIALQUIET", 0x100: "DIALDIALTONE",
	0x200: "MSP", 0x400: "CALLHUB", 0x800: "CALLHUBTRACKING",
	0x1000: "PRIVATEOBJECTS", 0x2000: "LOCAL",
}

var lineFeatureFlags = map[uint32]string{
	0x1: "DEVSPECIFIC", 0x2: "DEVSPECIFICFEAT", 0x4: "FORWARD",
	0x8: "MAKECALL", 0x10: "SETMEDIACONTROL", 0x20: "SETTERMINAL",
	0x40: "SETDEVSTATUS", 0x80: "FORWARDFWD", 0x100: "FORWARDDND",
}

var devStateFlags = map[uint32]string{
	0x1: "OTHER", 0x2: "RINGING", 0x4: "CONNECTED", 0x8: "DISCONNECTED",
	0x10: "MSGWAITON", 0x20: "MSGWAITOFF", 0x40: "INSERVICE",
	0x80: "OUTOFSERVICE", 0x100: "MAINTENANCE", 0x200: "OPEN", 0x400: "CLOSE",
	0x800: "NUMCALLS", 0x1000: "NUMCOMPLETIONS", 0x2000: "TERMINALS",
	0x4000: "ROAMMODE", 0x8000: "BATTERY", 0x10000: "SIGNAL",
	0x20000: "DEVSPECIFIC", 0x40000: "REINIT", 0x80000: "LOCK",
	0x100000: "CAPSCHANGE", 0x200000: "CONFIGCHANGE",
	0x400000: "TRANSLATECHANGE", 0x800000: "COMPLCANCEL", 0x1000000: "REMOVED",
}

var addressSharingFlags = map[uint32]string{
	0x1: "PRIVATE", 0x2: "BRIDGEDEXCL", 0x4: "BRIDGEDNEW",
	0x8: "BRIDGEDSHARED", 0x10: "MONITORED",
}

var addrCapFlagFlags = map[uint32]string{
	0x1: "FWDNUMRINGS", 0x2: "PICKUPGROUPID", 0x4: "SECURE",
	0x8: "BLOCKIDDEFAULT", 0x10: "BLOCKIDOVERRIDE", 0x20: "DIALED",
	0x40: "ORIGOFFHOOK", 0x80: "DESTOFFHOOK", 0x100: "FWDCONSULT",
	0x200: "SETUPCONFNULL", 0x400: "AUTORECONNECT", 0x800: "COMPLETIONID",
	0x1000: "TRANSFERHELD", 0x2000: "TRANSFERMAKE", 0x4000: "CONFERENCEHELD",
	0x8000: "CONFERENCEMAKE", 0x10000: "PARTIALDIAL",
	0x20000: "FWDSTATUSVALID", 0x40000: "FWDINTEXTADDR",
	0x80000: "FWDBUSYNAADDR", 0x100000: "ACCEPTTOALERT", 0x200000: "CONFDROP",
	0x400000: "PICKUPCALLWAIT", 0x800000: "PREDICTIVEDIALER",
	0x1000000: "QUEUE", 0x2000000: "ROUTEPOINT", 0x4000000: "HOLDMAKESNEW",
	0x8000000: "NOINTERNALCALLS", 0x10000000: "NOEXTERNALCALLS",
	0x20000000: "SETCALLINGID", 0x40000000: "ACDGROUP",
	0x80000000: "NOPSTNADDRESSTRANSLATION",
}

var addrFeatureFlags = map[uint32]string{
	0x1: "FORWARD", 0x2: "MAKECALL", 0x4: "PICKUP", 0x8: "SETMEDIACONTROL",
	0x10: "SETTERMINAL", 0x20: "SETUPCONF", 0x40: "UNCOMPLETECALL",
	0x80: "UNPARK", 0x100: "PICKUPHELD", 0x200: "PICKUPGROUP",
	0x400: "PICKUPDIRECT", 0x800: "PICKUPWAITING", 0x1000: "FORWARDFWD",
	0x2000: "FORWARDDND",
}

var callFeatureFlags = map[uint32]string{
	0x1: "ACCEPT", 0x2: "ADDTOCONF", 0x4: "ANSWER", 0x8: "BLINDTRANSFER",
	0x10: "COMPLETECALL", 0x20: "COMPLETETRANSF", 0x40: "DIAL", 0x80: "DROP",
	0x100: "GATHERDIGITS", 0x200: "GENERATEDIGITS", 0x400: "GENERATETONE",
	0x800: "HOLD", 0x1000: "MONITORDIGITS", 0x2000: "MONITORMEDIA",
	0x4000: "MONITORTONES", 0x8000: "PARK", 0x10000: "PREPAREADDCONF",
	0x20000: "REDIRECT", 0x40000: "REMOVEFROMCONF", 0x80000: "SECURECALL",
	0x100000: "SENDUSERUSER", 0x200000: "SETCALLPARAMS",
	0x400000: "SETMEDIACONTROL", 0x800000: "SETTERMINAL",
	0x1000000: "SETUPCONF", 0x2000000: "SETUPTRANSFER", 0x4000000: "SWAPHOLD",
	0x8000000: "UNHOLD", 0x10000000: "RELEASEUSERUSERINFO",
	0x20000000: "SETTREATMENT", 0x40000000: "SETQOS", 0x80000000: "SETCALLDATA",
}

var callFeature2Flags = map[uint32]string{
	0x1: "NOHOLDCONFERENCE", 0x2: "ONESTEPTRANSFER", 0x4: "COMPLCAMPON",
	0x8: "COMPLCALLBACK", 0x10: "COMPLINTRUDE", 0x20: "COMPLMESSAGE",
	0x40: "TRANSFERNORM", 0x80: "TRANSFERCONF", 0x100: "PARKDIRECT",
	0x200: "PARKNONDIRECT",
}

var forwardModeFlags = map[uint32]string{
	0x1: "UNCOND", 0x2: "UNCONDINTERNAL", 0x4: "UNCONDEXTERNAL",
	0x8: "UNCONDSPECIFIC", 0x10: "BUSY", 0x20: "BUSYINTERNAL",
	0x40: "BUSYEXTERNAL", 0x80: "BUSYSPECIFIC", 0x100: "NOANSW",
	0x200: "NOANSWINTERNAL", 0x400: "NOANSWEXTERNAL", 0x800: "NOANSWSPECIFIC",
	0x1000: "BUSYNA", 0x2000: "BUSYNAINTERNAL", 0x4000: "BUSYNAEXTERNAL",
	0x8000: "BUSYNASPECIFIC", 0x10000: "UNKNOWN", 0x20000: "UNAVAIL",
}

var callStateFlags = map[uint32]string{
	0x1: "IDLE", 0x2: "OFFERING", 0x4: "ACCEPTED", 0x8: "DIALTONE",
	0x10: "DIALING", 0x20: "RINGBACK", 0x40: "BUSY", 0x80: "SPECIALINFO",
	0x100: "CONNECTED", 0x200: "PROCEEDING", 0x400: "ONHOLD",
	0x800: "CONFERENCED", 0x1000: "ONHOLDPENDCONF",
	0x2000: "ONHOLDPENDTRANSFER", 0x4000: "DISCONNECTED", 0x8000: "UNKNOWN",
}

var transferModeFlags = map[uint32]string{
	0x1: "TRANSFER", 0x2: "CONFERENCE",
}

// ------------------------------------------------------------------ helpers

// flagString renders a bitmask as its hex value followed by the names of the
// bits that are set. Bits with no name are reported as "0x..?" so a value the
// table does not know about is still visible rather than silently dropped.
func flagString(v uint32, names map[uint32]string) string {
	if v == 0 {
		return "0x00000000"
	}
	var bits []uint32
	for bit := range names {
		if v&bit != 0 {
			bits = append(bits, bit)
		}
	}
	sort.Slice(bits, func(i, j int) bool { return bits[i] < bits[j] })

	var parts []string
	rest := v
	for _, bit := range bits {
		parts = append(parts, names[bit])
		rest &^= bit
	}
	if rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%X?", rest))
	}
	return fmt.Sprintf("0x%08X  %s", v, strings.Join(parts, "|"))
}

// enumString renders a value that names one choice rather than a set of bits.
func enumString(v uint32, names map[uint32]string) string {
	if n, ok := names[v]; ok {
		return fmt.Sprintf("0x%08X  %s", v, n)
	}
	return fmt.Sprintf("0x%08X", v)
}

// guidAt renders the GUID at off in the usual braced form. Data1..Data3 are
// stored little endian, Data4 is a byte string.
func guidAt(b []byte, off uint32) string {
	if int(off)+16 > len(b) {
		return "(absent)"
	}
	d1 := getU32(b, off)
	d2 := uint16(b[off+4]) | uint16(b[off+5])<<8
	d3 := uint16(b[off+6]) | uint16(b[off+7])<<8
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		d1, d2, d3, b[off+8], b[off+9],
		b[off+10], b[off+11], b[off+12], b[off+13], b[off+14], b[off+15])
}

// multiSzAt decodes the NUL separated, double NUL terminated list TAPI uses
// for device class lists.
func multiSzAt(b []byte, off, size uint32) []string {
	if size == 0 || int(off)+int(size) > len(b) {
		return nil
	}
	var out []string
	var cur []uint16
	for i := uint32(0); i+1 < size; i += 2 {
		c := uint16(b[off+i]) | uint16(b[off+i+1])<<8
		if c == 0 {
			if len(cur) == 0 {
				break // the list terminator
			}
			out = append(out, string(utf16Runes(cur)))
			cur = nil
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(utf16Runes(cur)))
	}
	return out
}

func utf16Runes(u []uint16) []rune {
	r := make([]rune, 0, len(u))
	for _, c := range u {
		r = append(r, rune(c))
	}
	return r
}

func row(name, value string) {
	fmt.Printf("    %-30s %s\n", name, value)
}

// dword reads member i of an all-DWORD structure.
func dword(b []byte, i uint32) uint32 { return getU32(b, i*4) }

// -------------------------------------------------------------------- dumps

func dumpLineDevCaps(b []byte) {
	fmt.Println("  LINEDEVCAPS")
	row("dwProviderInfo", utf16At(b, getU32(b, dcProviderInfoOffset), getU32(b, dcProviderInfoSize)))
	row("dwSwitchInfo", utf16At(b, getU32(b, dcSwitchInfoOffset), getU32(b, dcSwitchInfoSize)))
	row("dwLineName", utf16At(b, getU32(b, dcLineNameOffset), getU32(b, dcLineNameSize)))
	row("dwPermanentLineID", fmt.Sprintf("%d", getU32(b, dcPermanentLineID)))
	row("PermanentLineGuid", guidAt(b, dcPermanentLineGuid))
	classes := multiSzAt(b, getU32(b, dcDeviceClassesOffset), getU32(b, dcDeviceClassesSize))
	if len(classes) == 0 {
		row("dwDeviceClasses", "(none)")
	} else {
		row("dwDeviceClasses", strings.Join(classes, ", "))
	}
	row("dwStringFormat", enumString(getU32(b, dcStringFormat), stringFormats))
	row("dwAddressModes", flagString(getU32(b, dcAddressModes), addressModeFlags))
	row("dwNumAddresses", fmt.Sprintf("%d", getU32(b, dcNumAddresses)))
	row("dwBearerModes", flagString(getU32(b, dcBearerModes), bearerModeFlags))
	row("dwMaxRate", fmt.Sprintf("%d", getU32(b, dcMaxRate)))
	row("dwMediaModes", flagString(getU32(b, dcMediaModes), mediaModeFlags))
	row("dwDevCapFlags", flagString(getU32(b, dcDevCapFlags), devCapFlagFlags))
	row("dwMaxNumActiveCalls", fmt.Sprintf("%d", getU32(b, dcMaxNumActiveCalls)))
	row("dwAnswerMode", enumString(getU32(b, dcAnswerMode), answerModes))
	row("dwRingModes", fmt.Sprintf("%d", getU32(b, dcRingModes)))
	row("dwLineStates", flagString(getU32(b, dcLineStates), devStateFlags))
	row("dwLineFeatures", flagString(getU32(b, dcLineFeatures), lineFeatureFlags))
	row("dwSettableDevStatus", flagString(getU32(b, dcSettableDevStatus), devStateFlags))
	row("dwNumTerminals", fmt.Sprintf("%d", getU32(b, dcNumTerminals)))
	row("dwDevSpecificSize", fmt.Sprintf("%d", getU32(b, dcDevSpecificSize)))
}

func dumpAddressCaps(b []byte) {
	fmt.Println("  LINEADDRESSCAPS (address 0)")
	row("dwAddress", utf16At(b, dword(b, acAddressOffset), dword(b, acAddressSize)))
	row("dwLineDeviceID", fmt.Sprintf("%d", dword(b, acLineDeviceID)))
	row("dwAddressSharing", flagString(dword(b, acAddressSharing), addressSharingFlags))
	row("dwAddrCapFlags", flagString(dword(b, acAddrCapFlags), addrCapFlagFlags))
	row("dwAddressFeatures", flagString(dword(b, acAddressFeatures), addrFeatureFlags))
	row("dwCallFeatures", flagString(dword(b, acCallFeatures), callFeatureFlags))
	row("dwCallStates", flagString(dword(b, acCallStates), callStateFlags))
	row("dwTransferModes", flagString(dword(b, acTransferModes), transferModeFlags))
	row("dwMaxNumActiveCalls", fmt.Sprintf("%d", dword(b, acMaxNumActiveCalls)))
	row("dwMaxNumOnHoldCalls", fmt.Sprintf("%d", dword(b, acMaxNumOnHoldCalls)))
	row("dwForwardModes", flagString(dword(b, acForwardModes), forwardModeFlags))
	row("dwParkModes", fmt.Sprintf("0x%08X", dword(b, acParkModes)))
	row("dwPredictiveAutoTransferStates", flagString(dword(b, acPredictiveAutoTransferStates), callStateFlags))
	row("dwCallFeatures2", flagString(dword(b, acCallFeatures2), callFeature2Flags))
	row("dwAvailableMediaModes", flagString(dword(b, acAvailableMediaModes), mediaModeFlags))
	classes := multiSzAt(b, dword(b, acDeviceClassesOffset), dword(b, acDeviceClassesSize))
	if len(classes) == 0 {
		row("dwDeviceClasses", "(none)")
	} else {
		row("dwDeviceClasses", strings.Join(classes, ", "))
	}
}
