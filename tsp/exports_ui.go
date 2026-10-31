package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "shim.h"
*/
import "C"

import (
	"github.com/adee42/ami-tsp/internal/logx"
)

// TAPI 2.0 and later no longer call TSPI_providerInstall. lineAddProvider asks
// the provider for a UI DLL here, loads that DLL into the calling process and
// invokes TUISPI_providerInstall there. A provider that does not export
// TSPI_providerUIIdentify cannot be installed at all: lineAddProvider fails
// with LINEERR_OPERATIONUNAVAIL (0x80000049).
//
// The TUISPI_* entry points live in amitspui.dll rather than here, because
// this DLL carries a Go runtime that must never be loaded into a client
// process. See ui/amitspui.c.

// TSPI_providerUIIdentify names the DLL holding this provider's TUISPI_*
// entry points. It sits next to the provider, which means System32 once
// installed.
//
//export TSPI_providerUIIdentify
func TSPI_providerUIIdentify(lpszUIDLLName C.LPWSTR) (rc C.LONG) {
	defer recoverEntry("TSPI_providerUIIdentify", &rc)
	if lpszUIDLLName == nil {
		return lerr(C.LINEERR_INVALPOINTER)
	}
	// TAPI supplies a buffer of MAX_PATH characters and nothing more.
	if C.amitsp_ui_path(lpszUIDLLName, C.DWORD(C.MAX_PATH)) == 0 {
		logx.Errorf("tsp: cannot derive the UI DLL path from this module's location")
		return lerr(C.LINEERR_OPERATIONFAILED)
	}
	return 0
}
