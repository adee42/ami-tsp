/*
 * shim.h - TSPI types and callback trampolines for the Go provider.
 *
 * This header is included by every cgo file in the package. Because files
 * that use //export may not contain *definitions* in their preamble, it
 * declares only; the bodies live in shim.c.
 *
 * Windows structures and constants come from <tapi.h>. The handful of types
 * that live in <tspi.h> (driver handles, the two callback signatures) are
 * reproduced here instead, because tspi.h is not shipped by every mingw-w64
 * distribution and these definitions have been stable since TAPI 2.0.
 */
#ifndef AMITSP_SHIM_H
#define AMITSP_SHIM_H

#define WIN32_LEAN_AND_MEAN
#define TAPI_CURRENT_VERSION 0x00020002

#include <windows.h>
#include <tapi.h>

#ifndef TSPIAPI
#define TSPIAPI WINAPI
#endif

/* ---- from tspi.h ---------------------------------------------------- */

typedef DWORD DRV_REQUESTID;

DECLARE_HANDLE(HDRVCALL);
DECLARE_HANDLE(HDRVLINE);
DECLARE_HANDLE(HDRVPHONE);
DECLARE_HANDLE(HPROVIDER);
DECLARE_HANDLE(HTAPICALL);
DECLARE_HANDLE(HTAPILINE);
DECLARE_HANDLE(HTAPIPHONE);

typedef HDRVCALL  *LPHDRVCALL;
typedef HDRVLINE  *LPHDRVLINE;
typedef HDRVPHONE *LPHDRVPHONE;

typedef void (CALLBACK *ASYNC_COMPLETION)(DRV_REQUESTID dwRequestID, LONG lResult);

typedef void (CALLBACK *LINEEVENT)(HTAPILINE htLine, HTAPICALL htCall, DWORD dwMsg,
                                   DWORD_PTR dwParam1, DWORD_PTR dwParam2,
                                   DWORD_PTR dwParam3);

typedef void (CALLBACK *PHONEEVENT)(HTAPIPHONE htPhone, DWORD dwMsg,
                                    DWORD_PTR dwParam1, DWORD_PTR dwParam2,
                                    DWORD_PTR dwParam3);

/* Passed to the TUISPI_* entry points so a UI running in the client process
   can call back into the provider inside TapiSrv. This provider has no UI and
   never uses it, but the parameter is part of the signature TAPI calls. */
typedef LONG (CALLBACK *TUISPIDLLCALLBACK)(DWORD_PTR dwObjectID, DWORD dwObjectType,
                                           LPVOID lpParams, DWORD dwSize);

/* TSPI-only messages. The LINE_* messages this provider otherwise sends
   (LINE_CALLSTATE, LINE_CALLINFO, LINE_LINEDEVSTATE, LINE_GENERATE) are
   ordinary TAPI messages and come from <tapi.h>; LINE_NEWCALL is not, and
   only exists on the service provider side of the interface. */
#ifndef TSPI_MESSAGE_BASE
#define TSPI_MESSAGE_BASE 500
#endif
#ifndef LINE_NEWCALL
#define LINE_NEWCALL (TSPI_MESSAGE_BASE + 0)
#endif

/* LINE_CREATE is an ordinary TAPI message and every tapi.h that ships with a
   TAPI 2.0 SDK defines it. The fallback exists only so a stripped mingw-w64
   header cannot break the build; if it is ever used the value must stay 19,
   which is what TAPI 2.0 fixed it at. */
#ifndef LINE_CREATE
#define LINE_CREATE 19
#endif

/* Value TAPI passes as dwDeviceID when negotiating at provider scope. */
#ifndef INITIALIZE_NEGOTIATION
#define INITIALIZE_NEGOTIATION 0xFFFFFFFFUL
#endif

/* TSPI_providerInit option bits. */
#ifndef LINETSPIOPTION_NONREENTRANT
#define LINETSPIOPTION_NONREENTRANT 0x00000001
#endif

/* ---- trampolines ---------------------------------------------------- */

/*
 * Go cannot call a C function pointer directly, so every callback into TAPI
 * goes through one of these.
 */

/* Fire an arbitrary line event (LINE_CALLSTATE, LINE_CALLINFO, ...). */
void amitsp_line_event(LINEEVENT proc, HTAPILINE htLine, HTAPICALL htCall,
                       DWORD dwMsg, DWORD_PTR p1, DWORD_PTR p2, DWORD_PTR p3);

/*
 * Announce an incoming call. LINE_NEWCALL passes the address of an HTAPICALL
 * that TAPI fills in synchronously; keeping that pointer on the C stack avoids
 * handing a Go pointer to foreign code.
 */
HTAPICALL amitsp_new_call(LINEEVENT proc, HTAPILINE htLine, HDRVCALL hdCall);

/* Complete an asynchronous TSPI request. */
void amitsp_completion(ASYNC_COMPLETION proc, DRV_REQUESTID id, LONG result);

/*
 * Announce a line device created after TSPI_providerInit. TAPI responds by
 * calling TSPI_providerCreateLineDevice with the same temporary ID and the
 * permanent device ID it has assigned, so this must not be called with the
 * provider lock held.
 */
void amitsp_line_create(LINEEVENT proc, HPROVIDER hProvider, DWORD_PTR dwTempID);

/*
 * Pin the DLL into the process. The Go runtime cannot survive being unloaded
 * (its threads, TLS and signal handlers outlive FreeLibrary), and TapiSrv is
 * entitled to unload a provider after TSPI_providerShutdown. Pinning trades a
 * little address space for not crashing svchost.exe.
 */
void amitsp_pin_module(void);

/*
 * Write the full path of amitspui.dll, which sits beside this DLL, into a
 * caller-supplied buffer; return the number of characters written, or 0 on
 * failure. This is what TSPI_providerUIIdentify reports to TAPI.
 */
DWORD amitsp_ui_path(LPWSTR buf, DWORD cch);

#endif /* AMITSP_SHIM_H */
