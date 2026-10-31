#include "shim.h"

#include <string.h>
#include <wchar.h>

void amitsp_line_event(LINEEVENT proc, HTAPILINE htLine, HTAPICALL htCall,
                       DWORD dwMsg, DWORD_PTR p1, DWORD_PTR p2, DWORD_PTR p3)
{
    if (proc != NULL && htLine != NULL) {
        proc(htLine, htCall, dwMsg, p1, p2, p3);
    }
}

HTAPICALL amitsp_new_call(LINEEVENT proc, HTAPILINE htLine, HDRVCALL hdCall)
{
    HTAPICALL htCall = NULL;

    if (proc == NULL || htLine == NULL) {
        return NULL;
    }
    /* TAPI writes the application-side call handle into htCall before it
       returns; dwParam1 is our handle for the same call. */
    proc(htLine, NULL, LINE_NEWCALL, (DWORD_PTR)hdCall, (DWORD_PTR)&htCall, 0);
    return htCall;
}

void amitsp_completion(ASYNC_COMPLETION proc, DRV_REQUESTID id, LONG result)
{
    if (proc != NULL) {
        proc(id, result);
    }
}

void amitsp_line_create(LINEEVENT proc, HPROVIDER hProvider, DWORD_PTR dwTempID)
{
    if (proc == NULL || hProvider == NULL) {
        return;
    }
    /* TSPI passes the provider handle where a line handle normally goes; the
       message is about the provider, not about any existing line. */
    proc((HTAPILINE)hProvider, NULL, LINE_CREATE, dwTempID, 0, 0);
}

void amitsp_pin_module(void)
{
    HMODULE self = NULL;

    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN |
                           GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCWSTR)(void *)&amitsp_pin_module, &self);
}

/*
 * Pin as early as the toolchain allows. TapiSrv loads the provider, calls a
 * single entry point (TSPI_providerUIIdentify during lineAddProvider, or
 * TSPI_providerEnumDevices when it finds no devices) and then unloads it
 * again. Pinning from inside those entry points is already too late to be a
 * rule: any path that unloads us without calling the one function that
 * happens to pin takes the Go runtime's threads down with it, which surfaces
 * as an access violation in "amitsp.dll_unloaded".
 */
static void __attribute__((constructor)) amitsp_on_load(void)
{
    amitsp_pin_module();
}

DWORD amitsp_ui_path(LPWSTR buf, DWORD cch)
{
    static const WCHAR uiName[] = L"amitspui.dll";
    const DWORD uiLen = (DWORD)(sizeof(uiName) / sizeof(WCHAR)) - 1;
    HMODULE self = NULL;
    LPWSTR sep;
    DWORD n, dirLen;

    if (buf == NULL || cch == 0) {
        return 0;
    }
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT |
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            (LPCWSTR)(void *)&amitsp_ui_path, &self)) {
        return 0;
    }
    n = GetModuleFileNameW(self, buf, cch);
    /* Pre-Win10 GetModuleFileNameW truncates instead of failing, so treat a
       full buffer as failure rather than build a path from a clipped one. */
    if (n == 0 || n >= cch) {
        return 0;
    }
    sep = wcsrchr(buf, L'\\');
    if (sep == NULL) {
        return 0;
    }
    dirLen = (DWORD)(sep - buf) + 1; /* keep the separator */
    if (dirLen + uiLen + 1 > cch) {
        return 0;
    }
    memcpy(buf + dirLen, uiName, (uiLen + 1) * sizeof(WCHAR));
    return dirLen + uiLen;
}
