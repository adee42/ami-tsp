/*
 * amitspui.c - install-time UI half of the AMI TAPI service provider.
 *
 * TAPI 2.x runs a provider's install, remove and configure entry points in the
 * *client's* process, not in TapiSrv: lineAddProvider asks the provider for a
 * UI DLL name via TSPI_providerUIIdentify, then loads that DLL into whatever
 * process made the call (amitsp-ctl.exe, or rundll32.exe hosting telephon.cpl)
 * and calls TUISPI_providerInstall there.
 *
 * That DLL deliberately is not amitsp.dll. The provider is a cgo c-shared
 * library, so loading it starts a Go runtime -- threads, TLS and exception
 * handlers that cannot be unloaded again. Naming it as the UI DLL therefore
 * left every client process with the choice between crashing on FreeLibrary
 * and hosting a pinned Go runtime forever. This file has neither problem: it
 * is plain C, starts no threads, and unloads cleanly.
 *
 * Configuration lives in a JSON file rather than a dialog, so there is no UI
 * to show and these entry points only need to succeed.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* From tspi.h. Lets a UI running in the client call back into the provider
   inside TapiSrv; this provider has no UI and never uses it. */
typedef LONG(CALLBACK *TUISPIDLLCALLBACK)(DWORD_PTR dwObjectID, DWORD dwObjectType,
                                          LPVOID lpParams, DWORD dwSize);

__declspec(dllexport) LONG WINAPI
TUISPI_providerInstall(TUISPIDLLCALLBACK lpfnUIDLLCallback, HWND hwndOwner,
                       DWORD dwPermanentProviderID)
{
    (void)lpfnUIDLLCallback;
    (void)hwndOwner;
    (void)dwPermanentProviderID;
    return 0;
}

__declspec(dllexport) LONG WINAPI
TUISPI_providerRemove(TUISPIDLLCALLBACK lpfnUIDLLCallback, HWND hwndOwner,
                      DWORD dwPermanentProviderID)
{
    (void)lpfnUIDLLCallback;
    (void)hwndOwner;
    (void)dwPermanentProviderID;
    return 0;
}

__declspec(dllexport) LONG WINAPI
TUISPI_providerConfig(TUISPIDLLCALLBACK lpfnUIDLLCallback, HWND hwndOwner,
                      DWORD dwPermanentProviderID)
{
    (void)lpfnUIDLLCallback;
    (void)hwndOwner;
    (void)dwPermanentProviderID;
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        /* Nothing here is per-thread, and the clients that load this DLL are
           free to create threads for their own reasons. */
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
