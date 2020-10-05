#include "HookLib.h"
#include "ProcessProtector.h"

#pragma data_seg("SharedData")
DWORD dwProtectedProcessId = 0;
#pragma data_seg()
#pragma comment(linker, "/SECTION:SharedData,RWS")

struct SharedData { DWORD dwHookCallerProcessID; };

HINSTANCE hInstance;
HHOOK hHook;

BOOL WINAPI SetGlobalWindowsHook() {
	dwProtectedProcessId = GetCurrentProcessId();
	return (hHook = SetWindowsHookExW(WH_GETMESSAGE, [](int nCode, WPARAM wParam, LPARAM lParam) { return CallNextHookEx(NULL, nCode, wParam, lParam); }, hInstance, 0)) != NULL;
}

BOOL WINAPI UnhookGlobalWindowsHook() {
	const BOOL ret = UnhookWindowsHookEx(hHook);
	if (ret)
		hHook = NULL;
	return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved) {
	using namespace Hydr10n::ProcessUtils;
	switch (dwReason) {
	case DLL_PROCESS_ATTACH: {
		hInstance = hModule;
		ProcessProtector::Hide(dwProtectedProcessId);
		ProcessProtector::Protect(dwProtectedProcessId);
	}	break;
	case DLL_PROCESS_DETACH: {
		ProcessProtector::Unprotect(dwProtectedProcessId);
		ProcessProtector::Unhide(dwProtectedProcessId);
	}	break;
	}
	return TRUE;
}