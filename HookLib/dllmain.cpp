#include "HookLib.h"
#include "ProcessProtector.h"

#pragma data_seg("SharedData")
struct { DWORD dwHookCallerProcessID; } sharedData{};
#pragma data_seg()
#pragma comment(linker, "/SECTION:SharedData,RWS")

HINSTANCE hInstance;
HHOOK hHook;

BOOL WINAPI SetGlobalWindowsHook() {
	sharedData.dwHookCallerProcessID = GetCurrentProcessId();
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
		ProcessProtector::Hide(sharedData.dwHookCallerProcessID);
		ProcessProtector::Protect(sharedData.dwHookCallerProcessID);
	}	break;
	case DLL_PROCESS_DETACH: {
		ProcessProtector::Unprotect(sharedData.dwHookCallerProcessID);
		ProcessProtector::Unhide(sharedData.dwHookCallerProcessID);
	}	break;
	}
	return TRUE;
}