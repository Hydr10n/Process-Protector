#include "HookLib.h"
#include "ProcessProtector.h"

#pragma data_seg("SharedData")
HHOOK hHook{};
struct { DWORD dwHookCallerProcessId; } sharedData{};
#pragma data_seg()
#pragma comment(linker, "/SECTION:SharedData,RWS")

HINSTANCE hInstance;

BOOL WINAPI SetGlobalWindowsHook() {
	sharedData.dwHookCallerProcessId = GetCurrentProcessId();
	return hHook == NULL ? (hHook = SetWindowsHookExW(WH_GETMESSAGE, [](int nCode, WPARAM wParam, LPARAM lParam) { return CallNextHookEx(NULL, nCode, wParam, lParam); }, hInstance, 0)) != NULL : FALSE;
}

BOOL WINAPI UnhookGlobalWindowsHook() {
	const BOOL ret = UnhookWindowsHookEx(hHook);
	if (ret)
		hHook = NULL;
	return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved) {
	using Hydr10n::ProcessUtils::ProcessProtector;
	switch (dwReason) {
	case DLL_PROCESS_ATTACH: {
		ProcessProtector::Hide(sharedData.dwHookCallerProcessId);
		ProcessProtector::Protect(sharedData.dwHookCallerProcessId);
		hInstance = hModule;
	}	break;
	}
	return TRUE;
}