#include "HookLib.h"
#include "ProcessProtector.h"

#pragma data_seg("SharedData")
struct {
	HHOOK hHook;
	DWORD dwHookCallerProcessId;
} sharedData{};
#pragma data_seg()
#pragma comment(linker, "/SECTION:SharedData,RWS")

HINSTANCE hInstance;

BOOL WINAPI SetGlobalWindowsHook() {
	BOOL ret = sharedData.hHook == NULL;
	if (ret) {
		sharedData.dwHookCallerProcessId = GetCurrentProcessId();
		ret = (sharedData.hHook = SetWindowsHookExW(WH_GETMESSAGE, [](int nCode, WPARAM wParam, LPARAM lParam) { return CallNextHookEx(NULL, nCode, wParam, lParam); }, hInstance, 0)) != NULL;
	}
	return ret;
}

BOOL WINAPI UnhookGlobalWindowsHook() {
	const BOOL ret = UnhookWindowsHookEx(sharedData.hHook);
	if (ret)
		sharedData.hHook = NULL;
	return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved) {
	using Hydr10n::ProcessUtils::ProcessProtector;
	switch (dwReason) {
	case DLL_PROCESS_ATTACH: {
		if (sharedData.hHook != NULL) {
			ProcessProtector::Hide(sharedData.dwHookCallerProcessId);
			ProcessProtector::Protect(sharedData.dwHookCallerProcessId);
		}
		hInstance = hModule;
	}	break;
	}
	return TRUE;
}