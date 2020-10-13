/*
 * ATTENTION: The test must be running as administrator. Besides, Visual Studio [Solution Platforms] must be set correctly before building ("Release" mode is recommended) (for example, if the test is going to be running on Windows x64 platform, change [Solution Platforms] to "x64" so that the test program can inject its DLL into 64-bit Task Manager).
*/

#include <iostream>
#include <conio.h>
#include "../HookLib/HookLib.h"

using namespace std;

int wmain() {
	WCHAR szModuleFileName[MAX_PATH];
	GetModuleFileNameW(NULL, szModuleFileName, ARRAYSIZE(szModuleFileName));
	ShellExecuteW(NULL, NULL, L"taskmgr", NULL, NULL, SW_SHOWNORMAL);
	wcout << "Test: view current process \"" << szModuleFileName << "\" in Task Manager." << endl << endl
		<< "Test ready. Waiting for a key to start..." << endl;
	(void)_getwch();

	SetGlobalWindowsHook();
	wcout << "Test started. Waiting for a key to stop..." << endl;
	(void)_getwch();

	UnhookGlobalWindowsHook();
	wcout << "Test stopped. Waiting for a key to quit..." << endl;
	(void)_getwch();
}