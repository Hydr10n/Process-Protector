/*
 * ATTENTION: The test must be running as administrator. Besides, Visual Studio [Solution Platforms] must be set correctly before building (for example, if the test is going to be running on Windows x64 platform, change [Solution Platforms] to "x64" so that the test program can inject its DLL into 64-bit Task Manager).
*/

#include <iostream>
#include <conio.h>
#include "../HookLib/HookLib.h"

using namespace std;

int main() {
	CHAR szModuleFileName[MAX_PATH];
	if (!GetModuleFileNameA(NULL, szModuleFileName, ARRAYSIZE(szModuleFileName))) {
		cerr << "Test failed to start" << endl;
		return ERROR_CAN_NOT_COMPLETE;
	}
	ShellExecuteW(NULL, NULL, L"taskmgr", NULL, NULL, SW_SHOW);
	cout << "Test: view current process \"" << szModuleFileName << "\" in Task Manager." << endl << endl;

	SetGlobalWindowsHook();
	cout << "Test started. Waiting for a key to stop..." << endl;
	(void)_getch();

	UnhookGlobalWindowsHook();
	cout << "Test stopped. Waiting for a key to quit..." << endl;
	(void)_getch();
}