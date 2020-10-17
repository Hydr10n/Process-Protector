# Process Protector

This project is a demonstration of how to protect and hide processes by using Microsoft Detours library and other techniques such as DLL injection and windows hook on Windows platform. Intercepting the Windows functions ```NtQuerySystemInformation``` and ```NtOpenProcess``` is the key.

A simple library is provided to make the task above easier. See README.md files in HookLib and ProcessUtils directories for details.