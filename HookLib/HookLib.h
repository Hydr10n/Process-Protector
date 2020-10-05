#pragma once

#include <Windows.h>

#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN extern
#endif

EXTERN BOOL WINAPI SetGlobalWindowsHook();
EXTERN BOOL WINAPI UnhookGlobalWindowsHook();