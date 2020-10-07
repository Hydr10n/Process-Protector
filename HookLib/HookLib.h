/*
 * Header Files: HookLib.h
 * Last Update: 2020/10/07
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

BOOL WINAPI SetGlobalWindowsHook();
BOOL WINAPI UnhookGlobalWindowsHook();