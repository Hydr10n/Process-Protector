/*
 * Heade File: DetoursHelpers.h
 * Last Update: 2020/10/13
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#include "detours.h"

namespace Hydr10n {
	namespace DetoursHelpers {
		LONG WINAPI ChangeProcAddr(PVOID* ppPointer, PVOID pDetour, BOOL bRestore) {
			LONG ret = DetourTransactionBegin();
			if (ret != NO_ERROR
				|| (ret = DetourUpdateThread(GetCurrentThread())) != NO_ERROR
				|| (ret = (bRestore ? DetourDetach(ppPointer, pDetour) : DetourAttach(ppPointer, pDetour))) != NO_ERROR)
				return ret;
			return DetourTransactionCommit();
		}
	}
}