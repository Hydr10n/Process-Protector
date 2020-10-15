/*
 * Heade File: ProcessProtector.h
 * Last Update: 2020/10/15
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#pragma warning(disable:4302)
#pragma warning(disable:4311)

#include <Windows.h>
#include <winternl.h>
#include "../DetoursHelpers/DetoursHelpers.h"
#include "../std_container_helpers/set_helper.h"

#pragma comment(lib, "ntdll")

namespace Hydr10n {
	namespace ProcessUtils {
		class ProcessProtector final {
		public:
			static bool Hide(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_HiddenProcessIds, dwProcessId, false); }

			static bool Unhide(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_HiddenProcessIds, dwProcessId, true); }

			static bool Protect(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_ProtectedProcessIds, dwProcessId, false); }

			static bool Unprotect(DWORD dwProcessId) { return std_container_helpers::set_helper::modify(m_ProtectedProcessIds, dwProcessId, true); }

		private:
			static std::set<DWORD> m_HiddenProcessIds, m_ProtectedProcessIds;
			static decltype(OpenProcess)* m_OpenProcess;
			static decltype(NtQuerySystemInformation)* m_NtQuerySystemInformation;

			static const struct static_constructor {
				static_constructor() {
					using DetoursHelpers::ChangeProcAddr;
					m_OpenProcess = OpenProcess;
					m_NtQuerySystemInformation = NtQuerySystemInformation;
					ChangeProcAddr((PVOID*)&m_OpenProcess, MyOpenProcess, FALSE);
					ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, FALSE);
				}

				~static_constructor() {
					using DetoursHelpers::ChangeProcAddr;
					ChangeProcAddr((PVOID*)&m_OpenProcess, MyOpenProcess, TRUE);
					ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, TRUE);
				}
			} m_static_constructor;

			static HANDLE WINAPI MyOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) { return m_OpenProcess(std_container_helpers::set_helper::contains(m_ProtectedProcessIds, dwProcessId) ? 0 : dwDesiredAccess, bInheritHandle, dwProcessId); }

			static NTSTATUS NTAPI MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
				const NTSTATUS ret = m_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
				if (NT_SUCCESS(ret) && SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
					for (PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation, pPrevious = NULL; pCurrent != NULL; pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset)) {
						if (!std_container_helpers::set_helper::contains(m_HiddenProcessIds, (DWORD)pCurrent->UniqueProcessId))
							pPrevious = pCurrent;
						else if (pPrevious != NULL)
							pPrevious->NextEntryOffset = pCurrent->NextEntryOffset ? pPrevious->NextEntryOffset + pCurrent->NextEntryOffset : 0;
						if (!pCurrent->NextEntryOffset)
							break;
					}
				return ret;
			}
		};

		decltype(ProcessProtector::m_static_constructor) ProcessProtector::m_static_constructor;
		decltype(ProcessProtector::m_HiddenProcessIds) ProcessProtector::m_HiddenProcessIds;
		decltype(ProcessProtector::m_ProtectedProcessIds) ProcessProtector::m_ProtectedProcessIds;
		decltype(ProcessProtector::m_OpenProcess) ProcessProtector::m_OpenProcess;
		decltype(ProcessProtector::m_NtQuerySystemInformation) ProcessProtector::m_NtQuerySystemInformation;
	}
}