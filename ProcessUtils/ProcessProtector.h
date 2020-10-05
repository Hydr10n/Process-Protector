/*
 * Heade File: ProcessProtector.h
 * Last Update: 2020/10/05
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <set>
#include "../Detours/include/detours.h"

#pragma comment(lib, "ntdll")

#ifdef _M_IX86
#pragma comment(lib, "../Detours/lib.X86/detours")
#elif defined _M_X64
#pragma comment(lib, "../Detours/lib.X64/detours")
#endif

#pragma warning(disable:4302)
#pragma warning(disable:4311)

namespace Hydr10n {
	namespace ProcessUtils {
		class ProcessProtector final {
		public:
			static LONG Hide(DWORD dwProcessId) {
				m_HiddenProcessesIds.insert(dwProcessId);
				return ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, FALSE);
			}

			static LONG Unhide(DWORD dwProcessId) {
				m_HiddenProcessesIds.erase(dwProcessId);
				return ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, TRUE);
			}

			static LONG Protect(DWORD dwProcessId) {
				m_ProtectedProcessesIds.insert(dwProcessId);
				return ChangeProcAddr((PVOID*)&m_OpenProcess, MyOpenProcess, FALSE);
			}

			static LONG Unprotect(DWORD dwProcessId) {
				m_ProtectedProcessesIds.erase(dwProcessId);
				return ChangeProcAddr((PVOID*)&m_OpenProcess, MyOpenProcess, TRUE);
			}

		private:
			static std::set<DWORD> m_HiddenProcessesIds, m_ProtectedProcessesIds;
			static decltype(NtQuerySystemInformation)* m_NtQuerySystemInformation;
			static decltype(OpenProcess)* m_OpenProcess;

			template <class T> static bool Contains(const std::set<T>& _set, const T& item) { return _set.find(item) != _set.end(); }

			static const struct static_constructor {
				static_constructor() {
					m_OpenProcess = OpenProcess;
					m_NtQuerySystemInformation = NtQuerySystemInformation;
				}
			} m_static_constructor;

			static LONG ChangeProcAddr(PVOID* ppPointer, PVOID pDetour, BOOL bRestore) {
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				if (bRestore)
					DetourDetach(ppPointer, pDetour);
				else
					DetourAttach(ppPointer, pDetour);
				return DetourTransactionCommit();
			}

			static HANDLE WINAPI MyOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) { return m_OpenProcess(Contains(m_ProtectedProcessesIds, dwProcessId) ? 0 : dwDesiredAccess, bInheritHandle, dwProcessId); }

			static NTSTATUS NTAPI MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
				const NTSTATUS status = m_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
				if (NT_SUCCESS(status) && SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
					for (PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation, pPrevious = NULL; pCurrent != NULL; pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset)) {
						if (!Contains(m_HiddenProcessesIds, (DWORD)pCurrent->UniqueProcessId))
							pPrevious = pCurrent;
						else if (pPrevious != NULL)
							pPrevious->NextEntryOffset = pCurrent->NextEntryOffset ? pPrevious->NextEntryOffset + pCurrent->NextEntryOffset : 0;
						if (!pCurrent->NextEntryOffset)
							break;
					}
				return status;
			}
		};

		decltype(ProcessProtector::m_static_constructor) ProcessProtector::m_static_constructor;
		decltype(ProcessProtector::m_HiddenProcessesIds) ProcessProtector::m_HiddenProcessesIds;
		decltype(ProcessProtector::m_ProtectedProcessesIds) ProcessProtector::m_ProtectedProcessesIds;
		decltype(ProcessProtector::m_OpenProcess) ProcessProtector::m_OpenProcess;
		decltype(ProcessProtector::m_NtQuerySystemInformation) ProcessProtector::m_NtQuerySystemInformation;
	}
}