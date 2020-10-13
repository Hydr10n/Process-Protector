/*
 * Heade File: ProcessProtector.h
 * Last Update: 2020/10/13
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <set>
#include "../DetoursHelpers/DetoursHelpers.h"

#pragma comment(lib, "ntdll")

#pragma warning(disable:4302)
#pragma warning(disable:4311)

namespace Hydr10n {
	namespace ProcessUtils {
		class ProcessProtector final {
		public:
			static bool Hide(DWORD dwProcessId) { return std_set_helper::modify(m_HiddenProcessIds, dwProcessId, false); }

			static bool Unhide(DWORD dwProcessId) { return std_set_helper::modify(m_HiddenProcessIds, dwProcessId, true); }

			static bool Protect(DWORD dwProcessId) { return std_set_helper::modify(m_ProtectedProcessIds, dwProcessId, false); }

			static bool Unprotect(DWORD dwProcessId) { return std_set_helper::modify(m_ProtectedProcessIds, dwProcessId, true); }

		private:
			struct std_set_helper final {
				template <class T> static bool contains(const std::set<T>& container, const T& item) { return container.find(item) != container.end(); }

				template <class T> static bool modify(std::set<T>& container, const T& item, bool remove) {
					const bool ret = contains(container, item) == remove;
					if (ret) {
						if (remove)
							container.erase(item);
						else
							container.insert(item);
					}
					return ret;
				}
			};

			static std::set<DWORD> m_HiddenProcessIds, m_ProtectedProcessIds;
			static decltype(OpenProcess)* m_OpenProcess;
			static decltype(NtQuerySystemInformation)* m_NtQuerySystemInformation;

			static const struct static_constructor {
				static_constructor() {
					using Hydr10n::DetoursHelpers::ChangeProcAddr;
					m_OpenProcess = OpenProcess;
					m_NtQuerySystemInformation = NtQuerySystemInformation;
					ChangeProcAddr((PVOID*)&m_OpenProcess, MyOpenProcess, FALSE);
					ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, FALSE);
				}

				~static_constructor() {
					using Hydr10n::DetoursHelpers::ChangeProcAddr;
					ChangeProcAddr((PVOID*)&m_OpenProcess, MyOpenProcess, TRUE);
					ChangeProcAddr((PVOID*)&m_NtQuerySystemInformation, MyNtQuerySystemInformation, TRUE);
				}
			} m_static_constructor;

			static HANDLE WINAPI MyOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) { return m_OpenProcess(std_set_helper::contains(m_ProtectedProcessIds, dwProcessId) ? 0 : dwDesiredAccess, bInheritHandle, dwProcessId); }

			static NTSTATUS NTAPI MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
				const NTSTATUS ret = m_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
				if (NT_SUCCESS(ret) && SystemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
					for (PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation, pPrevious = NULL; pCurrent != NULL; pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset)) {
						if (!std_set_helper::contains(m_HiddenProcessIds, (DWORD)pCurrent->UniqueProcessId))
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